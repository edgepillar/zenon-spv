// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

func collectionFixture(t *testing.T) ([]json.RawMessage, CandidateBatchCollectionSelection) {
	t.Helper()
	corpus := candidateRPCRows(t)
	var rows []json.RawMessage
	var selected CandidateBatchCollectionSelection
	for i, row := range corpus[:3] {
		if !row.Signed {
			t.Fatal("fixture must retain its recorded public signatures")
		}
		value, err := DecodeCandidateV3Momentum([]byte(row.Wire))
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, json.RawMessage(row.Wire))
		h := value.Header.Header
		if i == 0 {
			selected.ChainID, selected.AnchorHeight, selected.AnchorHash = h.ChainIdentifier, h.Height-1, h.PreviousHash
		}
		if i == 1 {
			selected.Height, selected.HeaderHash = h.Height, h.HeaderHash
		}
		if i == 2 {
			selected.TipHeight, selected.TipHash = h.Height, h.HeaderHash
		}
	}
	raw, err := hex.DecodeString("01b3b6e5adcb4d0cad7fcef33598c6318c6318c0")
	if err != nil {
		t.Fatal(err)
	}
	selected.Settlement, selected.DomainID, selected.BatchID = chain.Address(raw), 1, 1
	return rows, selected
}

func collectionReply(t *testing.T, result any) []byte {
	t.Helper()
	return candidateRPCJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
}

func collectionClient(t *testing.T, rows []json.RawMessage, selected CandidateBatchCollectionSelection, mode string) (*Client, *[]string) {
	t.Helper()
	client := NewClient("https://user:PRIVATE@private.invalid/PRIVATE?token=PRIVATE")
	var methods []string
	client.HTTP.Transport = diagnosticTransport(func(req *http.Request) (*http.Response, error) {
		var call struct {
			Method string
			Params []json.RawMessage
		}
		if json.NewDecoder(req.Body).Decode(&call) != nil {
			t.Fatal("request encoding")
		}
		methods = append(methods, call.Method)
		var result any
		switch call.Method {
		case "ledger.getMomentumsByHeight":
			var start, count uint64
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &start) != nil || json.Unmarshal(call.Params[1], &count) != nil {
				t.Fatal("range request")
			}
			offset := start - selected.AnchorHeight - 1
			if count == 0 || count > rpcRangePageSize || offset+count > uint64(len(rows)) {
				t.Fatal("range selection changed")
			}
			members := rows[offset : offset+count]
			if mode == "short" {
				members = members[:len(members)-1]
			}
			if mode == "bad-row" {
				members = append([]json.RawMessage(nil), members...)
				members[0] = json.RawMessage(`{}`)
			}
			result = map[string]any{"list": members, "count": len(members)}
		case "ledger.getProof":
			var height uint64
			var key []byte
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &height) != nil || json.Unmarshal(call.Params[1], &key) != nil || height != selected.Height {
				t.Fatal("proof height changed")
			}
			// Independent fixed full key: prefix/address/subkey/domain/batch,
			// not the 32-byte hashed path passed back through another hash.
			want, err := hex.DecodeString("0301b3b6e5adcb4d0cad7fcef33598c6318c6318c00402000000010000000000000001")
			if err != nil || !bytes.Equal(key, want) {
				t.Fatal("proof key was not locally selected full key")
			}
			root := chain.Hash{7}
			result = map[string]any{"root": root, "value": nil, "proof": make([]byte, 99)}
			if mode == "large-witness" {
				result = map[string]any{"root": root, "value": make([]byte, 4096), "proof": make([]byte, proof.CandidateSMTMaxProofBytes)}
			}
			if mode == "missing-proof" {
				result = nil
			}
			if mode == "bad-proof" {
				result = map[string]any{"root": root, "value": nil, "proof": nil}
			}
		case "embedded.settlement.getBatch":
			var domain uint32
			var batch uint64
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &domain) != nil || json.Unmarshal(call.Params[1], &batch) != nil || domain != selected.DomainID || batch != selected.BatchID {
				t.Fatal("frontier selectors changed")
			}
			fields := candidateSettlementFields(t)
			fields["batchId"] = json.RawMessage("1")
			if mode == "wrong-gateway" {
				fields["batchId"] = json.RawMessage("2")
			}
			result = fields
			if mode == "missing-gateway" {
				result = nil
			}
		default:
			t.Fatal("unexpected RPC method")
		}
		body := collectionReply(t, result)
		if mode == "transport" {
			return nil, errors.New("PRIVATE transport cause")
		}
		if mode == "proof-overflow" && call.Method == "ledger.getProof" {
			body = append(bytes.Repeat([]byte{' '}, int(MaxCandidateStateResponseBytes)), body...)
		}
		if mode == "gateway-overflow" && call.Method == "embedded.settlement.getBatch" {
			body = append(bytes.Repeat([]byte{' '}, int(MaxCandidateStateResponseBytes)), body...)
		}
		if mode == "range-budget" && call.Method == "ledger.getMomentumsByHeight" {
			body = append(bytes.Repeat([]byte{' '}, (4<<20)+1-len(body)), body...)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	return client, &methods
}

func TestCandidateBatchCollectionRecordedWire(t *testing.T) {
	for _, compare := range []bool{false, true} {
		rows, selected := collectionFixture(t)
		client, methods := collectionClient(t, rows, selected, "")
		raw, err := client.FetchCandidateBatchEntryBundle(context.Background(), selected, compare)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]json.RawMessage
		if json.Unmarshal(raw, &document) != nil || len(document) != 3+btoi(compare) || string(document["version"]) != "1" {
			t.Fatal("wrong provider schema")
		}
		var got []json.RawMessage
		if json.Unmarshal(document["momentums"], &got) != nil || len(got) != 3 {
			t.Fatal("lost wire rows")
		}
		for i := range rows {
			var a, b bytes.Buffer
			_ = json.Compact(&a, rows[i])
			_ = json.Compact(&b, got[i])
			if !bytes.Equal(a.Bytes(), b.Bytes()) {
				t.Fatal("received wire data or content order changed")
			}
		}
		if _, err := DecodeCandidateStateWitness(document["witness"]); err != nil {
			t.Fatal(err)
		}
		want := []string{"ledger.getMomentumsByHeight", "ledger.getProof"}
		if compare {
			want = append(want, "embedded.settlement.getBatch")
			gateway, err := DecodeCandidateSettlementBatch(document["gateway"])
			if err != nil || !gateway.IsFinalized {
				t.Fatal("frontier hint lost", err)
			}
		}
		if !reflect.DeepEqual(*methods, want) {
			t.Fatal("unexpected request count or method")
		}
		saved := bytes.Clone(raw)
		raw[0] = 'x'
		again, err := client.FetchCandidateBatchEntryBundle(context.Background(), selected, compare)
		if err != nil || !bytes.Equal(again, saved) {
			t.Fatal("returned bytes alias retained input")
		}
	}
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestCandidateBatchCollectionLocalSelections(t *testing.T) {
	_, base := collectionFixture(t)
	for _, name := range []string{"chain", "anchor-height", "anchor-hash", "range", "large", "height", "header-hash", "tip-hash", "settlement", "same-height-hashes", "overflow"} {
		t.Run(name, func(t *testing.T) {
			s := base
			switch name {
			case "chain":
				s.ChainID = 0
			case "anchor-height":
				s.AnchorHeight = 0
			case "anchor-hash":
				s.AnchorHash = chain.Hash{}
			case "range":
				s.TipHeight = s.AnchorHeight
			case "large":
				s.TipHeight = s.AnchorHeight + 4097
			case "height":
				s.Height = s.AnchorHeight
			case "header-hash":
				s.HeaderHash = chain.Hash{}
			case "tip-hash":
				s.TipHash = chain.Hash{}
			case "settlement":
				s.Settlement = chain.Address{}
			case "same-height-hashes":
				s.Height = s.TipHeight
			case "overflow":
				s.AnchorHeight = ^uint64(0)
				s.TipHeight = 1
			}
			if raw, err := (*Client)(nil).FetchCandidateBatchEntryBundle(context.Background(), s, false); !errors.Is(err, ErrInvalidQuery) || raw != nil {
				t.Fatal("invalid local selection reached transport", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if raw, err := (*Client)(nil).FetchCandidateBatchEntryBundle(ctx, base, false); !errors.Is(err, context.Canceled) || raw != nil {
		t.Fatal("pre-cancelled operation progressed", err)
	}
	full := base
	full.AnchorHeight = ^uint64(0) - 1
	full.Height = ^uint64(0)
	full.TipHeight = full.Height
	full.HeaderHash = full.TipHash
	full.DomainID = ^uint32(0)
	full.BatchID = ^uint64(0)
	if full.Validate() != nil {
		t.Fatal("full-width local selectors were truncated")
	}
}

func TestCandidateBatchCollectionNoPartialFailures(t *testing.T) {
	for _, mode := range []string{"short", "bad-row", "wrong-chain", "wrong-anchor", "wrong-header", "wrong-tip", "missing-proof", "bad-proof", "proof-overflow", "wrong-gateway", "missing-gateway", "gateway-overflow", "transport"} {
		t.Run(mode, func(t *testing.T) {
			rows, selected := collectionFixture(t)
			client, methods := collectionClient(t, rows, selected, mode)
			switch mode {
			case "wrong-chain":
				selected.ChainID++
			case "wrong-anchor":
				selected.AnchorHash = chain.Hash{9}
			case "wrong-header":
				selected.HeaderHash = chain.Hash{9}
			case "wrong-tip":
				selected.TipHash = chain.Hash{9}
			}
			raw, err := client.FetchCandidateBatchEntryBundle(context.Background(), selected, true)
			if err == nil || raw != nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("failure exposed data or partial provider document", err)
			}
			if len(*methods) == 0 {
				t.Fatal("expected selected read was not attempted")
			}
			if strings.HasPrefix(mode, "wrong-") && mode != "wrong-gateway" && len(*methods) != 1 {
				t.Fatal("identity mismatch continued to proof")
			}
			if mode == "missing-proof" || mode == "missing-gateway" {
				if !errors.Is(err, ErrCandidateStateUnavailable) {
					t.Fatal("unavailable data became absence", err)
				}
			}
		})
	}
}

// Generated transport-only chains deliberately reuse an unsigned fixture.
// No signature is produced and no owned-header acceptance is asserted.
func collectionGeneratedRows(t *testing.T, sizes []int) ([]json.RawMessage, CandidateBatchCollectionSelection) {
	t.Helper()
	base := candidateRPCRows(t)[3]
	if base.Signed {
		t.Fatal("transport fixture must be unsigned")
	}
	value, err := DecodeCandidateV3Momentum([]byte(base.Wire))
	if err != nil {
		t.Fatal(err)
	}
	_, selected := collectionFixture(t)
	selected.AnchorHeight = 1
	selected.AnchorHash = chain.Hash{9}
	selected.Height = 2
	selected.TipHeight = uint64(len(sizes) + 1)
	previous := selected.AnchorHash
	var rows []json.RawMessage
	for i, size := range sizes {
		h := value.Header
		h.Header.ChainIdentifier = selected.ChainID
		h.Header.Height = uint64(i + 2)
		h.Header.PreviousHash = previous
		data := bytes.Repeat([]byte{0x5a}, size)
		h.Header.DataHash = chain.Hash(sha3.Sum256(data))
		h.Header.HeaderHash, err = h.ComputeHash()
		if err != nil {
			t.Fatal(err)
		}
		fields := candidateRPCFields(t, base.Wire)
		for name, v := range map[string]any{"chainIdentifier": h.Header.ChainIdentifier, "height": h.Header.Height, "previousHash": h.Header.PreviousHash, "hash": h.Header.HeaderHash, "data": data} {
			fields[name] = candidateRPCJSON(t, v)
		}
		rows = append(rows, candidateRPCJSON(t, fields))
		previous = h.Header.HeaderHash
		if i == 0 {
			selected.HeaderHash = h.Header.HeaderHash
		}
		selected.TipHash = h.Header.HeaderHash
	}
	return rows, selected
}

func TestCandidateBatchCollectionPagingAndWholeBounds(t *testing.T) {
	rows, selected := collectionGeneratedRows(t, make([]int, 1025))
	client, methods := collectionClient(t, rows, selected, "")
	if raw, err := client.FetchCandidateBatchEntryBundle(context.Background(), selected, false); err != nil || len(raw) == 0 || len(*methods) != 3 {
		t.Fatal("complete paginated range refused", err)
	}
	client, methods = collectionClient(t, rows, selected, "range-budget")
	if raw, err := client.FetchCandidateBatchEntryBundle(context.Background(), selected, false); !errors.Is(err, ErrResponseTooLarge) || raw != nil || len(*methods) != 2 {
		t.Fatal("page bodies did not share one byte budget", err)
	}
	sizes := make([]int, 400)
	for i := range sizes {
		sizes[i] = 12000
	}
	rows, _ = collectionGeneratedRows(t, sizes)
	body := collectionReply(t, map[string]any{"list": rows, "count": len(rows)})
	slack := int(MaxCandidateV3RangeBytes) - 512 - len(body)
	if slack < 0 {
		t.Fatal("whole-document boundary fixture exceeds range before adjustment")
	}
	for i := range sizes {
		extra := min((MaxCandidateV3MomentumDataBytes-sizes[i])/3, slack/4)
		sizes[i] += extra * 3
		slack -= extra * 4
	}
	if slack > 3 {
		t.Fatal("whole-document boundary fixture could not fill its budget")
	}
	rows, selected = collectionGeneratedRows(t, sizes)
	body = collectionReply(t, map[string]any{"list": rows, "count": len(rows)})
	if len(body) > int(MaxCandidateV3RangeBytes) || len(body) < int(MaxCandidateV3RangeBytes)-515 {
		t.Fatal("incorrect measured boundary fixture")
	}
	client, methods = collectionClient(t, rows, selected, "large-witness")
	if raw, err := client.FetchCandidateBatchEntryBundle(context.Background(), selected, false); !errors.Is(err, ErrResponseTooLarge) || raw != nil || len(*methods) != 2 {
		t.Fatal("whole provider document escaped its complete cap", err)
	}
}
