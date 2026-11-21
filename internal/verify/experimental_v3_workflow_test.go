// SPDX-License-Identifier: MIT

package verify_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type experimentalV3Transport func(*http.Request) (*http.Response, error)

func (f experimentalV3Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestExperimentalV3RecordedRPCToOwnedRootAndResume(t *testing.T) {
	raw, err := os.ReadFile("../testdata/conformance/candidate-v3-node-rpc.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != 15475 || hex.EncodeToString(sum[:]) != "4ac2da237eead98f146d931a27679a7251a5a9ef5e109920b9f7fd1f3a383e57" {
		t.Fatal("recorded RPC bytes changed")
	}
	var recorded struct {
		Rows []struct {
			Signed   bool   `json:"existing_signature_valid"`
			Wire     string `json:"wire_json"`
			Producer string `json:"producer_raw_hex"`
		} `json:"rows"`
	}
	if json.Unmarshal(raw, &recorded) != nil || len(recorded.Rows) != 8 {
		t.Fatal("RPC fixture shape")
	}
	wires := []json.RawMessage{}
	for _, row := range recorded.Rows {
		if row.Signed {
			wires = append(wires, json.RawMessage(row.Wire))
		}
	}
	if len(wires) != 3 {
		t.Fatal("expected three original public signatures")
	}
	client := fetch.NewClient("https://candidate.invalid")
	client.HTTP.Transport = experimentalV3Transport(func(req *http.Request) (*http.Response, error) {
		var call struct {
			Method string    `json:"method"`
			Params [2]uint64 `json:"params"`
		}
		if json.NewDecoder(req.Body).Decode(&call) != nil || call.Method != "ledger.getMomentumsByHeight" || call.Params != [2]uint64{12, 3} {
			t.Fatal("selected consumer range changed")
		}
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"list": wires, "count": 3}})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	candidates, err := client.FetchCandidateV3ByHeight(context.Background(), 12, 3)
	if err != nil || len(candidates) != 3 {
		t.Fatal("recorded RPC range failed", err)
	}
	var genesis, anchor chain.Hash
	if genesis.UnmarshalText([]byte("0385d849ee33b94c8783288c148e3ae741c2ecec98b08b3f59d6bcc219168fe5")) != nil || anchor.UnmarshalText([]byte("2b584eb276428450a3485d18df309d37352110d59cd670b25bc774837b5f5768")) != nil {
		t.Fatal("fixture trust inputs")
	}
	profile := verify.ExperimentalV3Profile{Version: 1, Genesis: verify.GenesisTrustRoot{ChainID: 100, Height: 1, HeaderHash: genesis}, Anchor: verify.GenesisTrustRoot{ChainID: 100, Height: 11, HeaderHash: anchor}, FirstV3Height: 12, ValidThrough: 14, NodeRevision: verify.ExperimentalV3NodeRevision, Source: "isolated original-node fixture; not authenticated network activation"}
	policy := verify.ExperimentalV3Policy{W: 1, RetainHeaders: 2, MaxBatchHeaders: 3}
	entries := make([]verify.ProducerEntry, 3)
	headers := make([]chain.CandidateV3Header, 3)
	for i, c := range candidates {
		// This schedule is an explicit test configuration from a pinned public
		// fixture. It is not an independently selected live producer schedule.
		producer, err := hex.DecodeString(recorded.Rows[i].Producer)
		if err != nil || len(producer) != 20 {
			t.Fatal("fixture producer")
		}
		var address chain.Address
		copy(address[:], producer)
		entries[i] = verify.ProducerEntry{Height: uint64(12 + i), TimestampUnix: uint64(1000000110 + 10*i), ProducingAddr: address}
		headers[i] = c.Header
	}
	schedule, err := verify.NewProducerSchedule(100, []verify.ProducerCoverage{{FromHeight: 12, ThroughHeight: 14}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := verify.ExperimentalV3ContextFor(profile, policy, schedule)
	if err != nil {
		t.Fatal(err)
	}
	state, err := verify.NewExperimentalV3State(profile, policy, schedule, ctx.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	result, state := state.Extend(headers)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal(result)
	}
	root, err := state.RootAt(13, headers[1].Header.HeaderHash, ctx.Fingerprint)
	if err != nil || root != headers[1].StateRoot {
		t.Fatal("owned header root lost", err)
	}
	path := filepath.Join(t.TempDir(), "owned-v3.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	resumed, err := verify.LoadTrustedExperimentalV3State(path, profile, policy, schedule, ctx.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := resumed.RootAt(13, headers[1].Header.HeaderHash, ctx.Fingerprint); err != nil || actual != root {
		t.Fatal("resumed consumer root mismatch", err)
	}
	native, err := verify.NewVerifiedState(profile.Anchor, verify.VerifyOptions{Policy: verify.Policy{W: 1, RetainHeaders: 2, MaxHeaders: 3}})
	if err != nil {
		t.Fatal(err)
	}
	refused, _ := native.Extend([]chain.Header{headers[0].Header})
	if refused.Outcome != verify.OutcomeRefused || refused.Reason != verify.ReasonUnsupportedHeaderVersion {
		t.Fatal("experimental workflow enabled production v3", refused)
	}
	for _, guarantee := range result.Proven {
		if guarantee == verify.GuaranteeStateValueInclusion || guarantee == verify.GuaranteeCanonicality || guarantee == verify.GuaranteeStateTransition {
			t.Fatal("recorded workflow emitted an unsupported guarantee")
		}
	}
}

func TestExperimentalV3RecordedChain69TypedHistory(t *testing.T) {
	// The original pinned node emitted these proof bytes after its disposable
	// tree was reopened. Linux, macOS and Windows recorded identical bytes in
	// run 44882528531, attempt 1. Both projected headers are unsigned.
	const chainID, domainID, batchID = 69, 1, 0
	digest := func(value string) chain.Hash {
		t.Helper()
		var hash chain.Hash
		if err := hash.UnmarshalText([]byte(value)); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	empty := sha3.Sum256(nil)
	header := func(height, timestamp uint64, hash, parent, changes, stateRoot string) chain.CandidateV3Header {
		return chain.CandidateV3Header{
			Header: chain.Header{
				Version: 3, ChainIdentifier: chainID, Height: height, TimestampUnix: timestamp,
				HeaderHash: digest(hash), PreviousHash: digest(parent), ChangesHash: digest(changes),
				DataHash: empty, ContentHash: empty, NextFusionPrice: 1000, NextWorkPrice: 1000,
			},
			StateRoot: digest(stateRoot),
		}
	}
	target := header(5, 1794699080, "938d9640571e09c8e9682b012b6cd5c6358279544fb77f5481c39d57b5035f11",
		"88b5157d36fadebd3c2f7a79bff1ab8f8331c2def25cfdf35b4695aa2cc1817e", "439ee6c7bc06a94638fe65d14f0c1acfdbab49b2ce4a3852ca7610464f2dc87e",
		"a64d693d3d49a55765dadb0fdf16c2908e3e5c314cdee984863b7fca71d5808c")
	tip := header(6, 1794699090, "eb3c8e761388b622a3e1c3b3ea62ae17e89d307358e0ae817617e5dce490db98",
		"938d9640571e09c8e9682b012b6cd5c6358279544fb77f5481c39d57b5035f11", "f3c520dca8736dbedcf65b3b02c7fb924f030c0f464d0eb5f9e566696c3d4420",
		"c7cc587a01c16699858a3db76c3ab8cedaa4fa4662b740fa8575438ab063e716")
	for _, candidate := range []chain.CandidateV3Header{target, tip} {
		if hash, err := candidate.ComputeHash(); err != nil || hash != candidate.Header.HeaderHash {
			t.Fatalf("recorded header hash changed at height %d: %v", candidate.Header.Height, err)
		}
		if _, err := json.Marshal(candidate); !errors.Is(err, chain.ErrCandidateV3Header) {
			t.Fatalf("unsigned header must fail wire validation: %v", err)
		}
	}
	if tip.Header.PreviousHash != target.Header.HeaderHash || tip.StateRoot == target.StateRoot {
		t.Fatal("recorded target and tip binding changed")
	}

	var settlement chain.Address
	if err := settlement.UnmarshalText([]byte("01b3b6e5adcb4d0cad7fcef33598c6318c6318c0")); err != nil {
		t.Fatal(err)
	}
	selected := fetch.CandidateBatchCollectionSelection{
		ChainID: chainID, AnchorHeight: target.Header.Height - 1, AnchorHash: target.Header.PreviousHash,
		Height: target.Header.Height, HeaderHash: target.Header.HeaderHash, TipHeight: tip.Header.Height,
		TipHash: tip.Header.HeaderHash, Settlement: settlement, DomainID: domainID, BatchID: batchID,
	}
	resume := fetch.CandidateBatchContextResume{Height: selected.TipHeight, Hash: selected.TipHash}

	members := [...]struct {
		role, key, digest, encoded string
		proofBytes, siblings       int
	}{
		{role: "batch_entry", key: "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c00402000000010000000000000000", digest: "2a8b3a0908961ca58b5e4d06754eae9400847230170ff5a71aef73697396bcd6",
			proofBytes: 1063, siblings: 5, encoded: `
AV7kNY/z0A9LJM/aHZv1EgwCzhWUrqStpxdnuS6GKG1vLIG8W9DbnVLkUxargh49qqpetmgCMq0D
6sGt+pw5jHMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwAF0hRjVDIeNrQJMRsQR3Qt
mYQ6sMdlZ0X9q96cyJmgutDBJRbs4emaCx5sMn3upyZw0AlRZ0KGW6Kmrd3gvyNx2kcpu956VrKe
r1qZiIHdUoRuDuJhyH4lw8JLNmxGP9lm80Dup4K/xFtOUjjuIPbnRRiA+V4ZEolXx+qtObw84Ojt
VkSjdOO7sEapNvaBZ2KiZG0o6DRGPkqrD1lSwhHYXAAAAyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFFRUVFRUVFR
UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAx
MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy
MjIyMjIyMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0
NDQ0NDQ0NDQ0NDQ0NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATQAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1URVNULXBpbGxhci0xAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABkAAAAAQAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAU5mMYxjGMYxjGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
`},
		{role: "domain_record", key: "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c0040100000001", digest: "428d72cce1c35f3d3069859880e7203c015b079b05748b4b58c74ac8875a7897",
			proofBytes: 775, siblings: 7, encoded: `
AR+9Oxvoz74XlCsbGCwkjTEFxXHGWw9C1092zeKQxi0IMCQ4cJv/y9Lb2D7/0olI9iFA1w+1W51R
fe9kC5zV5KoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3wAHbqbMTqDrAwahPV+7kjt2
HPiu/qcf9I44uegLt8pKR+ThFHJoYFDVO8A/lqChMee3JOqXM9g1CuTsUvzNceLgRjQ2ZwZI8ycW
KU44GDHfJkT2OR/4lT3yIuKuT3ffheUFkMCyuf/k+QD06c+Kd2+OSGuSdEpM7TUopDY94JdoZXpT
DRDVwi8ksEsm4GsX+7Fe3dij738UHQW4xy7s3A0HWOUcDWn6njyEM2q0d2oq4JPWqTkA0SXz+g2v
ON63UU4I7VZEo3Tju7BGqTb2gWdiomRtKOg0Rj5Kqw9ZUsIR2FwAAAHAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAwQFBgcI
CQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
`},
		{role: "domain_config", key: "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c0041500000001", digest: "75f2db9f9088f68193cf95492e04bd3a06d29f08cdd52a3d5b6335637ddfb265",
			proofBytes: 359, siblings: 6, encoded: `
AZQhWW4w8ntd5EXHRDZb6z1lijz8iRZ5G7LtJo63g1VZkM2oS3yy7O4SdoV0hI9Ctvw/OGwd6h77
MvQBTEN8udYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPwAGYc33n5ZHPkCpVIlakS0p
qS/XTQfbOQKuGh08QsiC6llYYdd/IpwuykZ2QTsHkAfm8WUbrhvIXl4gVVpjyz4QqaNyI6VEjuAG
PmfUQwSE9rS/qOAT2xzjVwdSwLbFIVe9anwBkiAQpNtmdm6uopLSIO07CPLhZdjY0Ayk7r4kVP3/
+aqoZB80HjYeqTQvfX1rQVj/kGB6GWrKy//q69UYaKX2JBx3H8BHLPVrS1BlPTlNrrnIvv8BTui/
IKsg15U0AAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAEA=
`},
	}
	rawRows, err := os.ReadFile("../testdata/conformance/batch-context-node-witness.json")
	if err != nil || sha256.Sum256(rawRows) != digest("773cda402e08709ffd73adfea355f73269b1470b7336c5a027ddd5b331ab9d96") {
		t.Fatalf("selected stored ABI bytes changed: %v", err)
	}
	var stored struct {
		Rows []struct {
			Role  string `json:"name"`
			Key   string `json:"ledger_key_hex"`
			Value string `json:"value_hex"`
		}
	}
	if err := json.Unmarshal(rawRows, &stored); err != nil || len(stored.Rows) != 4 {
		t.Fatalf("selected stored ABI rows changed: %v", err)
	}

	decodeProof := func(encoded string, expectedSize int, expectedHash string) []byte {
		t.Helper()
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) != expectedSize || sha256.Sum256(raw) != digest(expectedHash) {
			t.Fatalf("recorded proof bytes changed: %v", err)
		}
		return raw
	}
	type recordedStateProof struct {
		Value []byte     `json:"value"`
		Proof []byte     `json:"proof"`
		Root  chain.Hash `json:"root"`
	}
	wireWitness := func(root chain.Hash, value, rawProof []byte) []byte {
		t.Helper()
		// Match the original StateProof result's field order.
		wire, err := json.Marshal(struct {
			JSONRPC string             `json:"jsonrpc"`
			ID      int                `json:"id"`
			Result  recordedStateProof `json:"result"`
		}{JSONRPC: "2.0", ID: 1, Result: recordedStateProof{Value: value, Proof: rawProof, Root: root}})
		if err != nil {
			t.Fatal(err)
		}
		return append(wire, '\n')
	}
	replay := func(t *testing.T, height uint64, keys []string, replies [][]byte) (*fetch.Client, *int) {
		t.Helper()
		calls := 0
		client := fetch.NewClient("https://recorded.invalid")
		client.HTTP.Transport = experimentalV3Transport(func(req *http.Request) (*http.Response, error) {
			var call struct {
				Method string            `json:"method"`
				Params []json.RawMessage `json:"params"`
			}
			var gotHeight uint64
			var gotKey []byte
			if err := json.NewDecoder(req.Body).Decode(&call); err != nil || call.Method != "ledger.getProof" ||
				calls >= len(keys) || len(call.Params) != 2 ||
				json.Unmarshal(call.Params[0], &gotHeight) != nil || gotHeight != height ||
				json.Unmarshal(call.Params[1], &gotKey) != nil || hex.EncodeToString(gotKey) != keys[calls] {
				t.Fatal("collector did not request the selected original proof key and height")
			}
			body := replies[calls]
			calls++
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
		})
		return client, &calls
	}

	t.Run("retained-three-row-membership", func(t *testing.T) {
		keys := make([]string, len(members))
		values, proofs, replies := make([][]byte, len(members)), make([][]byte, len(members)), make([][]byte, len(members))
		for i, member := range members {
			row := stored.Rows[i]
			value, err := hex.DecodeString(row.Value)
			if err != nil || row.Role != member.role || row.Key != member.key || len(value) == 0 {
				t.Fatalf("stored value identity changed for %s: %v", member.role, err)
			}
			keys[i], values[i] = member.key, value
			proofs[i] = decodeProof(member.encoded, member.proofBytes, member.digest)
			replies[i] = wireWitness(target.StateRoot, value, proofs[i])
		}
		client, calls := replay(t, selected.Height, keys, replies)
		raw, err := client.FetchCandidateBatchContextBundleAfter(context.Background(), selected, resume, false)
		var bundle struct {
			Momentums []json.RawMessage          `json:"momentums"`
			Witnesses map[string]json.RawMessage `json:"witnesses"`
		}
		if err != nil || *calls != len(members) || json.Unmarshal(raw, &bundle) != nil ||
			bundle.Momentums == nil || len(bundle.Momentums) != 0 || len(bundle.Witnesses) != len(members) {
			t.Fatalf("expected exactly three historical witnesses without header reads: %v", err)
		}

		inputs := make([]proof.CandidateSMTProofInput, len(members))
		for i, member := range members {
			witness, err := fetch.DecodeCandidateStateWitness(bundle.Witnesses[member.role])
			if err != nil || witness.Root != target.StateRoot || !bytes.Equal(witness.Value, values[i]) ||
				!bytes.Equal(witness.Proof, proofs[i]) {
				t.Fatalf("collected witness changed for %s: %v", member.role, err)
			}
			key, err := hex.DecodeString(member.key)
			if err != nil {
				t.Fatal(err)
			}
			inputs[i] = proof.CandidateSMTProofInput{
				Path: sha3.Sum256(key), Proof: witness.Proof, MaxSiblings: member.siblings,
				Limits: proof.CandidateSMTLimits{MaxProofBytes: len(proofs[i]), MaxValueBytes: len(values[i])},
			}
		}
		limits := proof.CandidateSMTSetLimits{MaxProofs: 3, MaxTotalProofBytes: 2197, MaxTotalValueBytes: 1312, MaxTotalSiblings: 18}
		matches, err := proof.ReadCandidateSMTProofSet(target.StateRoot, inputs, limits)
		if err != nil || len(matches) != len(members) {
			t.Fatalf("proofs failed against the recorded H5 root: %v", err)
		}
		for i, match := range matches {
			if !match.Present || !match.Canonical || int(match.SiblingCount) != members[i].siblings || !bytes.Equal(match.Value, values[i]) {
				t.Fatalf("expected the exact canonical member for %s", members[i].role)
			}
		}
		if wrong, err := proof.ReadCandidateSMTProofSet(tip.StateRoot, inputs, limits); !errors.Is(err, proof.ErrCandidateSMTMismatch) || wrong != nil {
			t.Fatalf("the historical proofs must fail under the H6 root: %v", err)
		}

		entry, err := proof.DecodeCandidateBatchEntry(matches[0].Value, proof.CandidateBatchEntryLimits{
			MaxValueBytes: 800, MaxExecutorPillarBytes: 13, MaxAssetFlowSummaryBytes: 100,
			MaxProofDataBytes: 1, MaxDynamicBytes: 113, StringRule: proof.CandidateBatchEntryUTF8String,
		})
		if err != nil || entry.ProtocolVersion != 1 || entry.SubmittedAtHeight != 77 || entry.FinalizeAtHeight != 87 ||
			entry.ExecutorPillar != "TEST-pillar-1" || entry.PostStateRoot != digest(strings.Repeat("51", chain.HashSize)) ||
			len(entry.AssetFlowSummary) != 100 || len(entry.ProofData) != 0 {
			t.Fatalf("decoded BatchEntry fields differ from the recorded bytes: %v", err)
		}
		record, err := proof.DecodeCandidateDomainRecord(matches[1].Value, proof.CandidateDomainRecordLimits{
			MaxValueBytes: 448, MaxProfileConfigBytes: 1, MaxChainBindingBytes: 1, MaxDynamicBytes: 1,
		})
		if err != nil || record.MinExecutors != 1 || record.StfSpecHash != digest("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20") ||
			len(record.ProfileConfig) != 0 || len(record.ChainBinding) != 0 {
			t.Fatalf("decoded domain record differs from the recorded bytes: %v", err)
		}
		config, err := proof.DecodeCandidateDomainConfig(matches[2].Value)
		if err != nil || config.WithdrawalDelay != 30 || config.RuntimeUpgradeDelay != 64 {
			t.Fatalf("decoded domain config differs from the recorded bytes: %v", err)
		}
	})

	t.Run("pruned-history-is-an-error", func(t *testing.T) {
		wire := []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"trie: no such version\"}}\n")
		client, calls := replay(t, selected.Height, []string{members[0].key}, [][]byte{wire})
		raw, err := client.FetchCandidateBatchContextBundleAfter(context.Background(), selected, resume, false)
		if err == nil || !strings.HasSuffix(err.Error(), "rpc error -32000") || raw != nil || *calls != 1 {
			t.Fatalf("pruned H5 must fail before reading another proof or returning a bundle: %v", err)
		}
	})

	t.Run("tip-batch-absence", func(t *testing.T) {
		raw := decodeProof(`
AF7kNY/z0A9LJM/aHZv1EgwCzhWUrqStpxdnuS6GKG1vAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwAF0hRjVDIeNrQJMRsQR3Qt
mYQ6sMdlZ0X9q96cyJmgutDBJRbs4emaCx5sMn3upyZw0AlRZ0KGW6Kmrd3gvyNx2kcpu956VrKe
r1qZiIHdUoRuDuJhyH4lw8JLNmxGP9lm80Dup4K/xFtOUjjuIPbnRRiA+V4ZEolXx+qtObw84Ojt
VkSjdOO7sEapNvaBZ2KiZG0o6DRGPkqrD1lSwhHYXA==
`, 259, "afcea2256020d740de66ddd561862e19a21689bbc3b3c796979eb38dcba7b911")
		wire := wireWitness(tip.StateRoot, nil, raw)
		if len(wire) != 482 || sha256.Sum256(wire) != digest("885a48658f1791478bbeef14da98f8e79faf4472c198f8da828388ce03a84787") {
			t.Fatal("reconstructed H6 RPC reply differs from the original")
		}
		client, calls := replay(t, selected.TipHeight, []string{members[0].key}, [][]byte{wire})
		witness, err := client.FetchCandidateBatchEntryProof(context.Background(), selected.TipHeight, settlement, domainID, batchID)
		if err != nil || witness.Root != tip.StateRoot || witness.Value != nil || !bytes.Equal(witness.Proof, raw) || *calls != 1 {
			t.Fatalf("H6 absence witness changed during collection: %v", err)
		}
		key := proof.CandidateSettlementBatchEntryKey(settlement, domainID, batchID)
		input := proof.CandidateSMTProofInput{
			Path: sha3.Sum256(key[:]), Proof: witness.Proof, MaxSiblings: 5,
			Limits: proof.CandidateSMTLimits{MaxProofBytes: len(raw), MaxValueBytes: 1},
		}
		limits := proof.CandidateSMTSetLimits{MaxProofs: 1, MaxTotalProofBytes: len(raw), MaxTotalValueBytes: 1, MaxTotalSiblings: 5}
		matches, err := proof.ReadCandidateSMTProofSet(tip.StateRoot, []proof.CandidateSMTProofInput{input}, limits)
		if err != nil || len(matches) != 1 || matches[0].Present || !matches[0].Canonical || matches[0].Value != nil {
			t.Fatalf("expected canonical absence under the H6 root: %v", err)
		}
	})
}
