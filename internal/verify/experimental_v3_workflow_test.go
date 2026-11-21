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

func TestExperimentalV3RecordedChain69H3ProofBoundary(t *testing.T) {
	const chainID, height = 69, 3
	digest := func(text string) chain.Hash {
		t.Helper()
		var hash chain.Hash
		if err := hash.UnmarshalText([]byte(text)); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	genesis := digest("fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9")
	empty := sha3.Sum256(nil)
	header := chain.CandidateV3Header{
		Header: chain.Header{
			Version: 3, ChainIdentifier: chainID, Height: height, TimestampUnix: 1794699060,
			HeaderHash:   digest("4946422fe25a40b1769e5e8063afde3b2f293c3bbc167dd5a3026988275ce0c6"),
			PreviousHash: digest("6203eed405db9b47b93628ed4178740150d35dbb3353bcee75fd622133c9798e"),
			DataHash:     empty, ContentHash: empty, ChangesHash: empty, NextFusionPrice: 1000, NextWorkPrice: 1000,
		},
		StateRoot: digest("36fd7a907707f00939bb4741da5d8f3dd4fdf4200581ebe869b934a8f1981287"),
	}
	if got, err := header.ComputeHash(); err != nil || got != header.Header.HeaderHash {
		t.Fatalf("recorded unsigned header hash changed: %v", err)
	}
	var settlement chain.Address
	if err := settlement.UnmarshalText([]byte("01b3b6e5adcb4d0cad7fcef33598c6318c6318c0")); err != nil {
		t.Fatal(err)
	}

	// The three exact proof payloads come from the original node output in
	// run 44675121122, attempt 1, Linux artifact 14601124031. The H3 result
	// records their digest and length and matches the retained H2 tree bytes.
	// The RPC envelopes below replay the pinned node's StateProof result shape.
	witnesses := []struct {
		role, key string
		siblings  int
		proof     string
	}{
		{"batch_entry", "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c00402000000010000000000000000", 5, `
AF7kNY/z0A9LJM/aHZv1EgwCzhWUrqStpxdnuS6GKG1vAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
HwAF0hRjVDIeNrQJMRsQR3QtmYQ6sMdlZ0X9q96cyJmgutDBJRbs4emaCx5sMn3u
pyZw0AlRZ0KGW6Kmrd3gvyNx2kcpu956VrKer1qZiIHdUoRuDuJhyH4lw8JLNmxG
P9lmfDvxMylQxivkGuUgmIl5rgiC5WGehYJtAFmBHvqnj+UPlIvLjb5qKOVOD2a0
OdAYrHN2GxcNKFtqe06rwikZeA==
`},
		{"domain_record", "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c0040100000001", 7, `
AB+9Oxvoz74XlCsbGCwkjTEFxXHGWw9C1092zeKQxi0IAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
3wAHbqbMTqDrAwahPV+7kjt2HPiu/qcf9I44uegLt8pKR+ThFHJoYFDVO8A/lqCh
Mee3JOqXM9g1CuTsUvzNceLgRjQ2ZwZI8ycWKU44GDHfJkT2OR/4lT3yIuKuT3ff
heUFkMCyuf/k+QD06c+Kd2+OSGuSdEpM7TUopDY94JdoZXpTDRDVwi8ksEsm4GsX
+7Fe3dij738UHQW4xy7s3A0HWDQn9I6DCWqzuM3diZ4RuwJYZt+gKRpBWfc4NAup
BBmyD5SLy42+aijlTg9mtDnQGKxzdhsXDShbantOq8IpGXg=
`},
		{"domain_config", "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c0041500000001", 6, `
AJQhWW4w8ntd5EXHRDZb6z1lijz8iRZ5G7LtJo63g1VZAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
PwAGYc33n5ZHPkCpVIlakS0pqS/XTQfbOQKuGh08QsiC6llYYdd/IpwuykZ2QTsH
kAfm8WUbrhvIXl4gVVpjyz4QqaNyI6VEjuAGPmfUQwSE9rS/qOAT2xzjVwdSwLbF
IVe9anwBkiAQpNtmdm6uopLSIO07CPLhZdjY0Ayk7r4kVP1tyiH26Di2PgSA0wwg
0c+VyKHgnjucrvBtHoqdDliljaWMxfbzej5c2C/RxRDo82SEkVQikQC9XZGM9gal
IM0e
`},
	}

	t.Run("replay-proof-reads", func(t *testing.T) {
		calls := 0
		rawProofs := make([][]byte, len(witnesses))
		for i, row := range witnesses {
			raw, err := base64.StdEncoding.Strict().DecodeString(row.proof)
			if err != nil || len(raw) != 99+row.siblings*chain.HashSize {
				t.Fatalf("invalid retained proof for %s: %v", row.role, err)
			}
			rawProofs[i] = raw
		}
		client := fetch.NewClient("https://candidate.invalid")
		client.HTTP.Transport = experimentalV3Transport(func(req *http.Request) (*http.Response, error) {
			var call struct {
				Method string            `json:"method"`
				Params []json.RawMessage `json:"params"`
			}
			var selectedHeight uint64
			var key []byte
			if json.NewDecoder(req.Body).Decode(&call) != nil || call.Method != "ledger.getProof" ||
				calls >= len(witnesses) || len(call.Params) != 2 ||
				json.Unmarshal(call.Params[0], &selectedHeight) != nil || selectedHeight != height ||
				json.Unmarshal(call.Params[1], &key) != nil || hex.EncodeToString(key) != witnesses[calls].key {
				t.Fatal("collector did not request the selected height and original full key")
			}
			wire, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"root": header.StateRoot, "value": nil, "proof": rawProofs[calls]},
			})
			if err != nil {
				t.Fatal(err)
			}
			calls++
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(wire))}, nil
		})
		selected := fetch.CandidateBatchCollectionSelection{
			ChainID: chainID, AnchorHeight: height - 1, AnchorHash: header.Header.PreviousHash,
			Height: height, HeaderHash: header.Header.HeaderHash, TipHeight: height, TipHash: header.Header.HeaderHash,
			Settlement: settlement, DomainID: 1, BatchID: 0,
		}
		raw, err := client.FetchCandidateBatchContextBundleAfter(context.Background(), selected,
			fetch.CandidateBatchContextResume{Height: height, Hash: selected.TipHash}, false)
		var bundle struct {
			Momentums []json.RawMessage
			Witnesses map[string]json.RawMessage
		}
		if err != nil || calls != len(witnesses) || json.Unmarshal(raw, &bundle) != nil ||
			bundle.Momentums == nil || len(bundle.Momentums) != 0 || len(bundle.Witnesses) != len(witnesses) {
			t.Fatalf("proof-only collection did not return exactly three witnesses: %v", err)
		}
		inputs := make([]proof.CandidateSMTProofInput, 0, len(witnesses))
		for i, row := range witnesses {
			witness, err := fetch.DecodeCandidateStateWitness(bundle.Witnesses[row.role])
			if err != nil || witness.Root != header.StateRoot || witness.Value != nil || !bytes.Equal(witness.Proof, rawProofs[i]) {
				t.Fatalf("retained witness changed for %s: %v", row.role, err)
			}
			key, err := hex.DecodeString(row.key)
			if err != nil {
				t.Fatal(err)
			}
			inputs = append(inputs, proof.CandidateSMTProofInput{
				Path: sha3.Sum256(key), Proof: witness.Proof, MaxSiblings: row.siblings,
				Limits: proof.CandidateSMTLimits{MaxProofBytes: len(rawProofs[i]), MaxValueBytes: 1},
			})
		}
		limits := proof.CandidateSMTSetLimits{MaxProofs: 3, MaxTotalProofBytes: 873, MaxTotalValueBytes: 1, MaxTotalSiblings: 18}
		results, err := proof.ReadCandidateSMTProofSet(header.StateRoot, inputs, limits)
		if err != nil || len(results) != len(witnesses) {
			t.Fatalf("node proofs did not reconstruct the recorded candidate header root: %v", err)
		}
		for i, result := range results {
			if result.Present || result.Value != nil || !result.Canonical || int(result.SiblingCount) != witnesses[i].siblings {
				t.Fatalf("expected canonical absence for %s", witnesses[i].role)
			}
		}
		if result, err := proof.ReadCandidateSMTProofSet(chain.Hash{}, inputs, limits); !errors.Is(err, proof.ErrCandidateSMTMismatch) || result != nil {
			t.Fatalf("proof set must fail against the zero root in the v1 parent: %v", err)
		}
		limits.MaxTotalProofBytes--
		if result, err := proof.ReadCandidateSMTProofSet(header.StateRoot, inputs, limits); !errors.Is(err, proof.ErrCandidateSMTBounds) || result != nil {
			t.Fatalf("proof set must fail at one byte below the selected budget: %v", err)
		}
	})

	t.Run("unsigned-header-cannot-supply-an-owned-root", func(t *testing.T) {
		profile := verify.ExperimentalV3Profile{
			Version: 1, FirstV3Height: height, ValidThrough: height,
			Genesis:      verify.GenesisTrustRoot{ChainID: chainID, Height: 1, HeaderHash: genesis},
			Anchor:       verify.GenesisTrustRoot{ChainID: chainID, Height: height - 1, HeaderHash: header.Header.PreviousHash},
			NodeRevision: verify.ExperimentalV3ReferenceGasNodeRevision, Source: "isolated unsigned H3 fixture",
		}
		policy := verify.ExperimentalV3Policy{W: 1, RetainHeaders: 2, MaxBatchHeaders: 1}
		// A test-only schedule covers the fixture height. Signature rejection
		// must occur before producer authorization can use the configured entry.
		schedule, err := verify.NewProducerSchedule(chainID, []verify.ProducerCoverage{{FromHeight: height, ThroughHeight: height}},
			[]verify.ProducerEntry{{Height: height, TimestampUnix: header.Header.TimestampUnix, ProducingAddr: chain.Address{0, 1}}}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := verify.PrepareExperimentalV3Configuration(profile, policy, schedule)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := prepared.Context().Fingerprint
		state, err := prepared.NewState(fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		result, next := state.Extend([]chain.CandidateV3Header{header})
		if result.Outcome != verify.OutcomeReject || result.Reason != verify.ReasonInvalidSignature || result.FailedAt != 0 || !next.Empty() {
			t.Fatalf("unsigned H3 changed the owned state: %+v", result)
		}
		root, err := next.RootAt(height, header.Header.HeaderHash, fingerprint)
		if !errors.Is(err, verify.ErrExperimentalV3HeaderUnavailable) || !root.IsZero() {
			t.Fatalf("unsigned H3 supplied an owned root: %v", err)
		}
	})
}

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
