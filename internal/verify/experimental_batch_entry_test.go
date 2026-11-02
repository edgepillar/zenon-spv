// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func TestExperimentalBatchEntryOwnedRootCannotBeSubstituted(t *testing.T) {
	state, p, c, request := experimentalBatchInputs(t)
	q, err := NewExperimentalBatchEntryQuery(state, p, c.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	value := experimentalBatchPacked(t, "typical")
	root, path, raw := experimentalBatchMathWitness(p, request.BatchID, value)
	math, err := proof.ReadCandidateSMTProof(root, path, raw, proof.CandidateSMTLimits{MaxProofBytes: int(p.MaxProofBytes), MaxValueBytes: int(p.Limits.MaxValueBytes)})
	if err != nil || !bytes.Equal(math.Value, value) {
		t.Fatal("mathematical fixture failed", err)
	}
	owned, err := state.RootAt(request.Height, request.HeaderHash, c.Header.Fingerprint)
	if err != nil || owned == root {
		t.Fatal("fixture does not distinguish candidate and owned roots", err)
	}
	result, err := q.Query(request, raw)
	requireExperimentalBatchNoResult(t, result, err)
	if !errors.Is(err, proof.ErrCandidateSMTMismatch) {
		t.Fatal("valid proof for another root was not refused", err)
	}
	witness := proof.CandidateStateWitness{Root: root, Value: value, Proof: raw}
	result, err = q.QueryWitness(request, witness)
	requireExperimentalBatchNoResult(t, result, err)
	if err != ErrExperimentalBatchEntryWitnessRoot {
		t.Fatal("provider selected the verification root", err)
	}
	witness.Root = owned
	result, err = q.QueryWitness(request, witness)
	requireExperimentalBatchNoResult(t, result, err)
	if !errors.Is(err, proof.ErrCandidateSMTMismatch) {
		t.Fatal("copying the owned root into a hint supplied authority", err)
	}
	result, err = q.QueryWithGateway(request, witness, proof.CandidateSettlementBatch{DomainID: p.DomainID, BatchID: request.BatchID})
	requireExperimentalBatchNoResult(t, result, err)
	if !errors.Is(err, proof.ErrCandidateSMTMismatch) {
		t.Fatal("gateway bypassed proof verification", err)
	}
	if chain.ValidateHeaderVersion(3) == nil {
		t.Fatal("experimental query enabled production v3")
	}
}

func TestExperimentalBatchEntryQueryIdentityAndResourceRefusals(t *testing.T) {
	state, p, c, request := experimentalBatchInputs(t)
	q, err := NewExperimentalBatchEntryQuery(state, p, c.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ExperimentalBatchEntryRequest){
		"context-zero":         func(r *ExperimentalBatchEntryRequest) { r.Context = chain.Hash{} },
		"context-different":    func(r *ExperimentalBatchEntryRequest) { r.Context[0] ^= 1 },
		"height-zero":          func(r *ExperimentalBatchEntryRequest) { r.Height = 0 },
		"evicted":              func(r *ExperimentalBatchEntryRequest) { r.Height = 12 },
		"tip-not-deep":         func(r *ExperimentalBatchEntryRequest) { r.Height = 14; r.HeaderHash = r.TipHash },
		"header-zero":          func(r *ExperimentalBatchEntryRequest) { r.HeaderHash = chain.Hash{} },
		"header-different":     func(r *ExperimentalBatchEntryRequest) { r.HeaderHash[0] ^= 1 },
		"tip-height-zero":      func(r *ExperimentalBatchEntryRequest) { r.TipHeight = 0 },
		"tip-height-different": func(r *ExperimentalBatchEntryRequest) { r.TipHeight++ },
		"tip-hash-zero":        func(r *ExperimentalBatchEntryRequest) { r.TipHash = chain.Hash{} },
		"tip-hash-different":   func(r *ExperimentalBatchEntryRequest) { r.TipHash[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			change(&changed)
			r, e := q.Query(changed, nil)
			requireExperimentalBatchNoResult(t, r, e)
		})
	}
	value := experimentalBatchPacked(t, "typical")
	_, _, raw := experimentalBatchMathWitness(p, request.BatchID, value)
	changed := request
	changed.BatchID++
	r, e := q.Query(changed, raw)
	requireExperimentalBatchNoResult(t, r, e)
	if !errors.Is(e, proof.ErrCandidateSMTPath) {
		t.Fatal("batch substitution did not change the local path", e)
	}
	large := make([]byte, 1<<20)
	r, e = q.Query(request, large)
	requireExperimentalBatchNoResult(t, r, e)
	if !errors.Is(e, proof.ErrCandidateSMTBounds) {
		t.Fatal("oversized raw proof was consumed", e)
	}
	root, err := state.RootAt(request.Height, request.HeaderHash, c.Header.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []proof.CandidateStateWitness{{Root: root, Value: large, Proof: raw}, {Root: root, Value: value, Proof: large}} {
		r, e = q.QueryWitness(request, w)
		requireExperimentalBatchNoResult(t, r, e)
		if !errors.Is(e, proof.ErrCandidateSMTBounds) {
			t.Fatal("oversized typed witness was consumed", e)
		}
	}
	var zero ExperimentalBatchEntryQuery
	r, e = zero.Query(request, raw)
	requireExperimentalBatchNoResult(t, r, e)
	if e != ErrUninitializedState {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 16; j++ {
				r, e := q.Query(request, nil)
				if !errors.Is(e, proof.ErrCandidateSMTEncoding) || !reflect.DeepEqual(r, ExperimentalBatchEntryResult{}) {
					t.Error("concurrent query changed its binding", e)
				}
			}
		}()
	}
	wg.Wait()
}

func TestExperimentalBatchEntryProofABICompositionMathOnly(t *testing.T) {
	// These are pure proof/ABI compositions, not positive exported owned-state
	// queries. A signed header plus matching BatchEntry witness remains a gate.
	for _, name := range []string{"empty-dynamic", "typical", "word-31", "word-32", "word-33", "unsigned-widths", "non-utf8-packer"} {
		t.Run(name, func(t *testing.T) {
			p := experimentalBatchProfile()
			value := experimentalBatchPacked(t, name)
			root, path, raw := experimentalBatchMathWitness(p, 1, value)
			match, entry, err := readExperimentalBatchEntry(root, path, raw, p)
			if name == "non-utf8-packer" {
				if err != proof.ErrCandidateBatchEntryEncoding || !reflect.DeepEqual(match, proof.CandidateSMTMatch{}) || !reflect.DeepEqual(entry, proof.CandidateBatchEntry{}) {
					t.Fatal("UTF-8 policy was bypassed", err)
				}
				p.Limits.StringRule = proof.CandidateBatchEntryOpaqueString
				match, entry, err = readExperimentalBatchEntry(root, path, raw, p)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := json.Marshal(ExperimentalBatchEntryResult{Entry: entry}); !errors.Is(err, ErrExperimentalBatchEntryJSON) {
					t.Fatal("opaque bytes were replaced in JSON", err)
				}
			}
			if err != nil || !match.Present || !match.Canonical || !bytes.Equal(match.Value, value) {
				t.Fatal("mathematical value read/ABI composition", err)
			}
			match.Value[0] ^= 1
			if bytes.Equal(match.Value, raw[len(raw)-len(value):]) {
				t.Fatal("returned value aliases proof bytes")
			}
		})
	}
	p := experimentalBatchProfile()
	value := experimentalBatchPacked(t, "typical")
	for _, kind := range []string{"integer", "offset", "padding", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(value)
			switch kind {
			case "integer":
				bad[0] = 1
			case "offset":
				bad[11*32+31] ^= 1
			case "padding":
				bad[len(bad)-1] = 1
			case "trailing":
				bad = append(bad, 0)
			}
			root, path, raw := experimentalBatchMathWitness(p, 1, bad)
			match, entry, err := readExperimentalBatchEntry(root, path, raw, p)
			if err == nil || !reflect.DeepEqual(match, proof.CandidateSMTMatch{}) || !reflect.DeepEqual(entry, proof.CandidateBatchEntry{}) {
				t.Fatal("valid math supplied an invalid typed row", err)
			}
		})
	}
}

func TestExperimentalBatchEntryCanonicalAbsenceAndExactBounds(t *testing.T) {
	p := experimentalBatchProfile()
	value := experimentalBatchPacked(t, "typical")
	root, path, raw := experimentalBatchMathWitness(p, 1, value)
	zeroSibling := append(append(append([]byte(nil), raw[:99]...), make([]byte, 32)...), raw[99:]...)
	zeroSibling[65] = 0x80
	binary.BigEndian.PutUint16(zeroSibling[97:99], 1)
	match, entry, err := readExperimentalBatchEntry(root, path, zeroSibling, p)
	if err != ErrExperimentalBatchEntryCanonical || !reflect.DeepEqual(match, proof.CandidateSMTMatch{}) || !reflect.DeepEqual(entry, proof.CandidateBatchEntry{}) {
		t.Fatal("equivalent noncanonical proof accepted", err)
	}
	p.MaxSiblings = 0
	if _, _, err := readExperimentalBatchEntry(root, path, zeroSibling, p); err != proof.ErrCandidateSMTBounds {
		t.Fatal("explicit sibling ceiling ignored", err)
	}
	p.MaxProofBytes = uint32(len(raw))
	if _, _, err := readExperimentalBatchEntry(root, path, raw, p); err != nil {
		t.Fatal("exact proof bound", err)
	}
	p.MaxProofBytes--
	if _, _, err := readExperimentalBatchEntry(root, path, raw, p); err != proof.ErrCandidateSMTBounds {
		t.Fatal("proof over bound", err)
	}
	absence := make([]byte, 99)
	copy(absence[1:33], path[:])
	p = experimentalBatchProfile()
	match, entry, err = readExperimentalBatchEntry(chain.Hash{}, path, absence, p)
	if err != ErrExperimentalBatchEntryAbsent || !reflect.DeepEqual(match, proof.CandidateSMTMatch{}) || !reflect.DeepEqual(entry, proof.CandidateBatchEntry{}) {
		t.Fatal("absence became a typed or zero row", err)
	}
}

func TestExperimentalBatchEntryGatewayStoredFieldComparison(t *testing.T) {
	p := experimentalBatchProfile()
	_, entry, err := readExperimentalBatchEntryFixture(t, p)
	if err != nil {
		t.Fatal(err)
	}
	base := proof.CandidateSettlementBatch{DomainID: p.DomainID, BatchID: 1, Entry: entry}
	for _, hint := range []bool{false, true} {
		base.IsFinalized = hint
		if !sameExperimentalBatchEntryGateway(p.DomainID, 1, entry, base) {
			t.Fatal("frontier hint was treated as a stored field")
		}
	}
	for name, change := range map[string]func(*proof.CandidateSettlementBatch){
		"domain": func(g *proof.CandidateSettlementBatch) { g.DomainID++ }, "batch": func(g *proof.CandidateSettlementBatch) { g.BatchID++ },
		"protocol": func(g *proof.CandidateSettlementBatch) { g.Entry.ProtocolVersion++ }, "first": func(g *proof.CandidateSettlementBatch) { g.Entry.FirstInputSeq++ },
		"last": func(g *proof.CandidateSettlementBatch) { g.Entry.LastInputSeq++ }, "pre": func(g *proof.CandidateSettlementBatch) { g.Entry.PreStateRoot[0] ^= 1 },
		"post": func(g *proof.CandidateSettlementBatch) { g.Entry.PostStateRoot[0] ^= 1 }, "input": func(g *proof.CandidateSettlementBatch) { g.Entry.InputRoot[0] ^= 1 },
		"receipt": func(g *proof.CandidateSettlementBatch) { g.Entry.ReceiptRoot[0] ^= 1 }, "event": func(g *proof.CandidateSettlementBatch) { g.Entry.EventRoot[0] ^= 1 },
		"outbox": func(g *proof.CandidateSettlementBatch) { g.Entry.OutboxRoot[0] ^= 1 }, "da-hash": func(g *proof.CandidateSettlementBatch) { g.Entry.DaHash[0] ^= 1 },
		"da-mode": func(g *proof.CandidateSettlementBatch) { g.Entry.DaMode++ }, "executor": func(g *proof.CandidateSettlementBatch) { g.Entry.ExecutorPillar += "x" },
		"submitted": func(g *proof.CandidateSettlementBatch) { g.Entry.SubmittedAtHeight++ }, "finalize": func(g *proof.CandidateSettlementBatch) { g.Entry.FinalizeAtHeight++ },
		"asset": func(g *proof.CandidateSettlementBatch) {
			g.Entry.AssetFlowSummary = append(bytes.Clone(g.Entry.AssetFlowSummary), 1)
		},
		"proof-data": func(g *proof.CandidateSettlementBatch) { g.Entry.ProofData = append(bytes.Clone(g.Entry.ProofData), 1) }, "state": func(g *proof.CandidateSettlementBatch) { g.Entry.State++ },
	} {
		t.Run(name, func(t *testing.T) {
			different := base
			change(&different)
			if sameExperimentalBatchEntryGateway(p.DomainID, 1, entry, different) {
				t.Fatal("gateway substitution matched stored row")
			}
		})
	}
}

func readExperimentalBatchEntryFixture(t *testing.T, p ExperimentalBatchEntryProfile) (proof.CandidateSMTMatch, proof.CandidateBatchEntry, error) {
	t.Helper()
	value := experimentalBatchPacked(t, "typical")
	root, path, raw := experimentalBatchMathWitness(p, 1, value)
	return readExperimentalBatchEntry(root, path, raw, p)
}

func TestExperimentalBatchEntryResumeAndExactTipBinding(t *testing.T) {
	f := experimentalV3Inputs(t)
	initial := experimentalV3New(t, f)
	accepted, prefix := initial.Extend(f.headers[:2])
	if accepted.Outcome != OutcomeAccept {
		t.Fatal(accepted)
	}
	p := experimentalBatchProfile()
	c, err := ExperimentalBatchEntryContextFor(prefix, p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewExperimentalBatchEntryQuery(prefix, p, c.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request := ExperimentalBatchEntryRequest{Context: c.Fingerprint, Height: 12, HeaderHash: f.headers[0].Header.HeaderHash, TipHeight: 13, TipHash: f.headers[1].Header.HeaderHash, BatchID: 1}
	binding, err := q.binding(request)
	if err != nil {
		t.Fatal(err)
	}
	accepted, tail := prefix.Extend(f.headers[2:])
	if accepted.Outcome != OutcomeAccept {
		t.Fatal(accepted)
	}
	qc, err := ExperimentalBatchEntryContextFor(tail, p)
	if err != nil || qc != c {
		t.Fatal("static context unexpectedly pinned history", err)
	}
	latest, err := NewExperimentalBatchEntryQuery(tail, p, c.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := latest.binding(request); err != ErrExperimentalBatchEntryTip {
		t.Fatal("matching context reused another tip", err)
	}
	if again, err := q.binding(request); err != nil || again != binding {
		t.Fatal("later extension mutated query snapshot", err)
	}
	path := filepath.Join(t.TempDir(), "owned-v3.json")
	if err := tail.Save(path); err != nil {
		t.Fatal(err)
	}
	resumed, err := LoadTrustedExperimentalV3State(path, f.profile, f.policy, f.schedule, f.pin)
	if err != nil {
		t.Fatal(err)
	}
	rebound, err := NewExperimentalBatchEntryQuery(resumed, p, c.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request.Height = 13
	request.HeaderHash = f.headers[1].Header.HeaderHash
	request.TipHeight = 14
	request.TipHash = f.headers[2].Header.HeaderHash
	a, err := latest.binding(request)
	if err != nil {
		t.Fatal(err)
	}
	b, err := rebound.binding(request)
	if err != nil || a != b {
		t.Fatal("resumed exact query changed identity", err)
	}
	if a.fingerprint == binding.fingerprint {
		t.Fatal("query identity omitted header or tip")
	}
}
