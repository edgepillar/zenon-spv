// SPDX-License-Identifier: MIT

package proof_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
)

func TestCandidateSMTValueReadsRecordedCases(t *testing.T) {
	cases := candidateSMTCases(t)
	storedOne := candidateSMTBytes(t, candidateSMTSelect(t, cases, "positive-one").Value)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			wantResult, wantPresent, wantValue := c.NodeResult, c.Present, candidateSMTBytes(t, c.Value)
			switch c.Name {
			case "wrong-rpc-value", "present-proof-used-for-absence":
				// The query reads the stored value; it does not repeat the old
				// caller's different value/presence comparison.
				wantResult, wantPresent, wantValue = "match", true, storedOne
			case "absence-proof-used-for-presence":
				wantResult, wantPresent, wantValue = "match", false, nil
			}
			result, err := proof.ReadCandidateSMTProof(candidateSMTHash(t, c.Root), candidateSMTHash(t, c.Path), candidateSMTBytes(t, c.Proof), candidateSMTLimits())
			if wantResult != "match" {
				want := map[string]error{"malformed": proof.ErrCandidateSMTEncoding, "path_mismatch": proof.ErrCandidateSMTPath, "mismatch": proof.ErrCandidateSMTMismatch}[wantResult]
				if want == nil {
					t.Fatal("unselected source result")
				}
				requireCandidateSMTError(t, result, err, want)
				return
			}
			canonical := c.Name != "stored-zero-sibling-equivalent" && c.Name != "absent-stored-zero-sibling-equivalent"
			if err != nil || result.Present != wantPresent || result.Canonical != canonical || !bytes.Equal(result.Value, wantValue) {
				t.Fatal("root-bound value read differs from recorded bytes", err)
			}
		})
	}
}

func TestCandidateSMTValueReadKeepsComparisonContract(t *testing.T) {
	cases := candidateSMTCases(t)
	c := candidateSMTSelect(t, cases, "wrong-rpc-value")
	want := candidateSMTBytes(t, candidateSMTSelect(t, cases, "positive-one").Value)
	root, path, raw := candidateSMTHash(t, c.Root), candidateSMTHash(t, c.Path), candidateSMTBytes(t, c.Proof)
	if result, err := proof.CheckCandidateSMTInclusion(root, path, candidateSMTBytes(t, c.Value), raw, candidateSMTLimits()); !errors.Is(err, proof.ErrCandidateSMTMismatch) || !reflect.DeepEqual(result, proof.CandidateSMTMatch{}) {
		t.Fatal("expected-value API no longer compares the claimed value")
	}
	result, err := proof.ReadCandidateSMTProof(root, path, raw, candidateSMTLimits())
	if err != nil || !bytes.Equal(result.Value, want) {
		t.Fatal("query could not read the actual stored value", err)
	}
	result.Value[0] = 9
	next, err := proof.ReadCandidateSMTProof(root, path, raw, candidateSMTLimits())
	if err != nil || !bytes.Equal(next.Value, want) {
		t.Fatal("query output aliases its input", err)
	}
}

func TestCandidateSMTValueReadBounds(t *testing.T) {
	c := candidateSMTSelect(t, candidateSMTCases(t), "positive-one")
	root, path, raw := candidateSMTHash(t, c.Root), candidateSMTHash(t, c.Path), candidateSMTBytes(t, c.Proof)
	want := candidateSMTBytes(t, c.Value)
	for _, limits := range []proof.CandidateSMTLimits{{}, {MaxProofBytes: len(raw) - 1, MaxValueBytes: len(want)}, {MaxProofBytes: proof.CandidateSMTMaxProofBytes + 1, MaxValueBytes: len(want)}, {MaxProofBytes: len(raw), MaxValueBytes: 4097}, {MaxProofBytes: len(raw), MaxValueBytes: len(want) - 1}} {
		result, err := proof.ReadCandidateSMTProof(root, path, raw, limits)
		requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTBounds)
	}
	for length := 0; length < 99; length++ {
		result, err := proof.ReadCandidateSMTProof(root, path, raw[:length], candidateSMTLimits())
		requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTEncoding)
	}
	if result, err := proof.ReadCandidateSMTProof(root, path, raw, proof.CandidateSMTLimits{MaxProofBytes: len(raw), MaxValueBytes: len(want)}); err != nil || !bytes.Equal(result.Value, want) {
		t.Fatal("exact explicit query byte bounds", err)
	}
}
