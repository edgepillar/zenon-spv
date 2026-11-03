// SPDX-License-Identifier: MIT

package proof_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func candidateSMTSetLimits() proof.CandidateSMTSetLimits {
	return proof.CandidateSMTSetLimits{MaxProofs: 3, MaxTotalProofBytes: 3 * proof.CandidateSMTMaxProofBytes,
		MaxTotalValueBytes: 3 * proof.CandidateSMTMaxValueBytes, MaxTotalSiblings: 3 * 256}
}

func candidateSMTSetInputs(t testing.TB, names ...string) (chain.Hash, []proof.CandidateSMTProofInput) {
	t.Helper()
	cases := candidateSMTCases(t)
	var root chain.Hash
	var inputs []proof.CandidateSMTProofInput
	for _, name := range names {
		c := candidateSMTSelect(t, cases, name)
		selected := candidateSMTHash(t, c.Root)
		if len(inputs) > 0 && root != selected {
			t.Fatal("fixture does not select one root")
		}
		root = selected
		inputs = append(inputs, proof.CandidateSMTProofInput{Path: candidateSMTHash(t, c.Path),
			Proof: candidateSMTBytes(t, c.Proof), Limits: candidateSMTLimits(), MaxSiblings: 256})
	}
	return root, inputs
}

func candidateSMTSetRefuse(t testing.TB, root chain.Hash, inputs []proof.CandidateSMTProofInput, limits proof.CandidateSMTSetLimits, want error) {
	t.Helper()
	result, err := proof.ReadCandidateSMTProofSet(root, inputs, limits)
	if !errors.Is(err, want) || result != nil {
		t.Fatalf("proof set returned partial data or wrong refusal: %v, %v; want %v", result, err, want)
	}
}

func TestCandidateSMTProofSetRecordedRoot(t *testing.T) {
	for _, names := range [][]string{
		{"stored-zero"},
		{"stored-zero", "positive-one"},
		{"stored-zero", "positive-one", "maximum-256-bit-magnitude"},
		{"positive-one", "257-bit-magnitude-only", "missing-token"},
		{"branch-bit-0", "branch-bit-3", "branch-boundary-absence"},
	} {
		t.Run(names[len(names)-1], func(t *testing.T) {
			root, inputs := candidateSMTSetInputs(t, names...)
			result, err := proof.ReadCandidateSMTProofSet(root, inputs, candidateSMTSetLimits())
			if err != nil || len(result) != len(inputs) {
				t.Fatal("original-node proof collection failed", err)
			}
			for i, input := range inputs {
				want, err := proof.ReadCandidateSMTProof(root, input.Path, input.Proof, input.Limits)
				if err != nil || !reflect.DeepEqual(result[i], want) {
					t.Fatal("set changed the existing single-proof contract", i, err)
				}
			}
		})
	}
}

func TestCandidateSMTProofSetRecordedSingleEquivalence(t *testing.T) {
	// Reuse all 41 pinned original-node encodings, including malformed,
	// noncanonical, absent and 33-byte values; do not regenerate their bytes.
	for _, c := range candidateSMTCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			root, path, raw := candidateSMTHash(t, c.Root), candidateSMTHash(t, c.Path), candidateSMTBytes(t, c.Proof)
			want, wantErr := proof.ReadCandidateSMTProof(root, path, raw, candidateSMTLimits())
			got, err := proof.ReadCandidateSMTProofSet(root, []proof.CandidateSMTProofInput{{Path: path, Proof: raw, Limits: candidateSMTLimits(), MaxSiblings: 256}}, candidateSMTSetLimits())
			if wantErr != nil {
				if !errors.Is(err, wantErr) || got != nil {
					t.Fatal("set changed a recorded refusal", err, wantErr)
				}
			} else if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], want) {
				t.Fatal("set changed a recorded successful read", err)
			}
		})
	}
}

func TestCandidateSMTProofSetLimits(t *testing.T) {
	root, inputs := candidateSMTSetInputs(t, "stored-zero", "positive-one", "maximum-256-bit-magnitude")
	maxInt := int(^uint(0) >> 1)
	for _, tc := range []struct {
		name string
		edit func(*proof.CandidateSMTSetLimits)
	}{
		{"zero_count", func(l *proof.CandidateSMTSetLimits) { l.MaxProofs = 0 }},
		{"negative_count", func(l *proof.CandidateSMTSetLimits) { l.MaxProofs = -1 }},
		{"count_above_ceiling", func(l *proof.CandidateSMTSetLimits) { l.MaxProofs = 4 }},
		{"count_overflow", func(l *proof.CandidateSMTSetLimits) { l.MaxProofs = maxInt }},
		{"zero_proof_bytes", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalProofBytes = 0 }},
		{"negative_proof_bytes", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalProofBytes = -1 }},
		{"small_proof_bytes", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalProofBytes = 98 }},
		{"proof_bytes_above_ceiling", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalProofBytes++ }},
		{"proof_bytes_overflow", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalProofBytes = maxInt }},
		{"zero_value_bytes", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalValueBytes = 0 }},
		{"negative_value_bytes", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalValueBytes = -1 }},
		{"value_bytes_above_ceiling", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalValueBytes++ }},
		{"value_bytes_overflow", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalValueBytes = maxInt }},
		{"negative_siblings", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalSiblings = -1 }},
		{"siblings_above_ceiling", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalSiblings++ }},
		{"siblings_overflow", func(l *proof.CandidateSMTSetLimits) { l.MaxTotalSiblings = maxInt }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := candidateSMTSetLimits()
			tc.edit(&limits)
			candidateSMTSetRefuse(t, root, inputs, limits, proof.ErrCandidateSMTBounds)
		})
	}
	for _, tc := range []struct {
		name string
		edit func(*proof.CandidateSMTProofInput)
	}{
		{"zero_individual_proof", func(v *proof.CandidateSMTProofInput) { v.Limits.MaxProofBytes = 0 }},
		{"large_individual_proof", func(v *proof.CandidateSMTProofInput) { v.Limits.MaxProofBytes++ }},
		{"zero_individual_value", func(v *proof.CandidateSMTProofInput) { v.Limits.MaxValueBytes = 0 }},
		{"large_individual_value", func(v *proof.CandidateSMTProofInput) { v.Limits.MaxValueBytes++ }},
		{"negative_individual_siblings", func(v *proof.CandidateSMTProofInput) { v.MaxSiblings = -1 }},
		{"large_individual_siblings", func(v *proof.CandidateSMTProofInput) { v.MaxSiblings = 257 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := append([]proof.CandidateSMTProofInput(nil), inputs...)
			tc.edit(&changed[2])
			candidateSMTSetRefuse(t, root, changed, candidateSMTSetLimits(), proof.ErrCandidateSMTBounds)
		})
	}
	for _, count := range []int{0, 4} {
		changed := append(append([]proof.CandidateSMTProofInput(nil), inputs...), inputs[0])[:count]
		candidateSMTSetRefuse(t, root, changed, candidateSMTSetLimits(), proof.ErrCandidateSMTBounds)
	}
}

func TestCandidateSMTProofSetExactBudgets(t *testing.T) {
	root, inputs := candidateSMTSetInputs(t, "stored-zero", "positive-one", "257-bit-magnitude-only")
	limits := proof.CandidateSMTSetLimits{MaxProofs: len(inputs)}
	for i := range inputs {
		v := &inputs[i]
		match, err := proof.ReadCandidateSMTProof(root, v.Path, v.Proof, v.Limits)
		if err != nil {
			t.Fatal(err)
		}
		v.Limits = proof.CandidateSMTLimits{MaxProofBytes: len(v.Proof), MaxValueBytes: len(match.Value)}
		v.MaxSiblings = int(match.SiblingCount)
		limits.MaxTotalProofBytes += len(v.Proof)
		limits.MaxTotalValueBytes += len(match.Value)
		limits.MaxTotalSiblings += int(match.SiblingCount)
	}
	if _, err := proof.ReadCandidateSMTProofSet(root, inputs, limits); err != nil {
		t.Fatal("exact aggregate and individual caps were refused", err)
	}
	for _, field := range []string{"proof", "value", "siblings"} {
		t.Run(field, func(t *testing.T) {
			changed := limits
			switch field {
			case "proof":
				changed.MaxTotalProofBytes--
			case "value":
				changed.MaxTotalValueBytes--
			case "siblings":
				changed.MaxTotalSiblings--
			}
			candidateSMTSetRefuse(t, root, inputs, changed, proof.ErrCandidateSMTBounds)
		})
		t.Run("individual_"+field, func(t *testing.T) {
			changed := append([]proof.CandidateSMTProofInput(nil), inputs...)
			switch field {
			case "proof":
				changed[2].Limits.MaxProofBytes--
			case "value":
				changed[2].Limits.MaxValueBytes--
			case "siblings":
				changed[2].MaxSiblings--
			}
			candidateSMTSetRefuse(t, root, changed, limits, proof.ErrCandidateSMTBounds)
		})
	}
	// No bytes are copied and no earlier invalid leaf is hashed when a later
	// row exceeds the aggregate value budget. Bound failure wins over its hash.
	inputs[0].Proof[33] ^= 1
	limits.MaxTotalValueBytes--
	candidateSMTSetRefuse(t, root, inputs, limits, proof.ErrCandidateSMTBounds)
}

func TestCandidateSMTProofSetAtomicRefusals(t *testing.T) {
	root, inputs := candidateSMTSetInputs(t, "stored-zero", "positive-one", "maximum-256-bit-magnitude")
	for i := range inputs {
		t.Run(string(rune('0'+i)), func(t *testing.T) {
			changed := append([]proof.CandidateSMTProofInput(nil), inputs...)
			changed[i].Proof = bytes.Clone(inputs[i].Proof)
			changed[i].Proof[33] ^= 1
			candidateSMTSetRefuse(t, root, changed, candidateSMTSetLimits(), proof.ErrCandidateSMTEncoding)
		})
	}
	t.Run("duplicate_path", func(t *testing.T) {
		changed := append([]proof.CandidateSMTProofInput(nil), inputs...)
		changed[2] = changed[0]
		candidateSMTSetRefuse(t, root, changed, candidateSMTSetLimits(), proof.ErrCandidateSMTDuplicatePath)
	})
	t.Run("wrong_selected_path", func(t *testing.T) {
		changed := append([]proof.CandidateSMTProofInput(nil), inputs...)
		changed[2].Path[0] ^= 1
		candidateSMTSetRefuse(t, root, changed, candidateSMTSetLimits(), proof.ErrCandidateSMTPath)
	})
	t.Run("mixed_roots", func(t *testing.T) {
		_, foreign := candidateSMTSetInputs(t, "branch-bit-0")
		changed := append([]proof.CandidateSMTProofInput(nil), inputs...)
		changed[2] = foreign[0]
		candidateSMTSetRefuse(t, root, changed, candidateSMTSetLimits(), proof.ErrCandidateSMTMismatch)
	})
	t.Run("every_late_truncation", func(t *testing.T) {
		changed := append([]proof.CandidateSMTProofInput(nil), inputs...)
		for end := 0; end < len(inputs[2].Proof); end++ {
			changed[2].Proof = inputs[2].Proof[:end]
			candidateSMTSetRefuse(t, root, changed, candidateSMTSetLimits(), proof.ErrCandidateSMTEncoding)
		}
	})
}

func TestCandidateSMTProofSetDetached(t *testing.T) {
	root, inputs := candidateSMTSetInputs(t, "stored-zero", "positive-one", "257-bit-magnitude-only")
	before := make([][]byte, len(inputs))
	for i := range inputs {
		before[i] = bytes.Clone(inputs[i].Proof)
	}
	result, err := proof.ReadCandidateSMTProofSet(root, inputs, candidateSMTSetLimits())
	if err != nil {
		t.Fatal(err)
	}
	for i := range inputs {
		result[i].Value[0] ^= 1
		if !bytes.Equal(inputs[i].Proof, before[i]) {
			t.Fatal("result aliases an input proof")
		}
		owned := bytes.Clone(result[i].Value)
		inputs[i].Proof[len(inputs[i].Proof)-1] ^= 1
		if !bytes.Equal(result[i].Value, owned) {
			t.Fatal("input mutation changed a detached result")
		}
	}
}

func TestCandidateSMTProofSetZeroSiblingBudget(t *testing.T) {
	var inputs []proof.CandidateSMTProofInput
	for _, n := range []byte{1, 2, 3} {
		var path chain.Hash
		path[31] = n
		raw := make([]byte, 99)
		copy(raw[1:33], path[:])
		inputs = append(inputs, proof.CandidateSMTProofInput{Path: path, Proof: raw,
			Limits: proof.CandidateSMTLimits{MaxProofBytes: 99, MaxValueBytes: 1}, MaxSiblings: 0})
	}
	limits := proof.CandidateSMTSetLimits{MaxProofs: 3, MaxTotalProofBytes: 3 * 99, MaxTotalValueBytes: 1, MaxTotalSiblings: 0}
	result, err := proof.ReadCandidateSMTProofSet(chain.Hash{}, inputs, limits)
	if err != nil || len(result) != 3 {
		t.Fatal("explicit zero-sibling policy refused empty-tree mathematics", err)
	}
	for _, match := range result {
		if match.Present || !match.Canonical || match.SiblingCount != 0 || len(match.Value) != 0 {
			t.Fatal("absence became present data")
		}
	}
	root, withSiblings := candidateSMTSetInputs(t, "stored-zero")
	candidateSMTSetRefuse(t, root, withSiblings, limits, proof.ErrCandidateSMTBounds)
}

func TestCandidateSMTProofSetNoFailureAllocations(t *testing.T) {
	root, inputs := candidateSMTSetInputs(t, "stored-zero", "positive-one", "maximum-256-bit-magnitude")
	_, foreign := candidateSMTSetInputs(t, "branch-bit-0")
	inputs[2] = foreign[0]
	limits := candidateSMTSetLimits()
	allocations := testing.AllocsPerRun(20, func() {
		got, err := proof.ReadCandidateSMTProofSet(root, inputs, limits)
		if err != proof.ErrCandidateSMTMismatch || got != nil {
			panic("late root mismatch did not fail atomically")
		}
	})
	if allocations != 0 {
		t.Fatalf("failed set allocated detached output: %g allocations", allocations)
	}
	limits.MaxTotalValueBytes = 1
	allocations = testing.AllocsPerRun(20, func() {
		got, err := proof.ReadCandidateSMTProofSet(root, inputs, limits)
		if err != proof.ErrCandidateSMTBounds || got != nil {
			panic("aggregate cap did not precede mathematical verification")
		}
	})
	if allocations != 0 {
		t.Fatalf("aggregate refusal allocated output: %g allocations", allocations)
	}
}

func FuzzCandidateSMTProofSet(f *testing.F) {
	root, selected := candidateSMTSetInputs(f, "stored-zero", "positive-one", "maximum-256-bit-magnitude")
	f.Add(selected[0].Proof, selected[1].Proof, selected[2].Proof)
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(selected[0].Proof, selected[1].Proof, selected[2].Proof[:99])
	f.Fuzz(func(t *testing.T, first, second, third []byte) {
		inputs := append([]proof.CandidateSMTProofInput(nil), selected...)
		for i, raw := range [][]byte{first, second, third} {
			inputs[i].Proof = raw
		}
		result, err := proof.ReadCandidateSMTProofSet(root, inputs, candidateSMTSetLimits())
		if err != nil {
			if result != nil {
				t.Fatal("fuzz refusal returned partial output")
			}
			return
		}
		if len(result) != 3 {
			t.Fatal("successful set lost a selected proof")
		}
		for i, input := range inputs {
			want, err := proof.ReadCandidateSMTProof(root, input.Path, input.Proof, input.Limits)
			if err != nil || !reflect.DeepEqual(result[i], want) {
				t.Fatal("fuzz set differs from single-proof verification", err)
			}
			if int(result[i].SiblingCount) != int(binary.BigEndian.Uint16(input.Proof[97:99])) {
				t.Fatal("successful set lost encoded work accounting")
			}
		}
	})
}

func BenchmarkCandidateSMTProofSet(b *testing.B) {
	root, inputs := candidateSMTSetInputs(b, "stored-zero", "positive-one", "maximum-256-bit-magnitude")
	_, foreign := candidateSMTSetInputs(b, "branch-bit-0")
	for _, name := range []string{"success", "late_root_mismatch", "aggregate_refusal"} {
		b.Run(name, func(b *testing.B) {
			selected := append([]proof.CandidateSMTProofInput(nil), inputs...)
			limits := candidateSMTSetLimits()
			want := error(nil)
			if name == "late_root_mismatch" {
				selected[2], want = foreign[0], proof.ErrCandidateSMTMismatch
			} else if name == "aggregate_refusal" {
				limits.MaxTotalValueBytes, want = 1, proof.ErrCandidateSMTBounds
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, err := proof.ReadCandidateSMTProofSet(root, selected, limits)
				if err != want || (err != nil && got != nil) || (err == nil && len(got) != 3) {
					b.Fatal("unexpected benchmark result", err)
				}
			}
		})
	}
}
