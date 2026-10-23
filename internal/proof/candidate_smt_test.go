// SPDX-License-Identifier: MIT

package proof_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

type candidateSMTCase struct {
	Name       string `json:"name"`
	Domain     string `json:"domain"`
	Address    string `json:"address"`
	Token      string `json:"token"`
	RawKey     string `json:"raw_key"`
	Path       string `json:"path"`
	Value      string `json:"value"`
	Present    bool   `json:"present"`
	Proof      string `json:"proof"`
	Root       string `json:"root"`
	NodeResult string `json:"node_result"`
}

func candidateSMTCases(t testing.TB) []candidateSMTCase {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "tools", "gen-state-root-vectors", "testdata", "candidate-v3-balances.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close recorded node fixture: %v", err)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(f, 152438))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != 152437 || hex.EncodeToString(sum[:]) != "8b69cdaf78ae4eeaad79cdfa493ed9633a1202e09819178da83e17be385f00d3" {
		t.Fatal("original node byte corpus changed")
	}
	var corpus struct {
		Kind   string                          `json:"kind"`
		Source struct{ Revision, Tree string } `json:"source"`
		Scope  struct {
			Synthetic                   bool `json:"synthetic"`
			Unsigned                    bool `json:"unsigned"`
			CandidatePrimitiveExecution bool `json:"candidate_primitive_execution"`
			ProfileAgreed               bool `json:"profile_agreed"`
			RuntimeStateProofAcceptance bool `json:"runtime_state_proof_acceptance"`
		} `json:"scope"`
		Proofs []candidateSMTCase `json:"proofs"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Kind != "candidate-state-root-byte-research" ||
		corpus.Source.Revision != "56ce2c384966f2f1940967257a0788d3998a5eef" ||
		corpus.Source.Tree != "d5abff528566a561e1a53a46103cb4b15ff63c6c" ||
		!corpus.Scope.Synthetic || !corpus.Scope.Unsigned || !corpus.Scope.CandidatePrimitiveExecution ||
		corpus.Scope.ProfileAgreed || corpus.Scope.RuntimeStateProofAcceptance || len(corpus.Proofs) != 41 {
		t.Fatal("recorded node revision or research scope changed")
	}
	return corpus.Proofs
}

func candidateSMTSelect(t testing.TB, cases []candidateSMTCase, name string) candidateSMTCase {
	t.Helper()
	for _, c := range cases {
		if c.Name == name {
			return c
		}
	}
	t.Fatal("missing preselected recorded case")
	return candidateSMTCase{}
}

func candidateSMTBytes(t testing.TB, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func candidateSMTHash(t testing.TB, text string) chain.Hash {
	t.Helper()
	raw := candidateSMTBytes(t, text)
	if len(raw) != chain.HashSize {
		t.Fatal("recorded hash width changed")
	}
	return chain.Hash(raw)
}

func candidateSMTLimits() proof.CandidateSMTLimits {
	return proof.CandidateSMTLimits{MaxProofBytes: proof.CandidateSMTMaxProofBytes, MaxValueBytes: proof.CandidateSMTMaxValueBytes}
}

func candidateSMTCheck(t testing.TB, c candidateSMTCase, limits proof.CandidateSMTLimits) (proof.CandidateSMTMatch, error) {
	t.Helper()
	root, path := candidateSMTHash(t, c.Root), candidateSMTHash(t, c.Path)
	raw := candidateSMTBytes(t, c.Proof)
	if c.Present {
		return proof.CheckCandidateSMTInclusion(root, path, candidateSMTBytes(t, c.Value), raw, limits)
	}
	return proof.CheckCandidateSMTAbsence(root, path, raw, limits)
}

func candidateSMTClaim(t testing.TB, c candidateSMTCase) proof.CandidateBalanceClaim {
	t.Helper()
	address, token := candidateSMTBytes(t, c.Address), candidateSMTBytes(t, c.Token)
	if len(address) != chain.AddressSize || len(token) != chain.TokenStandardSize {
		t.Fatal("recorded typed key width changed")
	}
	return proof.CandidateBalanceClaim{Root: candidateSMTHash(t, c.Root), Address: chain.Address(address),
		Token: chain.TokenStandard(token), Present: c.Present, Value: candidateSMTBytes(t, c.Value)}
}

func requireCandidateSMTError(t testing.TB, result proof.CandidateSMTMatch, err, want error) {
	t.Helper()
	if !errors.Is(err, want) || !reflect.DeepEqual(result, proof.CandidateSMTMatch{}) {
		t.Fatalf("expected zero result and %v, got %+v, %v", want, result, err)
	}
}

func TestCandidateSMTRecordedNodeCases(t *testing.T) {
	for _, c := range candidateSMTCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			result, err := candidateSMTCheck(t, c, candidateSMTLimits())
			want := map[string]error{"malformed": proof.ErrCandidateSMTEncoding,
				"path_mismatch": proof.ErrCandidateSMTPath, "mismatch": proof.ErrCandidateSMTMismatch}
			if c.NodeResult != "match" {
				if want[c.NodeResult] == nil {
					t.Fatal("unselected recorded node result")
				}
				requireCandidateSMTError(t, result, err, want[c.NodeResult])
				return
			}
			canonical := c.Name != "stored-zero-sibling-equivalent" && c.Name != "absent-stored-zero-sibling-equivalent"
			if err != nil || result.Present != c.Present || result.Canonical != canonical ||
				!bytes.Equal(result.Value, candidateSMTBytes(t, c.Value)) {
				t.Fatalf("recorded match differs: %+v, %v", result, err)
			}
			raw := candidateSMTBytes(t, c.Proof)
			if result.SiblingCount != binary.BigEndian.Uint16(raw[97:99]) {
				t.Fatal("sibling observation differs from selected bytes")
			}
		})
	}
}

func TestCandidateSMTTypedBalanceKeys(t *testing.T) {
	cases := candidateSMTCases(t)
	for _, c := range cases {
		if c.Domain != "balance" {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			claim := candidateSMTClaim(t, c)
			key := proof.CandidateBalanceKey(claim.Address, claim.Token)
			if !bytes.Equal(key[:], candidateSMTBytes(t, c.RawKey)) || chain.Hash(sha3.Sum256(key[:])) != candidateSMTHash(t, c.Path) {
				t.Fatal("locally derived address/token key differs from node bytes")
			}
			result, err := proof.CheckCandidateBalanceProof(claim, candidateSMTBytes(t, c.Proof), candidateSMTLimits())
			if err != nil || result.Present != c.Present || !bytes.Equal(result.Value, claim.Value) {
				t.Fatalf("typed byte comparison failed: %+v, %v", result, err)
			}
		})
	}
	for _, c := range cases {
		if c.Domain != "excluded" {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			claim := candidateSMTClaim(t, candidateSMTSelect(t, cases, "stored-zero"))
			claim.Root, claim.Present, claim.Value = candidateSMTHash(t, c.Root), false, nil
			result, err := proof.CheckCandidateBalanceProof(claim, candidateSMTBytes(t, c.Proof), candidateSMTLimits())
			requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTPath)
		})
	}
}

func TestCandidateSMTClaimBindings(t *testing.T) {
	c := candidateSMTSelect(t, candidateSMTCases(t), "positive-one")
	base := candidateSMTClaim(t, c)
	for _, tc := range []struct {
		name   string
		change func(*proof.CandidateBalanceClaim)
		want   error
	}{
		{"root", func(c *proof.CandidateBalanceClaim) { c.Root[31] ^= 1 }, proof.ErrCandidateSMTMismatch},
		{"address", func(c *proof.CandidateBalanceClaim) { c.Address[0] ^= 1 }, proof.ErrCandidateSMTPath},
		{"token", func(c *proof.CandidateBalanceClaim) { c.Token[9] ^= 1 }, proof.ErrCandidateSMTPath},
		{"value", func(c *proof.CandidateBalanceClaim) { c.Value[0] ^= 1 }, proof.ErrCandidateSMTMismatch},
		{"presence", func(c *proof.CandidateBalanceClaim) { c.Present, c.Value = false, nil }, proof.ErrCandidateSMTEncoding},
		{"absent_nonempty_claim", func(c *proof.CandidateBalanceClaim) { c.Present = false }, proof.ErrCandidateSMTEncoding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claim := base
			claim.Value = bytes.Clone(base.Value)
			tc.change(&claim)
			result, err := proof.CheckCandidateBalanceProof(claim, candidateSMTBytes(t, c.Proof), candidateSMTLimits())
			requireCandidateSMTError(t, result, err, tc.want)
		})
	}
}

func TestCandidateSMTResourceLimits(t *testing.T) {
	cases := candidateSMTCases(t)
	maxInt := int(^uint(0) >> 1)
	for _, tc := range []struct {
		name, record string
		proof, value int
		want         error
	}{
		{"zero_proof_cap", "positive-one", 0, 4096, proof.ErrCandidateSMTBounds},
		{"negative_proof_cap", "positive-one", -1, 4096, proof.ErrCandidateSMTBounds},
		{"below_minimum_proof_cap", "positive-one", 98, 4096, proof.ErrCandidateSMTBounds},
		{"above_local_proof_ceiling", "positive-one", 12392, 4096, proof.ErrCandidateSMTBounds},
		{"integer_maximum_proof_cap", "positive-one", maxInt, 4096, proof.ErrCandidateSMTBounds},
		{"zero_value_cap", "positive-one", 12391, 0, proof.ErrCandidateSMTBounds},
		{"negative_value_cap", "positive-one", 12391, -1, proof.ErrCandidateSMTBounds},
		{"above_local_value_ceiling", "positive-one", 12391, 4097, proof.ErrCandidateSMTBounds},
		{"integer_maximum_value_cap", "positive-one", 12391, maxInt, proof.ErrCandidateSMTBounds},
		{"exact_present_proof", "full-bitmap-present-8327-bytes", 8327, 32, nil},
		{"below_present_proof", "full-bitmap-present-8327-bytes", 8326, 32, proof.ErrCandidateSMTBounds},
		{"exact_absent_proof", "full-bitmap-absent-8291-bytes", 8291, 32, nil},
		{"below_absent_proof", "full-bitmap-absent-8291-bytes", 8290, 32, proof.ErrCandidateSMTBounds},
		{"exact_value", "positive-one", 12391, 32, nil},
		{"below_value", "positive-one", 12391, 31, proof.ErrCandidateSMTBounds},
		{"recorded_33_byte_magnitude", "257-bit-magnitude-only", 12391, 33, nil},
		{"no_33_byte_truncation", "257-bit-magnitude-only", 12391, 32, proof.ErrCandidateSMTBounds},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := candidateSMTCheck(t, candidateSMTSelect(t, cases, tc.record), proof.CandidateSMTLimits{MaxProofBytes: tc.proof, MaxValueBytes: tc.value})
			if tc.want != nil {
				requireCandidateSMTError(t, result, err, tc.want)
			} else if err != nil || !result.Canonical {
				t.Fatalf("exact selected boundary failed: %+v, %v", result, err)
			}
		})
	}
}

func TestCandidateSMTEncodingRefusals(t *testing.T) {
	cases := candidateSMTCases(t)
	c := candidateSMTSelect(t, cases, "positive-one")
	root, path, value := candidateSMTHash(t, c.Root), candidateSMTHash(t, c.Path), candidateSMTBytes(t, c.Value)
	raw := candidateSMTBytes(t, c.Proof)
	t.Run("every_full_bitmap_prefix", func(t *testing.T) {
		full := candidateSMTSelect(t, cases, "full-bitmap-present-8327-bytes")
		encoded := candidateSMTBytes(t, full.Proof)
		fullRoot, fullPath, fullValue := candidateSMTHash(t, full.Root), candidateSMTHash(t, full.Path), candidateSMTBytes(t, full.Value)
		for end := 0; end < len(encoded); end++ {
			result, err := proof.CheckCandidateSMTInclusion(fullRoot, fullPath, fullValue, encoded[:end], candidateSMTLimits())
			requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTEncoding)
		}
	})
	t.Run("every_reserved_flag", func(t *testing.T) {
		for flag := 2; flag <= 255; flag++ {
			changed := bytes.Clone(raw)
			changed[0] = byte(flag)
			result, err := proof.CheckCandidateSMTInclusion(root, path, value, changed, candidateSMTLimits())
			requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTEncoding)
		}
	})
	t.Run("sibling_count_above_depth", func(t *testing.T) {
		changed := bytes.Clone(raw)
		binary.BigEndian.PutUint16(changed[97:99], 257)
		result, err := proof.CheckCandidateSMTInclusion(root, path, value, changed, candidateSMTLimits())
		requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTEncoding)
	})
	t.Run("uint32_length_without_bytes", func(t *testing.T) {
		changed := bytes.Clone(raw)
		offset := len(raw) - len(value) - 4
		binary.BigEndian.PutUint32(changed[offset:offset+4], ^uint32(0))
		result, err := proof.CheckCandidateSMTInclusion(root, path, value, changed, candidateSMTLimits())
		requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTEncoding)
	})
	t.Run("raw_above_local_ceiling", func(t *testing.T) {
		result, err := proof.CheckCandidateSMTInclusion(root, path, value, make([]byte, proof.CandidateSMTMaxProofBytes+1), candidateSMTLimits())
		requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTBounds)
	})
	t.Run("claim_above_local_ceiling", func(t *testing.T) {
		result, err := proof.CheckCandidateSMTInclusion(root, path, make([]byte, proof.CandidateSMTMaxValueBytes+1), raw, candidateSMTLimits())
		requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTBounds)
	})
}

func TestCandidateSMTDetachedValues(t *testing.T) {
	cases := candidateSMTCases(t)
	for _, name := range []string{"stored-zero", "positive-one", "257-bit-magnitude-only", "present-empty-core-only", "missing-token"} {
		t.Run(name, func(t *testing.T) {
			c := candidateSMTSelect(t, cases, name)
			root, path := candidateSMTHash(t, c.Root), candidateSMTHash(t, c.Path)
			raw, value := candidateSMTBytes(t, c.Proof), candidateSMTBytes(t, c.Value)
			rawBefore, valueBefore := bytes.Clone(raw), bytes.Clone(value)
			var result proof.CandidateSMTMatch
			var err error
			if c.Present {
				result, err = proof.CheckCandidateSMTInclusion(root, path, value, raw, candidateSMTLimits())
			} else {
				result, err = proof.CheckCandidateSMTAbsence(root, path, raw, candidateSMTLimits())
			}
			if err != nil || result.Present != c.Present {
				t.Fatal("selected ownership control failed", err)
			}
			if len(result.Value) > 0 {
				result.Value[0] ^= 1
				if !bytes.Equal(raw, rawBefore) || !bytes.Equal(value, valueBefore) {
					t.Fatal("returned value aliases an input")
				}
				owned := bytes.Clone(result.Value)
				raw[len(raw)-1] ^= 1
				value[len(value)-1] ^= 1
				if !bytes.Equal(result.Value, owned) {
					t.Fatal("input mutation changed returned value")
				}
			}
			raw[0] |= 2
			result, err = proof.CheckCandidateSMTInclusion(root, path, value, raw, candidateSMTLimits())
			requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTEncoding)
		})
	}
}

func candidateSMTLimitFixture(t testing.TB) (chain.Hash, chain.Hash, []byte, []byte) {
	t.Helper()
	path := candidateSMTHash(t, "e7b3a809364f27467d975732628c09aa7f323dc8fb199dac79405446b558e993")
	root := candidateSMTHash(t, "473e76a771a89ed1beaa4f4a96bb28ed5b92286319f52141f6eae5bacbdeec30")
	leaf := candidateSMTHash(t, "16b37531973e8c166002eee76ca1ad194610f69e6937052b74c44398959cdd5c")
	value := make([]byte, 4096)
	for i := range value {
		value[i] = byte(i % 251)
	}
	raw := []byte{1}
	raw = append(raw, path[:]...)
	raw = append(raw, leaf[:]...)
	raw = append(raw, bytes.Repeat([]byte{255}, 32)...)
	raw = append(raw, 1, 0)
	for i := 0; i < 256; i++ {
		input := append([]byte("native SMT sibling"), byte(i>>8), byte(i))
		sibling := sha3.Sum256(input)
		raw = append(raw, sibling[:]...)
	}
	raw = append(raw, 0, 0, 16, 0)
	raw = append(raw, value...)
	sum := sha256.Sum256(raw)
	if len(raw) != 12391 || hex.EncodeToString(sum[:]) != "fa8829e200f0e9d23fdf00055d1653cd6dce1ef2804f30cd83edcc6963fe2b15" {
		t.Fatal("independent hashlib local-ceiling fixture changed")
	}
	return root, path, value, raw
}

func TestCandidateSMTIndependentLocalCeiling(t *testing.T) {
	root, path, value, raw := candidateSMTLimitFixture(t)
	for _, tc := range []struct {
		name   string
		limits proof.CandidateSMTLimits
		want   error
	}{
		{"exact_12391_bytes_4096_value_256_siblings", candidateSMTLimits(), nil},
		{"one_less_proof_byte", proof.CandidateSMTLimits{MaxProofBytes: 12390, MaxValueBytes: 4096}, proof.ErrCandidateSMTBounds},
		{"one_less_value_byte", proof.CandidateSMTLimits{MaxProofBytes: 12391, MaxValueBytes: 4095}, proof.ErrCandidateSMTBounds},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := proof.CheckCandidateSMTInclusion(root, path, value, raw, tc.limits)
			if tc.want != nil {
				requireCandidateSMTError(t, result, err, tc.want)
			} else if err != nil || !result.Present || !result.Canonical || result.SiblingCount != 256 || !bytes.Equal(result.Value, value) {
				t.Fatalf("independent local-ceiling comparison failed: %+v, %v", result, err)
			}
		})
	}
}

var candidateSMTBenchmarkSink proof.CandidateSMTMatch

func BenchmarkCandidateSMT(b *testing.B) {
	cases := candidateSMTCases(b)
	for _, name := range []string{"positive-one", "missing-token", "full-bitmap-present-8327-bytes"} {
		c := candidateSMTSelect(b, cases, name)
		root, path := candidateSMTHash(b, c.Root), candidateSMTHash(b, c.Path)
		value, raw := candidateSMTBytes(b, c.Value), candidateSMTBytes(b, c.Proof)
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var result proof.CandidateSMTMatch
				var err error
				if c.Present {
					result, err = proof.CheckCandidateSMTInclusion(root, path, value, raw, candidateSMTLimits())
				} else {
					result, err = proof.CheckCandidateSMTAbsence(root, path, raw, candidateSMTLimits())
				}
				if err != nil {
					b.Fatal(err)
				}
				candidateSMTBenchmarkSink = result
			}
		})
	}
}
