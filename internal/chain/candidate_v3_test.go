// SPDX-License-Identifier: MIT

package chain_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

type candidateV3Reference struct {
	Name   string `json:"name"`
	Fields struct {
		Version         uint64 `json:"version"`
		ChainIdentifier uint64 `json:"chain_identifier"`
		PreviousHash    string `json:"previous_hash"`
		Height          uint64 `json:"height"`
		Timestamp       uint64 `json:"timestamp"`
		ChangesHash     string `json:"changes_hash"`
		NextFusionPrice uint64 `json:"next_fusion_price"`
		NextWorkPrice   uint64 `json:"next_work_price"`
		StateRoot       string `json:"state_root"`
	} `json:"fields"`
	DataHash    string `json:"data_hash"`
	ContentHash string `json:"content_hash"`
	Preimage    string `json:"preimage"`
	Hash        string `json:"hash"`
}

func candidateV3References(t *testing.T) []candidateV3Reference {
	t.Helper()
	path := filepath.Join("..", "..", "tools", "gen-state-root-vectors", "testdata", "candidate-v3-balances.json")
	f, err := os.Open(path)
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
		t.Fatal("recorded node fixture changed")
	}
	var recorded struct {
		Kind   string                    `json:"kind"`
		Source struct{ Revision string } `json:"source"`
		Scope  struct {
			Synthetic                   bool `json:"synthetic"`
			Unsigned                    bool `json:"unsigned"`
			ProfileAgreed               bool `json:"profile_agreed"`
			RuntimeStateProofAcceptance bool `json:"runtime_state_proof_acceptance"`
		} `json:"scope"`
		Headers []candidateV3Reference `json:"headers"`
	}
	if err := json.Unmarshal(raw, &recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Kind != "candidate-state-root-byte-research" ||
		recorded.Source.Revision != "56ce2c384966f2f1940967257a0788d3998a5eef" ||
		!recorded.Scope.Synthetic || !recorded.Scope.Unsigned ||
		recorded.Scope.ProfileAgreed || recorded.Scope.RuntimeStateProofAcceptance || len(recorded.Headers) != 10 {
		t.Fatal("original execution and research scope must remain explicit")
	}
	return recorded.Headers
}

func candidateV3Hash(t *testing.T, text string) chain.Hash {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != chain.HashSize {
		t.Fatal("bad recorded hash")
	}
	var result chain.Hash
	copy(result[:], raw)
	return result
}

func candidateV3FromReference(t *testing.T, v candidateV3Reference) chain.CandidateV3Header {
	t.Helper()
	return chain.CandidateV3Header{Header: chain.Header{
		Version: v.Fields.Version, ChainIdentifier: v.Fields.ChainIdentifier,
		HeaderHash: candidateV3Hash(t, v.Hash), PreviousHash: candidateV3Hash(t, v.Fields.PreviousHash),
		Height: v.Fields.Height, TimestampUnix: v.Fields.Timestamp,
		DataHash: candidateV3Hash(t, v.DataHash), ContentHash: candidateV3Hash(t, v.ContentHash),
		ChangesHash:     candidateV3Hash(t, v.Fields.ChangesHash),
		NextFusionPrice: v.Fields.NextFusionPrice, NextWorkPrice: v.Fields.NextWorkPrice,
	}, StateRoot: candidateV3Hash(t, v.Fields.StateRoot)}
}

func candidateV3WireValue(t *testing.T) chain.CandidateV3Header {
	t.Helper()
	for _, v := range candidateV3References(t) {
		if v.Name == "v3-balance-root" {
			result := candidateV3FromReference(t, v)
			// Dummy width-correct bytes exercise encoding, without signing or
			// authenticating the unsigned recorded candidate.
			result.Header.PublicKey = bytes.Repeat([]byte{0x17}, 32)
			result.Header.Signature = bytes.Repeat([]byte{0x29}, 64)
			return result
		}
	}
	t.Fatal("missing selected header")
	return chain.CandidateV3Header{}
}

var candidateV3WireFields = []string{
	"version", "chainIdentifier", "hash", "previousHash", "height", "timestamp",
	"dataHash", "contentHash", "changesHash", "publicKey", "signature",
	"nextFusionPrice", "nextWorkPrice", "stateRoot",
}

func candidateV3JSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func candidateV3Wire(t *testing.T) ([]byte, map[string]json.RawMessage) {
	t.Helper()
	raw := candidateV3JSON(t, candidateV3WireValue(t))
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != len(candidateV3WireFields) {
		t.Fatal("projected wire field set changed")
	}
	for _, name := range candidateV3WireFields {
		if _, ok := fields[name]; !ok {
			t.Fatalf("missing projected field %s", name)
		}
	}
	return raw, fields
}

func copyCandidateV3Fields(fields map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(fields))
	for key, value := range fields {
		result[key] = bytes.Clone(value)
	}
	return result
}

func requireCandidateV3Refusal(t *testing.T, raw []byte, reason string) {
	t.Helper()
	current := chain.CandidateV3Header{Header: chain.Header{
		Version: 77, ChainIdentifier: 99, HeaderHash: chain.Hash{1}, Height: 123,
		PublicKey: []byte{1, 2, 3}, Signature: []byte{4, 5, 6},
	}, StateRoot: chain.Hash{9}}
	before := current
	before.Header.PublicKey = bytes.Clone(current.Header.PublicKey)
	before.Header.Signature = bytes.Clone(current.Header.Signature)
	err := current.UnmarshalJSON(raw)
	if !errors.Is(err, chain.ErrCandidateV3Header) {
		t.Fatalf("expected candidate encoding refusal, got %v", err)
	}
	if reason != "" && !strings.Contains(err.Error(), reason) {
		t.Fatalf("expected %q diagnostic, got %v", reason, err)
	}
	if !reflect.DeepEqual(current, before) {
		t.Fatal("failed decoding changed the previous candidate")
	}
	value, err := chain.DecodeCandidateV3Header(raw)
	if !errors.Is(err, chain.ErrCandidateV3Header) || !reflect.DeepEqual(value, chain.CandidateV3Header{}) {
		t.Fatal("bounded document decoder published invalid or partial data", err)
	}
}

func TestCandidateV3HeaderRecordedNodeBytes(t *testing.T) {
	v3 := 0
	for _, v := range candidateV3References(t) {
		t.Run(v.Name, func(t *testing.T) {
			candidate := candidateV3FromReference(t, v)
			if v.Fields.Version != 3 {
				if _, err := candidate.Preimage(); !errors.Is(err, chain.ErrCandidateV3Header) {
					t.Fatal("candidate primitive accepted another layout")
				}
				if got := candidate.Header.ComputeHash(); got != candidateV3Hash(t, v.Hash) {
					t.Fatal("existing v1/v2 hash no longer matches recorded node bytes")
				}
				return
			}
			v3++
			want, err := hex.DecodeString(v.Preimage)
			if err != nil || len(want) != 208 {
				t.Fatal("bad recorded preimage")
			}
			got, err := candidate.Preimage()
			if err != nil || !bytes.Equal(got[:], want) {
				t.Fatalf("complete node preimage mismatch: %v", err)
			}
			hash, err := candidate.ComputeHash()
			if err != nil || hash != candidateV3Hash(t, v.Hash) {
				t.Fatalf("recorded node hash mismatch: %v", err)
			}
		})
	}
	if v3 != 6 {
		t.Fatal("all six recorded v3 encodings must execute")
	}
}

func TestCandidateV3HeaderVersionBoundary(t *testing.T) {
	value := candidateV3WireValue(t)
	for _, version := range []uint64{0, 1, 2, 4, math.MaxUint64} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			value.Header.Version = version
			preimage, err := value.Preimage()
			if !errors.Is(err, chain.ErrCandidateV3Header) || preimage != [208]byte{} {
				t.Fatal("unsupported candidate version did not fail without partial bytes")
			}
		})
	}
	if err := chain.ValidateHeaderVersion(chain.CandidateMomentumVersion3); !errors.Is(err, chain.ErrUnsupportedHeaderVersion) {
		t.Fatal("candidate encoding must not enable the native version gate")
	}
}

func TestCandidateV3HeaderProjectedWire(t *testing.T) {
	raw, _ := candidateV3Wire(t)
	var decoded chain.CandidateV3Header
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, candidateV3WireValue(t)) {
		t.Fatal("projected header fields did not round trip")
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if !reflect.DeepEqual(decoded, candidateV3WireValue(t)) {
		t.Fatal("decoded bytes alias the input buffer")
	}
}

func TestCandidateV3HeaderRequiredFields(t *testing.T) {
	raw, fields := candidateV3Wire(t)
	for _, name := range candidateV3WireFields {
		t.Run("missing/"+name, func(t *testing.T) {
			next := copyCandidateV3Fields(fields)
			delete(next, name)
			requireCandidateV3Refusal(t, candidateV3JSON(t, next), "missing required field")
		})
		t.Run("null/"+name, func(t *testing.T) {
			next := copyCandidateV3Fields(fields)
			next[name] = json.RawMessage("null")
			requireCandidateV3Refusal(t, candidateV3JSON(t, next), name+" must be non-null")
		})
		t.Run("duplicate/"+name, func(t *testing.T) {
			duplicate := append(bytes.Clone(raw[:len(raw)-1]), []byte(",\""+name+"\":"+string(fields[name])+"}")...)
			requireCandidateV3Refusal(t, duplicate, "duplicate field")
		})
	}
}

func TestCandidateV3HeaderMalformedWire(t *testing.T) {
	raw, fields := candidateV3Wire(t)
	cases := map[string][]byte{
		"null": []byte("null"), "array": []byte("[]"), "scalar": []byte("3"),
		"empty": []byte("{}"), "truncated": raw[:len(raw)-1],
		"trailing":          append(bytes.Clone(raw), []byte("{}")...),
		"escaped-duplicate": append(bytes.Clone(raw[:len(raw)-1]), []byte(",\"\\u0076ersion\":3}")...),
	}
	for name, rawValue := range map[string]json.RawMessage{
		"hash":            json.RawMessage("\"" + strings.Repeat("0", 64) + "\""),
		"stateRoot":       json.RawMessage("\"" + strings.Repeat("f", 64) + "\""),
		"nextFusionPrice": json.RawMessage("9999"),
	} {
		next := copyCandidateV3Fields(fields)
		next[name] = rawValue
		cases["inconsistent-"+name] = candidateV3JSON(t, next)
	}
	for _, version := range []uint64{0, 1, 2, 4, math.MaxUint64} {
		next := copyCandidateV3Fields(fields)
		next["version"] = candidateV3JSON(t, version)
		cases[fmt.Sprintf("version-%d", version)] = candidateV3JSON(t, next)
	}
	next := copyCandidateV3Fields(fields)
	next["PRIVATE_TEST_FIELD"] = json.RawMessage("\"PRIVATE_TEST_VALUE\"")
	cases["unknown"] = candidateV3JSON(t, next)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			requireCandidateV3Refusal(t, raw, "")
			_, err := chain.DecodeCandidateV3Header(raw)
			if strings.Contains(err.Error(), "PRIVATE_TEST") {
				t.Fatal("input names or values leaked into the diagnostic")
			}
		})
	}
}

func TestCandidateV3HeaderFieldRepresentations(t *testing.T) {
	_, fields := candidateV3Wire(t)
	for _, name := range []string{"hash", "previousHash", "dataHash", "contentHash", "changesHash", "stateRoot"} {
		for kind, raw := range map[string]json.RawMessage{
			"short":   json.RawMessage("\"" + strings.Repeat("0", 62) + "\""),
			"long":    json.RawMessage("\"" + strings.Repeat("0", 66) + "\""),
			"prefix":  json.RawMessage("\"0x" + strings.Repeat("0", 64) + "\""),
			"invalid": json.RawMessage("\"g" + strings.Repeat("0", 63) + "\""),
			"array":   json.RawMessage("[0]"),
		} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				next := copyCandidateV3Fields(fields)
				next[name] = raw
				requireCandidateV3Refusal(t, candidateV3JSON(t, next), "invalid "+name)
			})
		}
	}
	for _, name := range []string{"chainIdentifier", "height", "timestamp", "nextFusionPrice", "nextWorkPrice"} {
		for _, raw := range []string{"-1", "1.5", "1e0", "18446744073709551616", "\"1\""} {
			t.Run(name+"/"+raw, func(t *testing.T) {
				next := copyCandidateV3Fields(fields)
				next[name] = json.RawMessage(raw)
				requireCandidateV3Refusal(t, candidateV3JSON(t, next), "invalid "+name)
			})
		}
	}
	for _, name := range []string{"publicKey", "signature"} {
		for kind, raw := range map[string]json.RawMessage{
			"array": json.RawMessage("[0]"), "short": json.RawMessage("\"AA==\""),
			"invalid": json.RawMessage("\"!\""), "empty": json.RawMessage("\"\""),
		} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				next := copyCandidateV3Fields(fields)
				next[name] = raw
				requireCandidateV3Refusal(t, candidateV3JSON(t, next), "invalid "+name)
			})
		}
	}
}

func TestCandidateV3HeaderEncodedBytesAndBounds(t *testing.T) {
	raw, fields := candidateV3Wire(t)
	atLimit := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), chain.MaxCandidateV3HeaderJSONBytes-len(raw))...)
	if _, err := chain.DecodeCandidateV3Header(atLimit); err != nil {
		t.Fatal("exact local JSON byte limit must remain usable:", err)
	}
	// Invoke the bounded decoder directly: encoding/json itself strips trailing
	// whitespace before calling UnmarshalJSON.
	requireCandidateV3Refusal(t, append(atLimit, ' '), "")
	var direct chain.CandidateV3Header
	if err := direct.UnmarshalJSON(append(atLimit, ' ')); !errors.Is(err, chain.ErrCandidateV3Header) {
		t.Fatal("raw candidate byte limit was not enforced")
	}
	for _, name := range []string{"publicKey", "signature"} {
		next := copyCandidateV3Fields(fields)
		var text string
		if err := json.Unmarshal(next[name], &text); err != nil {
			t.Fatal(err)
		}
		index := len(text) - 2
		if name == "signature" {
			index = len(text) - 3
		}
		alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		digit := strings.IndexByte(alphabet, text[index])
		bad := []byte(text)
		bad[index] = alphabet[digit|1]
		next[name] = candidateV3JSON(t, string(bad))
		if _, err := base64.StdEncoding.DecodeString(string(bad)); err != nil {
			t.Fatal("padding-bit control must remain decodable by the non-strict codec")
		}
		requireCandidateV3Refusal(t, candidateV3JSON(t, next), "invalid "+name)
	}
}

func TestCandidateV3HeaderMarshalBoundary(t *testing.T) {
	base := candidateV3WireValue(t)
	for name, mutate := range map[string]func(*chain.CandidateV3Header){
		"version":         func(v *chain.CandidateV3Header) { v.Header.Version = 4 },
		"hash":            func(v *chain.CandidateV3Header) { v.Header.HeaderHash[0] ^= 1 },
		"root":            func(v *chain.CandidateV3Header) { v.StateRoot[0] ^= 1 },
		"key-width":       func(v *chain.CandidateV3Header) { v.Header.PublicKey = nil },
		"signature-width": func(v *chain.CandidateV3Header) { v.Header.Signature = nil },
	} {
		t.Run(name, func(t *testing.T) {
			next := base
			mutate(&next)
			if _, err := json.Marshal(next); !errors.Is(err, chain.ErrCandidateV3Header) {
				t.Fatal("inconsistent projected header was emitted", err)
			}
		})
	}
}
