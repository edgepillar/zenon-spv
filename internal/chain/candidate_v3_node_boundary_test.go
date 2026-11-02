// SPDX-License-Identifier: MIT

package chain_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

type nodeBoundaryRow struct {
	Header                json.RawMessage `json:"header"`
	Height                uint64          `json:"height"`
	Version               uint64          `json:"version"`
	Hash                  chain.Hash      `json:"hash"`
	PreviousHash          chain.Hash      `json:"previous_hash"`
	StateRoot             chain.Hash      `json:"state_root"`
	ParentDynamicActive   bool            `json:"parent_dynamic_active"`
	ParentStateRootActive bool            `json:"parent_state_root_active"`
	ParentTreeReady       bool            `json:"parent_tree_ready"`
	TreeRootMatched       bool            `json:"tree_root_matched"`
}

func nodeBoundaryBytes(t *testing.T, path string, size int64, digest string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close recorded node input: %v", err)
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		t.Fatal("recorded node input type or length changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, size+1))
	sum := sha256.Sum256(raw)
	if err != nil || int64(len(raw)) != size || hex.EncodeToString(sum[:]) != digest {
		t.Fatal("recorded node input digest changed")
	}
	return raw
}

func nodeBoundaryRows(t *testing.T) []nodeBoundaryRow {
	t.Helper()
	raw := nodeBoundaryBytes(t, "internal/testdata/conformance/first-v3-node-headers.json", 21634,
		"78222ac4bba092fc9f4b6775d158a8e5d013c22b7e7a85948dce6453f26cff12")
	var recorded struct {
		Format  string            `json:"format"`
		Source  map[string]string `json:"source"`
		Harness struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"harness"`
		Execution struct {
			NativeTest          string `json:"native_test"`
			Go                  string `json:"go"`
			Platform            string `json:"platform"`
			CGO                 bool   `json:"cgo_enabled"`
			Exit                int    `json:"actual_exit"`
			Complete            bool   `json:"output_complete"`
			RecordSHA256        string `json:"record_sha256"`
			GateSHA256          string `json:"gate_sha256"`
			OutputSHA256        string `json:"output_sha256"`
			UsedModules         int    `json:"used_modules_verified"`
			FullModuleGraph     string `json:"full_module_graph_go_mod_verify"`
			IndependentHashRows int    `json:"independent_python_hash_matches"`
		} `json:"execution"`
		Scope map[string]bool `json:"scope"`
		Trace struct {
			Format             string            `json:"format"`
			Scope              string            `json:"scope"`
			ChainID            uint64            `json:"chain_id"`
			Genesis            chain.Hash        `json:"genesis_hash"`
			DynamicEnforcement uint64            `json:"dynamic_enforcement"`
			RootEnforcement    uint64            `json:"state_root_enforcement"`
			FirstV3            uint64            `json:"first_incoming_v3"`
			Rows               []nodeBoundaryRow `json:"rows"`
		} `json:"trace"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&recorded); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		t.Fatal("trailing recorded node input")
	}
	wantSource := map[string]string{
		"repository":     "https://github.com/digitalSloth/go-zenon",
		"revision":       "938fca3b7787da86827a5eb63371509b36e14761",
		"tree":           "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4",
		"archive_sha256": "8ca1512eff8c04ee8b6ed0ff9a5da9e3eeba518660b07833f99a6b74e1dcc3a3",
	}
	wantScope := map[string]bool{
		"isolated_node_fixture": true, "fixture_public_keys_only": true,
		"network_execution": false, "network_activation_authenticated": false,
		"profile_agreed": false, "SPV_owned_v3_state": false,
		"runtime_state_value_acceptance": false, "consensus_finality": false,
		"recovery_qualified": false,
	}
	if recorded.Format != "zenon-recorded-first-v3-node-headers/v1" ||
		!reflect.DeepEqual(recorded.Source, wantSource) || !reflect.DeepEqual(recorded.Scope, wantScope) {
		t.Fatal("source identity and isolated fixture scope must remain explicit")
	}
	h := recorded.Harness
	if h.Path != "tools/gen-state-root-vectors/first-v3-header-capture_test.go.txt" ||
		h.SHA256 != "fdf97c44cb9bf118d1704423f9be919d244ccb8d7fb07a4a13c93aaeab8bdcae" {
		t.Fatal("node capture harness identity changed")
	}
	nodeBoundaryBytes(t, h.Path, 9427, h.SHA256)
	e := recorded.Execution
	if e.NativeTest != "TestSPVFirstIncomingV3HeaderCapture" || e.Go != "go1.25.14" ||
		e.Platform != "darwin/arm64" || !e.CGO || e.Exit != 0 || !e.Complete || e.UsedModules != 34 ||
		e.FullModuleGraph != "NOT_ESTABLISHED" || e.IndependentHashRows != 14 ||
		e.RecordSHA256 != "6a977dedb439309f8925ffd997d245b4f71eb0e5e7f836dc7f421b3e4e42f4df" ||
		e.GateSHA256 != "0eeeb54def6af3474a0af18c24961030fc70776882d9263d3b27a41db9430126" || len(e.OutputSHA256) != 64 {
		t.Fatal("recorded execution scope changed; reading a fixture is not a new node execution")
	}
	trace := recorded.Trace
	if trace.Format != "selected-node-fixture-first-v3-header-capture/v1" ||
		trace.Scope != "ISOLATED_NODE_FIXTURE_NOT_NETWORK_ACTIVATION" || trace.ChainID != 100 ||
		trace.Genesis != candidateV3Hash(t, "0385d849ee33b94c8783288c148e3ae741c2ecec98b08b3f59d6bcc219168fe5") ||
		trace.DynamicEnforcement != 10 || trace.RootEnforcement != 11 || trace.FirstV3 != 12 || len(trace.Rows) != 14 {
		t.Fatal("fixture genesis and parent enforcement differ from a network activation profile")
	}
	return trace.Rows
}

func TestCandidateV3HeaderNodeBoundaryCapture(t *testing.T) {
	rows := nodeBoundaryRows(t)
	counts := map[uint64]int{}
	signatures := 0
	for i, row := range rows {
		counts[row.Version]++
		t.Run(fmt.Sprintf("height-%d-v%d", row.Height, row.Version), func(t *testing.T) {
			wantVersion := uint64(1)
			if row.Height == 11 {
				wantVersion = 2
			} else if row.Height >= 12 {
				wantVersion = 3
			}
			if row.Height != uint64(i+1) || row.Version != wantVersion ||
				row.ParentDynamicActive != (row.Height > 10) || row.ParentStateRootActive != (row.Height > 11) ||
				row.ParentTreeReady != (i != 0) || row.TreeRootMatched != (wantVersion == 3) {
				t.Fatal("first incoming v3 must follow the parent enforcement boundary")
			}
			var header chain.Header
			if err := json.Unmarshal(row.Header, &header); err != nil {
				t.Fatal(err)
			}
			if header.Version != row.Version || header.Height != row.Height || header.ChainIdentifier != 100 ||
				header.HeaderHash != row.Hash || header.PreviousHash != row.PreviousHash {
				t.Fatal("projected header differs from the node observation")
			}
			var hash chain.Hash
			if wantVersion == 3 {
				candidate, err := chain.DecodeCandidateV3Header(row.Header)
				if err != nil || candidate.StateRoot != row.StateRoot || row.StateRoot.IsZero() {
					t.Fatal("complete captured v3 encoding or root mismatch", err)
				}
				preimage, err := candidate.Preimage()
				if err != nil || !bytes.Equal(preimage[176:], row.StateRoot[:]) {
					t.Fatal("v3 must append the raw state root after both prices", err)
				}
				hash, err = candidate.ComputeHash()
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if !row.StateRoot.IsZero() {
					t.Fatal("legacy header acquired a state-root commitment")
				}
				hash = header.ComputeHash()
			}
			if hash != row.Hash {
				t.Fatal("SPV encoding differs from the actual captured node hash")
			}
			if i == 0 {
				if !row.PreviousHash.IsZero() || len(header.PublicKey) != 0 || len(header.Signature) != 0 {
					t.Fatal("fixture genesis must remain an unsigned separate trust input")
				}
				return
			}
			if row.PreviousHash != rows[i-1].Hash || len(header.PublicKey) != ed25519.PublicKeySize ||
				!ed25519.Verify(ed25519.PublicKey(header.PublicKey), hash[:], header.Signature) {
				t.Fatal("captured link or fixture signature failed")
			}
			signatures++
		})
	}
	if !reflect.DeepEqual(counts, map[uint64]int{1: 10, 2: 1, 3: 3}) || signatures != 13 {
		t.Fatal("all captured versions and non-genesis signatures must execute")
	}
}

func nodeBoundaryV3(t *testing.T) chain.CandidateV3Header {
	t.Helper()
	row := nodeBoundaryRows(t)[11]
	candidate, err := chain.DecodeCandidateV3Header(row.Header)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestCandidateV3HeaderNodeBoundarySignedFields(t *testing.T) {
	original := nodeBoundaryV3(t)
	cases := []struct {
		name   string
		change func(*chain.CandidateV3Header)
	}{
		{"chain", func(c *chain.CandidateV3Header) { c.Header.ChainIdentifier++ }},
		{"previous", func(c *chain.CandidateV3Header) { c.Header.PreviousHash[0] ^= 1 }},
		{"height", func(c *chain.CandidateV3Header) { c.Header.Height++ }},
		{"timestamp", func(c *chain.CandidateV3Header) { c.Header.TimestampUnix++ }},
		{"data", func(c *chain.CandidateV3Header) { c.Header.DataHash[0] ^= 1 }},
		{"content", func(c *chain.CandidateV3Header) { c.Header.ContentHash[0] ^= 1 }},
		{"changes", func(c *chain.CandidateV3Header) { c.Header.ChangesHash[0] ^= 1 }},
		{"fusion-price", func(c *chain.CandidateV3Header) { c.Header.NextFusionPrice++ }},
		{"work-price", func(c *chain.CandidateV3Header) { c.Header.NextWorkPrice++ }},
		{"state-root", func(c *chain.CandidateV3Header) { c.StateRoot[0] ^= 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := original
			tc.change(&changed)
			hash, err := changed.ComputeHash()
			if err != nil || hash == original.Header.HeaderHash ||
				ed25519.Verify(ed25519.PublicKey(original.Header.PublicKey), hash[:], original.Header.Signature) {
				t.Fatal("a changed signed field retained the original hash or signature", err)
			}
		})
	}
}

func TestCandidateV3HeaderNodeBoundaryEncodingDoesNotAuthenticate(t *testing.T) {
	original := nodeBoundaryV3(t)
	t.Run("changed-root-with-recomputed-hash", func(t *testing.T) {
		changed := original
		changed.StateRoot[0] ^= 1
		var err error
		changed.Header.HeaderHash, err = changed.ComputeHash()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := chain.DecodeCandidateV3Header(raw)
		if err != nil || ed25519.Verify(ed25519.PublicKey(decoded.Header.PublicKey), decoded.Header.HeaderHash[:], decoded.Header.Signature) {
			t.Fatal("encoding consistency was confused with signature authentication", err)
		}
	})
	for _, field := range []string{"public-key", "signature"} {
		t.Run(field, func(t *testing.T) {
			changed := original
			changed.Header.PublicKey = bytes.Clone(original.Header.PublicKey)
			changed.Header.Signature = bytes.Clone(original.Header.Signature)
			if field == "public-key" {
				changed.Header.PublicKey[0] ^= 1
			} else {
				changed.Header.Signature[0] ^= 1
			}
			raw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := chain.DecodeCandidateV3Header(raw)
			if err != nil || ed25519.Verify(ed25519.PublicKey(decoded.Header.PublicKey), decoded.Header.HeaderHash[:], decoded.Header.Signature) {
				t.Fatal("width-correct candidate bytes acquired signature authority", err)
			}
		})
	}
	if err := chain.ValidateHeaderVersion(3); !errors.Is(err, chain.ErrUnsupportedHeaderVersion) {
		t.Fatal("recorded fixture must not activate the production v3 gate")
	}
}
