// SPDX-License-Identifier: MIT

package proof_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

type batchEntryKeyVector struct {
	Name    string
	Address string
	Domain  uint32 `json:"domain_id"`
	Batch   string `json:"batch_id_decimal"`
	Subkey  string `json:"application_subkey"`
	Key     string `json:"raw_key"`
	Path    string
}

func batchEntryKeyVectors(t *testing.T) []batchEntryKeyVector {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "testdata", "conformance", "settlement-batch-entry-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close BatchEntry key facts: %v", err)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if len(raw) != 5048 || hex.EncodeToString(digest[:]) != "03ae88f373b34bf376ee8972d2864db852799df5b53a8393b966a7766026e613" {
		t.Fatal("selected BatchEntry key facts changed")
	}
	var file struct {
		Format string
		Source struct {
			Repository, Revision, Tree string
			Files                      map[string]struct {
				Blob   string `json:"git_blob"`
				SHA256 string
				Bytes  int
			}
		}
		Scope struct {
			SourceOnly bool `json:"source_derived"`
			Node       bool `json:"node_execution"`
			Profile    bool `json:"profile_agreed"`
			Accepted   bool `json:"state_value_acceptance"`
		}
		Vectors []batchEntryKeyVector
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		t.Fatal(err)
	}
	if file.Format != "zenon-candidate-settlement-batch-entry-keys/v1" ||
		file.Source.Repository != "digitalSloth/go-zenon" ||
		file.Source.Revision != "938fca3b7787da86827a5eb63371509b36e14761" ||
		file.Source.Tree != "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4" ||
		len(file.Source.Files) != 10 || len(file.Vectors) != 6 ||
		!file.Scope.SourceOnly || file.Scope.Node || file.Scope.Profile || file.Scope.Accepted {
		t.Fatal("source identity or source-only scope differs")
	}
	return file.Vectors
}

func batchEntryInputs(t *testing.T, v batchEntryKeyVector) (chain.Address, uint64) {
	t.Helper()
	var address chain.Address
	if err := address.UnmarshalText([]byte(v.Address)); err != nil {
		t.Fatal(err)
	}
	batch, err := strconv.ParseUint(v.Batch, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return address, batch
}

func TestCandidateSettlementBatchEntryKeyVectors(t *testing.T) {
	for _, v := range batchEntryKeyVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			address, batch := batchEntryInputs(t, v)
			key := proof.CandidateSettlementBatchEntryKey(address, v.Domain, batch)
			if !bytes.Equal(key[:], candidateSMTBytes(t, v.Key)) ||
				!bytes.Equal(key[22:], candidateSMTBytes(t, v.Subkey)) {
				t.Fatal("full ledger key differs from independent byte facts")
			}
			path := proof.CandidateSettlementBatchEntryPath(address, v.Domain, batch)
			if path != candidateSMTHash(t, v.Path) {
				t.Fatal("full-key SHA3-256 path differs from independent digest")
			}
		})
	}
}

func TestCandidateSettlementBatchEntryPathBinding(t *testing.T) {
	var selected batchEntryKeyVector
	for _, v := range batchEntryKeyVectors(t) {
		if v.Name == "settlement_domain_1_batch_1" {
			selected = v
		}
	}
	if selected.Name == "" {
		t.Fatal("selected path case missing")
	}
	address, batch := batchEntryInputs(t, selected)
	key := proof.CandidateSettlementBatchEntryKey(address, selected.Domain, batch)
	path := proof.CandidateSettlementBatchEntryPath(address, selected.Domain, batch)

	// These arbitrary bytes exercise key/path binding, not a BatchEntry ABI.
	state := map[string]string{selected.Path: "010203"}
	tree := zenoTree(t, state)
	raw := zenoProof(t, tree, state, path)
	root, value := zenoNodeHash(tree), candidateSMTBytes(t, "010203")
	match, err := proof.CheckCandidateSMTInclusion(root, path, value, raw, candidateSMTLimits())
	if err != nil || !match.Present || !match.Canonical || !bytes.Equal(match.Value, value) {
		t.Fatalf("derived path comparison failed: %+v, %v", match, err)
	}

	other := address
	other[19] ^= 1
	balance, plasma, littleDomain, littleBatch := key, key, key, key
	balance[21], plasma[21] = 0x03, 0x05
	binary.LittleEndian.PutUint32(littleDomain[23:27], selected.Domain)
	binary.LittleEndian.PutUint64(littleBatch[27:35], batch)
	cases := []struct {
		name string
		path chain.Hash
	}{
		{"other_settlement", proof.CandidateSettlementBatchEntryPath(other, selected.Domain, batch)},
		{"other_domain", proof.CandidateSettlementBatchEntryPath(address, selected.Domain+1, batch)},
		{"other_batch", proof.CandidateSettlementBatchEntryPath(address, selected.Domain, batch+1)},
		{"balance_family", chain.Hash(sha3.Sum256(balance[:]))},
		{"excluded_plasma_family", chain.Hash(sha3.Sum256(plasma[:]))},
		{"without_account_namespace", chain.Hash(sha3.Sum256(key[21:]))},
		{"application_subkey_only", chain.Hash(sha3.Sum256(key[22:]))},
		{"little_endian_domain", chain.Hash(sha3.Sum256(littleDomain[:]))},
		{"little_endian_batch", chain.Hash(sha3.Sum256(littleBatch[:]))},
		{"path_hashed_again", chain.Hash(sha3.Sum256(path[:]))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.path == path {
				t.Fatal("negative case did not change the selected path")
			}
			result, err := proof.CheckCandidateSMTInclusion(root, c.path, value, raw, candidateSMTLimits())
			requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTPath)
		})
	}
}
