// SPDX-License-Identifier: MIT

package main

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/verify"
)

const l2StorageTestPath = "60b8073d7cee456c7eb5e738b72fc6c84227560337ee22a52ff7136bd6588789"

func TestExperimentalL2StorageSelectedBatch(t *testing.T) {
	request, err := decodeExperimentalL2StorageRequest([]byte(
		`{"contract_id":"` + strings.Repeat("11", 32) + `","local_key_hex":"0001"}`))
	if err != nil {
		t.Fatal(err)
	}

	// The path and roots are independent SHA3-256 byte oracles for a
	// single depth-256 leaf (or the empty tree) under the selected key.
	cases := []struct {
		name, root, leaf, value, length string
		present                         bool
	}{
		{"stored value", "1d35cb135dcdc336607a0bdead7f7c18ab658a880d66881df1ffa5922bab50ff",
			"2e61840b8ecce079f82152d9e87280b779ca6f76b9e8dc5f87c3be1fcb51b062", "00ff", "00000002", true},
		{"present empty", "f85f33e905b611c6b9fbbda5655e15cc6fab21ee7084971ae41a95125ce5fc63",
			"9926da7f6d0df352833278e87a3592e49e97b90b64085710cd603bcd2ef7b7fe", "", "00000000", true},
		{"absent", strings.Repeat("00", 32), strings.Repeat("00", 32), "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			batch := verify.ExperimentalBatchContextResult{}
			batch.Entry.ProtocolVersion = 1
			batch.Context.Entry.DomainID = 1
			batch.Request.BatchID = 9
			if err := batch.Entry.PostStateRoot.UnmarshalText([]byte(c.root)); err != nil {
				t.Fatal(err)
			}
			presence := "00"
			var value *string
			if c.present {
				presence, value = "01", &c.value
			}
			encoded := presence + l2StorageTestPath + c.leaf + strings.Repeat("00", 34) + c.length + c.value
			row := map[string]any{"path": l2StorageTestPath, "present": c.present, "value": value, "proof": encoded}
			raw := experimentalCLIJSON(t, map[string]any{
				"domainId": 1, "batchId": 9, "postStateRoot": c.root, "verified": false, "proofs": []any{row},
			})
			got, err := checkExperimentalL2Storage(batch, request, raw)
			if err != nil || got.DomainID != 1 || got.BatchID != 9 || got.PostStateRoot != batch.Entry.PostStateRoot ||
				hex.EncodeToString(got.Path[:]) != l2StorageTestPath || got.Present != c.present ||
				got.ProofBytes != len(encoded)/2 || c.present != (got.ValueHex != nil) ||
				c.present && *got.ValueHex != c.value {
				t.Fatalf("L2 storage result = %+v, %v", got, err)
			}
			if c.present {
				// A valid proof for another selected root must not fall back
				// to the provider's claimed root.
				batch.Entry.PostStateRoot[0] ^= 1
				if _, err := checkExperimentalL2Storage(batch, request, raw); !errors.Is(err, errExperimentalL2WitnessIdentity) {
					t.Fatal("accepted root did not control the storage result", err)
				}
			}
		})
	}
}

func TestExperimentalBatchContextCLIL2StorageScope(t *testing.T) {
	f := newBatchContextCLIInputs(t)
	baseline := batchContextCLIReport(t, experimentalContextQueryCommand, f.args(), 0)
	if baseline.Result == nil || baseline.L2Storage != nil {
		t.Fatal("ordinary three-row query changed")
	}

	dir := filepath.Dir(f.requestPath)
	request := filepath.Join(dir, "l2-request.json")
	witness := filepath.Join(dir, "l2-witness.json")
	if err := os.WriteFile(request, experimentalCLIJSON(t, map[string]any{
		"contract_id": strings.Repeat("11", 32), "local_key_hex": "0001",
	}), 0600); err != nil {
		t.Fatal(err)
	}
	withRequest := append(f.args()[:8:8], "--l2-storage-request", request)
	batchContextCLIReport(t, experimentalContextQueryCommand, append(withRequest, f.bundlePath), 64)
	withWitness := append(withRequest[:len(withRequest):len(withRequest)], "--l2-proof-result", witness, f.bundlePath)

	batch := baseline.Result
	wrongBatch := experimentalCLIJSON(t, map[string]any{
		"domainId": batch.Context.Entry.DomainID, "batchId": batch.Request.BatchID + 1,
		"postStateRoot": batch.Entry.PostStateRoot, "verified": true, "proofs": []any{map[string]any{}},
	})
	for _, test := range []struct {
		name, category string
		raw            []byte
		exit           int
	}{
		{"other batch", "identity_mismatch", wrongBatch, 1},
		{"unavailable witness", "unavailable", []byte("null"), 2},
		{"ambiguous witness", "invalid_witness", []byte("{\"batchId\":0,\"batchId\":1}"), 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(witness, test.raw, 0600); err != nil {
				t.Fatal(err)
			}
			report := batchContextCLIReport(t, experimentalContextQueryCommand, withWitness, test.exit)
			if report.Error == nil || report.Error.Stage != "l2_storage_witness" || report.Error.Category != test.category ||
				report.Headers == nil || report.Headers.Outcome != "ACCEPT" || report.L2Storage != nil || report.Result != nil {
				t.Fatalf("unexpected scoped refusal: %+v", report)
			}
		})
	}
}
