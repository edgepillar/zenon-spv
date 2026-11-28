// SPDX-License-Identifier: MIT

package main

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/fetch"
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
				if _, err := checkExperimentalL2Storage(batch, request, raw); !errors.Is(err, fetch.ErrCandidateZenoStorageIdentity) {
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

func TestExperimentalPhase1VaultBalance(t *testing.T) {
	const (
		account = "0022222222222222222222222222222222222222"
		token   = "33333333333333333333"
		key     = "d5336f60c93b175569f081df8a14ea4a56c1e306dd210b52925d36d9495c39af"
		path    = "5f65b0976c2db72c539d9099680b4e49eed4dc707c7ea3fc3a5eab0061932cfd"
		amount  = "57896044618658097711785492504343953926634992332820282019728792003957552474289"
	)
	vault := map[string]any{"account_hex": account, "token_standard_hex": token}
	requestJSON := map[string]any{"contract_id": strings.Repeat("11", 32), "vault_balance": vault}
	request, err := decodeExperimentalL2StorageRequest(experimentalCLIJSON(t, requestJSON))
	if err != nil || request.Vault == nil || hex.EncodeToString(request.LocalKey) != key {
		t.Fatal("vault local key", err)
	}
	for _, c := range []struct {
		name, root, leaf, stored, length, amount string
		present                                  bool
		want                                     error
	}{
		{
			name: "present u256", root: "bec08d54ebde2f6303cbc032bba2bd9546038359371417ee099225d07b52a7e3",
			leaf:   "0bbb1a4a65594705392ba47835af8df36a39d256f2d2549fab36914e0f784fec",
			stored: "800000000000000000000000000000000000000000000000000000003ade68b1", length: "00000020",
			present: true, amount: amount,
		},
		{
			name: "proven absence", root: strings.Repeat("00", 32), leaf: strings.Repeat("00", 32), amount: "0",
		},
		{
			name: "present empty has wrong vault ABI width", root: "0def5c8644bb89ed3c405629403110bd9feca6c92548652c6c13b70854525d2f",
			leaf:    "cec8f4681d62c4796a9f12e7901193c89e8008517a6385bb15e4983eec35e3f8",
			present: true, length: "00000000", want: errExperimentalVaultValue,
		},
	} {
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
				presence, value = "01", &c.stored
			}
			witness := map[string]any{"path": path, "present": c.present, "value": value,
				"proof": presence + path + c.leaf + strings.Repeat("00", 34) + c.length + c.stored}
			raw := experimentalCLIJSON(t, map[string]any{"domainId": 1, "batchId": 9,
				"postStateRoot": c.root, "verified": false, "proofs": []any{witness}})
			observed, err := checkExperimentalL2Storage(batch, request, raw)
			if c.want != nil {
				if !errors.Is(err, c.want) || observed.VaultBalance != nil {
					t.Fatal("invalid vault value published a result", err)
				}
				return
			}
			if err != nil || observed.BatchID != 9 || observed.Present != c.present ||
				hex.EncodeToString(observed.Path[:]) != path || observed.VaultBalance == nil ||
				observed.VaultBalance.AccountHex != account || observed.VaultBalance.TokenStandardHex != token ||
				observed.VaultBalance.AmountBaseUnits != c.amount ||
				observed.VaultBalance.InterfaceSHA256 != "26f4d8c1b1d1cbf9dcf2ed4d99fcbc4b8e81af5bfb476c756bfd99b759fefba9" ||
				c.present != (observed.ValueHex != nil) || c.present && *observed.ValueHex != c.stored {
				t.Fatalf("unexpected typed vault balance: %+v, %v", observed, err)
			}
		})
	}
	requestJSON["local_key_hex"] = key
	if _, err := decodeExperimentalL2StorageRequest(experimentalCLIJSON(t, requestJSON)); err == nil {
		t.Fatal("mixed raw and typed key selection was accepted")
	}
}
