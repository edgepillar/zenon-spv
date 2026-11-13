// SPDX-License-Identifier: MIT

package verify_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func preparedDevnetFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "conformance", name))
	if err != nil || len(raw) == 0 || len(raw) > verify.MaxExperimentalBatchEntryProfileBytes {
		t.Fatal("cannot read bounded prepared devnet input")
	}
	return raw
}

func preparedDevnetObject(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	result, ok := value[key].(map[string]any)
	if !ok {
		t.Fatal("prepared devnet metadata object is missing")
	}
	return result
}

func preparedDevnetInputs(t *testing.T) ([]byte, map[string]any, verify.ExperimentalBatchContextProfile) {
	t.Helper()
	return preparedDevnetNamedInputs(t, "prepared-devnet-")
}

func preparedDevnetNamedInputs(t *testing.T, prefix string) ([]byte, map[string]any, verify.ExperimentalBatchContextProfile) {
	t.Helper()
	raw := preparedDevnetFile(t, prefix+"consumer-selection.json")
	reader := json.NewDecoder(bytes.NewReader(raw))
	reader.UseNumber()
	var value map[string]any
	if err := reader.Decode(&value); err != nil || reader.Decode(new(any)) != io.EOF {
		t.Fatal("invalid prepared metadata JSON")
	}
	var canonical bytes.Buffer
	writer := json.NewEncoder(&canonical)
	writer.SetEscapeHTML(false)
	if err := writer.Encode(value); err != nil || !bytes.Equal(canonical.Bytes(), raw) {
		t.Fatal("prepared metadata must be canonical, unique-key JSON")
	}
	profile, err := verify.DecodeExperimentalBatchContextProfile(
		preparedDevnetFile(t, prefix+"query-profile.json"))
	if err != nil {
		t.Fatal("prepared query profile did not pass the public decoder")
	}
	return raw, value, profile
}

func TestPreparedReferenceGasDevnetConsumerProfile(t *testing.T) {
	oldRaw, oldSelection, oldProfile := preparedDevnetInputs(t)
	raw, selection, profile := preparedDevnetNamedInputs(t, "prepared-devnet-reference-gas-")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "d77cca86d4624e691917ee0d2b94dc70c4bf0e29f87316ea89513c72209a6b48" ||
		!bytes.Equal(profile.Entry.RuntimeIdentity[:], digest[:]) || bytes.Equal(oldRaw, raw) ||
		profile.Entry.RuntimeIdentity == oldProfile.Entry.RuntimeIdentity {
		t.Fatal("reference-gas metadata did not select a new, exact runtime metadata identity")
	}
	for _, key := range []string{"format", "network", "consumer", "source_profile", "authority"} {
		before, err := json.Marshal(oldSelection[key])
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(selection[key])
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("reference-gas selection changed the query, semantic expectations or trust scope")
		}
	}
	cohort := preparedDevnetObject(t, selection, "source_cohort")
	expected := map[string]string{
		"devnet":            "cf1c9c0e0f0ca3b257bdbd019c5589c2c27f748f",
		"node":              verify.ExperimentalV3ReferenceGasNodeRevision,
		"node_tree":         "f89d645c7f5be85dfe10dc7a510d80df7965d22f",
		"executor":          verify.ExperimentalBatchEntryReferenceGasExecutorRevision,
		"contract_sdk":      verify.ExperimentalBatchEntrySDKRevision,
		"typescript_client": "e9e02d8b12fa4053b8d19b1a4d6257d933bfdc0a",
		"typescript_sdk":    "75cd2565bd388c1df6b441bfcc1670e8da483c77",
	}
	if len(cohort) != len(expected) {
		t.Fatal("reference-gas source cohort is incomplete")
	}
	for key, revision := range expected {
		if cohort[key] != revision {
			t.Fatal("reference-gas source pair changed")
		}
	}
	configuration := preparedDevnetObject(t, selection, "devnet_configuration")
	if configuration["revision"] != expected["devnet"] {
		t.Fatal("reference-gas metadata retained the original devnet label")
	}
	profile.Entry.RuntimeIdentity, profile.Entry.Source = oldProfile.Entry.RuntimeIdentity, oldProfile.Entry.Source
	before, err := json.Marshal(oldProfile)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(profile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("reference-gas metadata changed canonical rules or work ceilings")
	}
	// This is native profile decoding and source selection, not a devnet capture,
	// accepted header, finite producer authorization or proof of runtime execution.
}

func TestPreparedDevnetConsumerProfile(t *testing.T) {
	raw, selection, profile := preparedDevnetInputs(t)
	if selection["format"] != "zenon-owned-devnet-consumer-selection/v1" {
		t.Fatal("wrong prepared metadata format")
	}
	network := preparedDevnetObject(t, selection, "network")
	if network["chain_identifier"] != json.Number("69") ||
		network["source_genesis_file_bytes"] != json.Number("8137") ||
		network["source_genesis_file_sha256"] != "0dd33b18b147f70b3d3d5f07199a2b45311f6e9b84a98b3f86d8f6c6b45f419a" ||
		network["source_genesis_H1_hash"] != "fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9" {
		t.Fatal("prepared network metadata differs from the selected source")
	}
	consumer := preparedDevnetObject(t, selection, "consumer")
	if consumer["kind"] != "existing-read-only-CLI-typed-BatchEntry" ||
		consumer["settlement_address_hex"] != verify.ExperimentalBatchEntrySettlementHex ||
		consumer["domain_id"] != json.Number("1") || consumer["batch_id_decimal"] != "0" ||
		consumer["require_three_present_same_root_proofs"] != true ||
		consumer["select_another_batch_after_provider_absence"] != false {
		t.Fatal("prepared consumer selectors are not independently fixed")
	}
	cohort := preparedDevnetObject(t, selection, "source_cohort")
	expected := map[string]string{
		"devnet":            "04dc0797f7bcc02e48e0acba3b0ac49df2d3289d",
		"node":              "938fca3b7787da86827a5eb63371509b36e14761",
		"node_tree":         "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4",
		"executor":          verify.ExperimentalBatchEntryExecutorRevision,
		"contract_sdk":      verify.ExperimentalBatchEntrySDKRevision,
		"typescript_client": "e9e02d8b12fa4053b8d19b1a4d6257d933bfdc0a",
		"typescript_sdk":    "e3b75183440f8e6543511f7a55e6c66e5736014e",
	}
	if len(cohort) != len(expected) {
		t.Fatal("prepared source cohort is incomplete")
	}
	for name, revision := range expected {
		if cohort[name] != revision {
			t.Fatal("prepared source cohort changed")
		}
	}
	selected := preparedDevnetObject(t, selection, "source_profile")
	for _, name := range []string{"domain_class", "runtime_kind", "input_source", "exec_profile",
		"foreign_profile", "proposer_policy", "finality_model"} {
		if selected[name] != json.Number("0") {
			t.Fatal("prepared source enum differs")
		}
	}
	if selected["profile_config_hex"] != "" || selected["chain_binding_hex"] != "" ||
		selected["min_executors"] != json.Number("1") ||
		selected["stf_spec_hash"] != "0000000000000000000000000000000000000000000000000000000000000001" ||
		selected["withdrawal_delay"] != json.Number("30") ||
		selected["runtime_upgrade_delay"] != json.Number("17280") {
		t.Fatal("prepared source domain metadata differs")
	}
	configuration := preparedDevnetObject(t, selection, "devnet_configuration")
	if configuration["repository"] != "Zeno-L2/zeno-devnet" ||
		configuration["revision"] != expected["devnet"] || configuration["path"] != "src/devnet.ts" ||
		configuration["git_blob"] != "e73b01b9dfe3c06d5fb662bec265f350f15aee13" ||
		configuration["bytes"] != json.Number("9230") ||
		configuration["sha256"] != "16b86fb256e90d6bf3b2375995b88ede24103d6c4f9526d1a9fc30c722669525" {
		t.Fatal("prepared configuration provenance differs")
	}
	authority := preparedDevnetObject(t, selection, "authority")
	if authority["runtime_identity_is_only_the_SHA256_of_this_canonical_metadata_descriptor"] != true {
		t.Fatal("runtime identity must be explicit local metadata")
	}
	for _, name := range []string{"authenticated_runtime_or_STF_execution",
		"network_anchor_or_finite_schedule_supplied_by_this_file",
		"network_activation_or_consensus_finality_proven"} {
		if authority[name] != false {
			t.Fatal("prepared metadata was upgraded to acceptance authority")
		}
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(profile.Entry.RuntimeIdentity[:], digest[:]) ||
		profile.Version != 2 || profile.Entry.Version != 2 ||
		profile.Entry.DomainID != 1 || profile.Entry.Settlement != verify.ExperimentalBatchEntrySettlementAddress() ||
		profile.Entry.SourceRule != verify.ExperimentalBatchEntrySourceRule {
		t.Fatal("prepared profile is not bound to the local selection and source rule")
	}
	limits := profile.Entry.Limits
	if limits.MaxValueBytes != 4096 || limits.MaxExecutorPillarBytes != 40 ||
		limits.MaxAssetFlowSummaryBytes != 1540 || limits.MaxProofDataBytes != 1 ||
		limits.MaxDynamicBytes != 1580 || limits.StringRule != proof.CandidateBatchEntryUTF8String {
		t.Fatal("prepared local work ceilings differ")
	}
	if profile.Limits.MaxTotalProofBytes != 33141 || profile.Limits.MaxTotalValueBytes != 8256 ||
		profile.Limits.MaxTotalSiblings != 768 || profile.DomainRule != verify.ExperimentalDomainRecordRule {
		t.Fatal("prepared aggregate work or source rule differs")
	}
}

func TestPreparedDevnetConsumerLocalKeys(t *testing.T) {
	_, _, profile := preparedDevnetInputs(t)
	address, domain := profile.Entry.Settlement, profile.Entry.DomainID
	entry := proof.CandidateSettlementBatchEntryKey(address, domain, 0)
	record := proof.CandidateSettlementDomainRecordKey(address, domain)
	config := proof.CandidateSettlementDomainConfigKey(address, domain)
	entryPath := proof.CandidateSettlementBatchEntryPath(address, domain, 0)
	recordPath := proof.CandidateSettlementDomainRecordPath(address, domain)
	configPath := proof.CandidateSettlementDomainConfigPath(address, domain)
	// These literal bytes also occur in the independently recorded source-key
	// vectors. They establish the local query identity, not value membership.
	for _, row := range []struct {
		name, key, path string
		actual          []byte
		actualPath      []byte
	}{
		{"batch-entry", "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c00402000000010000000000000000",
			"5ee4358ff3d00f4b24cfda1d9bf5120c02ce1594aea4ada71767b92e86286d6f", entry[:], entryPath[:]},
		{"domain-record", "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c0040100000001",
			"1fbd3b1be8cfbe17942b1b182c248d3105c571c65b0f42d74f76cde290c62d08", record[:], recordPath[:]},
		{"domain-config", "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c0041500000001",
			"9421596e30f27b5de445c744365beb3d658a3cfc8916791bb2ed268eb7835559", config[:], configPath[:]},
	} {
		t.Run(row.name, func(t *testing.T) {
			if hex.EncodeToString(row.actual) != row.key || hex.EncodeToString(row.actualPath) != row.path {
				t.Fatal("prepared local key or its single SHA3 path differs")
			}
		})
	}
}
