// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func TestExperimentalBatchEntrySourceRuleIndependentVectors(t *testing.T) {
	raw, err := os.ReadFile("../testdata/conformance/batch-entry-source-rule.json")
	sum := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(sum[:]) != "c3505ea90fa4d237db0956a7d08c611a0dab4f17946b5f82551da43a4b3cf2c6" {
		t.Fatal("independent source-field vectors changed", err)
	}
	var corpus struct {
		Vectors []struct {
			Name     string
			Accepted bool
			Value    string `json:"value_hex"`
		}
	}
	if json.Unmarshal(raw, &corpus) != nil || len(corpus.Vectors) != 34 {
		t.Fatal("independent corpus framing")
	}
	legacy := experimentalBatchProfile()
	legacy.Limits = ExperimentalBatchEntryLimits{MaxValueBytes: 4096, MaxExecutorPillarBytes: 4096,
		MaxAssetFlowSummaryBytes: 4096, MaxProofDataBytes: 4096, MaxDynamicBytes: 4096,
		StringRule: proof.CandidateBatchEntryOpaqueString}
	selected := legacy
	selected.Version, selected.SourceRule = 2, ExperimentalBatchEntrySourceRule
	if selected.Validate() != nil {
		t.Fatal("explicit source policy")
	}
	for _, row := range corpus.Vectors {
		t.Run(row.Name, func(t *testing.T) {
			value, err := hex.DecodeString(row.Value)
			if err != nil {
				t.Fatal(err)
			}
			root, path, encoded := experimentalBatchMathWitness(legacy, 0, value)
			// Every vector is canonical ABI with valid mathematical membership.
			// The legacy profile continues to return the uninterpreted row.
			match, old, err := readExperimentalBatchEntry(root, path, encoded, legacy)
			if err != nil || !match.Canonical || !match.Present || !bytes.Equal(match.Value, value) {
				t.Fatal("legacy proof/ABI behavior changed", err)
			}
			match, got, err := readExperimentalBatchEntry(root, path, encoded, selected)
			if row.Accepted {
				if err != nil || !reflect.DeepEqual(got, old) || !bytes.Equal(match.Value, value) {
					t.Fatal("selected source-field value differs", err)
				}
			} else if err != ErrExperimentalBatchEntrySourceRule || !reflect.DeepEqual(got, proof.CandidateBatchEntry{}) ||
				!reflect.DeepEqual(match, proof.CandidateSMTMatch{}) {
				t.Fatal("source mismatch returned partial typed/proven data", err)
			}
		})
	}
}

func TestExperimentalBatchEntrySourceRuleProfileVersions(t *testing.T) {
	state, legacy, old, _ := experimentalBatchInputs(t)
	original := experimentalV3JSON(t, legacy)
	if bytes.Contains(original, []byte("source_rule")) || bytes.Contains(experimentalV3JSON(t, old), []byte("source_rule")) {
		t.Fatal("new field appeared in legacy JSON")
	}
	selected := legacy
	selected.Version, selected.SourceRule = 2, ExperimentalBatchEntrySourceRule
	encoded := experimentalV3JSON(t, selected)
	if got, err := DecodeExperimentalBatchEntryProfile(encoded); err != nil || got != selected {
		t.Fatal("explicit policy round trip", err)
	}
	// Schema selection never makes duplicates/case aliases or optional source
	// rules acceptable. Failed decoding also preserves an existing receiver.
	for field := range experimentalV3Fields(t, encoded) {
		for _, change := range []string{"missing", "null", "duplicate", "case-alias"} {
			t.Run(field+"/"+change, func(t *testing.T) {
				fields := experimentalV3Fields(t, encoded)
				switch change {
				case "missing":
					delete(fields, field)
				case "null":
					fields[field] = json.RawMessage("null")
				case "case-alias":
					fields[strings.ToUpper(field)] = fields[field]
					delete(fields, field)
				}
				bad := experimentalV3JSON(t, fields)
				if change == "duplicate" {
					bad = append(bad[:len(bad)-1], ',')
					bad = append(bad, experimentalV3JSON(t, field)...)
					bad = append(append(bad, ':'), fields[field]...)
					bad = append(bad, '}')
				}
				target := selected
				if json.Unmarshal(bad, &target) == nil || target != selected {
					t.Fatal("ambiguous source policy changed a receiver")
				}
			})
		}
	}
	for _, pair := range []struct {
		version uint32
		rule    string
	}{{0, ""}, {1, ExperimentalBatchEntrySourceRule}, {2, ""}, {2, "unknown"}, {3, ExperimentalBatchEntrySourceRule}} {
		next := selected
		next.Version, next.SourceRule = pair.version, pair.rule
		if next.Validate() != ErrExperimentalBatchEntryProfile {
			t.Fatal("implicit or unsupported source policy accepted")
		}
		if _, err := DecodeExperimentalBatchEntryProfile(experimentalV3JSON(t, next)); err == nil {
			t.Fatal("unsupported wire policy accepted")
		}
	}
	fields := experimentalV3Fields(t, original)
	fields["source_rule"] = json.RawMessage(`""`)
	if _, err := DecodeExperimentalBatchEntryProfile(experimentalV3JSON(t, fields)); err == nil {
		t.Fatal("legacy wire schema admitted a new empty field")
	}
	current, err := ExperimentalBatchEntryContextFor(state, selected)
	if err != nil || current.Version != 2 || current.SourceRule != selected.SourceRule || current.Fingerprint == old.Fingerprint {
		t.Fatal("source policy omitted from context", err)
	}
	if _, err := NewExperimentalBatchEntryQuery(state, selected, old.Fingerprint); err != ErrExperimentalBatchEntryContext {
		t.Fatal("legacy pin authorized a new source policy", err)
	}
	if _, err := NewExperimentalBatchEntryQuery(state, legacy, current.Fingerprint); err != ErrExperimentalBatchEntryContext {
		t.Fatal("source pin authorized legacy interpretation", err)
	}
	selected.Source = "private source label remains excluded"
	again, err := ExperimentalBatchEntryContextFor(state, selected)
	if err != nil || again != current {
		t.Fatal("audit label changed source-policy identity", err)
	}
	selected.Limits.MaxProofDataBytes = 0
	if selected.Validate() != ErrExperimentalBatchEntryProfile {
		t.Fatal("empty proofData semantics disabled the positive byte cap")
	}
}

func TestExperimentalBatchContextSourceRuleOwnedAndIndependentBytes(t *testing.T) {
	f := newBatchContextFixture(t)
	legacy := f.Config.QueryProfile
	profile := legacy
	profile.Version, profile.Entry.Version, profile.Entry.SourceRule = 2, 2, ExperimentalBatchEntrySourceRule
	context, err := ExperimentalBatchContextFor(f.state, profile)
	if err != nil || context.Version != 2 || context.Entry.Version != 2 ||
		hex.EncodeToString(context.Entry.Fingerprint[:]) != "93cdf8e13f5a4251b6c6d978d41e79550399482b7b8f47979a2e962b13107c25" ||
		hex.EncodeToString(context.Fingerprint[:]) != "478088778573e6080c550c686c7434928bf4f16d0306daea6fe5416090cb91fd" {
		t.Fatal("independent version 2 context differs", err)
	}
	query, err := NewExperimentalBatchContextQuery(f.state, profile, context.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request := f.Request
	request.Context = context.Fingerprint
	result, err := query.QueryWitnesses(request, f.witness)
	if err != nil || result.Context != context ||
		hex.EncodeToString(result.QueryFingerprint[:]) != "b9b542757c5f0c1cdc1b982f153ad875450e57ea5a91bc247cefaa81e62b4f9e" {
		t.Fatal("source rule did not compose with the owned three-row query", err)
	}
	old, err := f.query.QueryWitnesses(f.Request, f.witness)
	if err != nil || !reflect.DeepEqual(result.Entry, old.Entry) || result.Root != old.Root {
		t.Fatal("version selection changed proven bytes", err)
	}
	path := t.TempDir() + "/owned-source-rule-state.json"
	if f.state.Save(path) != nil {
		t.Fatal("cannot save synthetic owned state")
	}
	resumed, err := LoadTrustedExperimentalV3State(path, f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule, context.Entry.Header.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewExperimentalBatchContextQuery(resumed, profile, context.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	got, err := q.QueryWitnesses(request, f.witness)
	if err != nil || got.QueryFingerprint != result.QueryFingerprint || !reflect.DeepEqual(got.Entry, result.Entry) {
		t.Fatal("trusted restart lost the explicit query policy", err)
	}
	for _, mixed := range []ExperimentalBatchContextProfile{
		{Version: 1, Entry: profile.Entry, DomainRule: profile.DomainRule, DomainRecord: profile.DomainRecord, DomainConfig: profile.DomainConfig, Limits: profile.Limits},
		{Version: 2, Entry: legacy.Entry, DomainRule: profile.DomainRule, DomainRecord: profile.DomainRecord, DomainConfig: profile.DomainConfig, Limits: profile.Limits},
	} {
		if mixed.Validate() != ErrExperimentalBatchContextProfile {
			t.Fatal("mixed profile versions accepted")
		}
	}
	if _, err := NewExperimentalBatchContextQuery(f.state, profile, f.Request.Context); err != ErrExperimentalBatchContextPin {
		t.Fatal("legacy three-row pin selected a new policy")
	}
	if _, err := query.QueryWitnesses(f.Request, f.witness); err != ErrExperimentalBatchContextPin {
		t.Fatal("legacy request entered the new policy")
	}
	// This remains experimental membership, without production v3 acceptance.
	if chain.ValidateHeaderVersion(3) == nil {
		t.Fatal("query policy enabled production v3")
	}
}

func TestExperimentalBatchEntrySourceRuleOwnedRejection(t *testing.T) {
	raw, err := os.ReadFile("../testdata/conformance/batch-entry-source-rule-invalid-context.json")
	sum := sha256.Sum256(raw)
	if err != nil || len(raw) != 17527 || hex.EncodeToString(sum[:]) != "12a60cba21d84a97cf4e584cfc016d871279f17814c087af1238d28d653825b8" {
		t.Fatal("synthetic negative workflow fixture changed", err)
	}
	var f batchContextFixture
	var trace struct {
		Witnesses struct {
			Root chain.Hash `json:"root_hex"`
			Rows []struct {
				Value string `json:"value_hex"`
				Proof string `json:"proof_hex"`
			}
		}
	}
	if json.Unmarshal(raw, &f) != nil || json.Unmarshal(raw, &trace) != nil || len(trace.Witnesses.Rows) != 3 {
		t.Fatal("negative workflow decode")
	}
	rows := []*proof.CandidateStateWitness{&f.witness.BatchEntry, &f.witness.DomainRecord, &f.witness.DomainConfig}
	for i, row := range trace.Witnesses.Rows {
		value, e1 := hex.DecodeString(row.Value)
		encoded, e2 := hex.DecodeString(row.Proof)
		if e1 != nil || e2 != nil {
			t.Fatal("negative workflow bytes")
		}
		*rows[i] = proof.CandidateStateWitness{Root: trace.Witnesses.Root, Value: value, Proof: encoded}
	}
	header, err := ExperimentalV3ContextFor(f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := NewExperimentalV3State(f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule, header.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	accepted, state := empty.Extend(f.Headers)
	if accepted.Outcome != OutcomeAccept {
		t.Fatal("synthetic negative fixture headers were not accepted", accepted)
	}
	// Version 1 confirms the entire canonical proof set and typed ABI, including
	// both unchanged context rows. Only explicit version 2 refuses this name.
	legacy := f.Config.QueryProfile
	legacy.Version, legacy.Entry.Version, legacy.Entry.SourceRule = 1, 1, ""
	oldContext, err := ExperimentalBatchContextFor(state, legacy)
	if err != nil {
		t.Fatal(err)
	}
	old, err := NewExperimentalBatchContextQuery(state, legacy, oldContext.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	oldRequest := f.Request
	oldRequest.Context = oldContext.Fingerprint
	value, err := old.QueryWitnesses(oldRequest, f.witness)
	if err != nil || value.Entry.ExecutorPillar != "a-_b" || value.Root != trace.Witnesses.Root {
		t.Fatal("negative fixture did not pass legacy canonical membership and ABI", err)
	}
	selected, err := NewExperimentalBatchContextQuery(state, f.Config.QueryProfile, f.Request.Context)
	if err != nil {
		t.Fatal(err)
	}
	result, err := selected.QueryWitnesses(f.Request, f.witness)
	if err != ErrExperimentalBatchEntrySourceRule || !reflect.DeepEqual(result, ExperimentalBatchContextResult{}) {
		t.Fatal("three-row source failure supplied a partial result", err)
	}
	for _, rawProof := range []bool{false, true} {
		context, err := ExperimentalBatchEntryContextFor(state, f.Config.QueryProfile.Entry)
		if err != nil {
			t.Fatal(err)
		}
		query, err := NewExperimentalBatchEntryQuery(state, f.Config.QueryProfile.Entry, context.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		request := ExperimentalBatchEntryRequest(f.Request)
		request.Context = context.Fingerprint
		var got ExperimentalBatchEntryResult
		if rawProof {
			got, err = query.Query(request, f.witness.BatchEntry.Proof)
		} else {
			got, err = query.QueryWitness(request, f.witness.BatchEntry)
		}
		if err != ErrExperimentalBatchEntrySourceRule || !reflect.DeepEqual(got, ExperimentalBatchEntryResult{}) {
			t.Fatal("single-row source failure supplied a partial result", err)
		}
	}
}
