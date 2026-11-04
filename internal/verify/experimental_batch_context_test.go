// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

type batchContextFixture struct {
	Config struct {
		HeaderProfile ExperimentalV3Profile           `json:"header_profile"`
		HeaderPolicy  ExperimentalV3Policy            `json:"header_policy"`
		Schedule      *ProducerSchedule               `json:"producer_schedule"`
		QueryProfile  ExperimentalBatchContextProfile `json:"query_profile"`
	}
	Headers  []chain.CandidateV3Header
	Request  ExperimentalBatchContextRequest
	Expected map[string]json.RawMessage
	state    ExperimentalV3State
	query    ExperimentalBatchContextQuery
	witness  ExperimentalBatchContextWitnesses
	absent   []byte
}

// The header signatures are public deterministic unit signatures, not original
// node signatures. The separate three-leaf proof bytes came from the selected
// original trie, using pooled ABI values rather than a single ledger snapshot.
func newBatchContextFixture(t testing.TB) batchContextFixture {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/batch-context-unit.json")
	sum := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(sum[:]) != "e4bfbdb7bff55f9719782c7e609240b2ba9aeefd0d0f42b7ee1948286e890366" {
		t.Fatal("synthetic workflow fixture changed", err)
	}
	var f batchContextFixture
	if json.Unmarshal(raw, &f) != nil || len(f.Headers) != 4 {
		t.Fatal("synthetic fixture encoding")
	}
	raw, err = os.ReadFile("../testdata/conformance/batch-context-node-witness.json")
	sum = sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(sum[:]) != "773cda402e08709ffd73adfea355f73269b1470b7336c5a027ddd5b331ab9d96" {
		t.Fatal("original three-row proof trace changed", err)
	}
	var trace struct {
		Root string `json:"root_hex"`
		Rows []struct {
			Name  string
			Proof string `json:"proof_hex"`
			Value string `json:"value_hex"`
		}
	}
	if json.Unmarshal(raw, &trace) != nil || len(trace.Rows) != 4 {
		t.Fatal("original three-row trace encoding")
	}
	decode := func(text string) []byte {
		value, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal("fixture hex", err)
		}
		return value
	}
	root := chain.Hash(decode(trace.Root))
	for i, row := range trace.Rows {
		value := proof.CandidateStateWitness{Root: root, Value: decode(row.Value), Proof: decode(row.Proof)}
		switch i {
		case 0:
			f.witness.BatchEntry = value
		case 1:
			f.witness.DomainRecord = value
		case 2:
			f.witness.DomainConfig = value
		case 3:
			f.absent = value.Proof
		}
	}
	headerPin, err := ExperimentalV3ContextFor(f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := NewExperimentalV3State(f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule, headerPin.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	envelope, state := empty.Extend(f.Headers)
	if envelope.Outcome != OutcomeAccept {
		t.Fatal(envelope)
	}
	f.state = state
	f.query, err = NewExperimentalBatchContextQuery(state, f.Config.QueryProfile, f.Request.Context)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f batchContextFixture) proofs() ExperimentalBatchContextProofs {
	return ExperimentalBatchContextProofs{f.witness.BatchEntry.Proof, f.witness.DomainRecord.Proof, f.witness.DomainConfig.Proof}
}

func TestExperimentalBatchContextOwnedWorkflowAndIndependentBytes(t *testing.T) {
	f := newBatchContextFixture(t)
	c, err := f.query.Context()
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.query.QueryWitnesses(f.Request, f.witness)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]chain.Hash{
		"schedule_hash": c.Entry.Header.ScheduleHash, "header_context": c.Entry.Header.Fingerprint,
		"entry_context": c.Entry.Fingerprint, "context": c.Fingerprint, "query": result.QueryFingerprint, "root": result.Root,
	} {
		var expected chain.Hash
		if json.Unmarshal(f.Expected[name], &expected) != nil || got != expected {
			t.Fatal("independent Python byte vector differs", name, got, expected)
		}
	}
	if result.Request != f.Request || result.Scope != "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP" ||
		result.Entry.SubmittedAtHeight != 77 || result.Entry.FinalizeAtHeight != 87 || result.DomainConfig.WithdrawalDelay != 30 ||
		result.Entry.FinalizeAtHeight == result.Entry.SubmittedAtHeight+result.DomainConfig.WithdrawalDelay ||
		result.DomainRecord.StfSpecHash == c.Entry.RuntimeIdentity || !c.RequireCanonical || !c.RequirePresent {
		t.Fatal("current context was confused with historical submission/runtime authority", result)
	}
	// The unchanged single-row API still works with its own distinct context.
	old, err := NewExperimentalBatchEntryQuery(f.state, f.Config.QueryProfile.Entry, c.Entry.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	oldRequest := ExperimentalBatchEntryRequest(f.Request)
	oldRequest.Context = c.Entry.Fingerprint
	legacy, err := old.QueryWitness(oldRequest, f.witness.BatchEntry)
	if err != nil || !reflect.DeepEqual(legacy.Entry, result.Entry) || legacy.Root != result.Root {
		t.Fatal("legacy single-row behavior changed", err)
	}
	oldRequest.Context = c.Fingerprint
	if _, err := old.QueryWitness(oldRequest, f.witness.BatchEntry); err != ErrExperimentalBatchEntryContext {
		t.Fatal("three-row context entered legacy query", err)
	}
	if _, err := NewExperimentalBatchContextQuery(f.state, f.Config.QueryProfile, c.Entry.Fingerprint); err != ErrExperimentalBatchContextPin {
		t.Fatal("legacy context entered three-row constructor", err)
	}
}

func TestExperimentalBatchContextExactIdentityAndOpaqueHandles(t *testing.T) {
	f := newBatchContextFixture(t)
	for name, change := range map[string]func(*ExperimentalBatchContextRequest){
		"zero-context":      func(r *ExperimentalBatchContextRequest) { r.Context = chain.Hash{} },
		"different-context": func(r *ExperimentalBatchContextRequest) { r.Context[0] ^= 1 },
		"legacy-context":    func(r *ExperimentalBatchContextRequest) { r.Context = f.query.data.context.Entry.Fingerprint },
		"unretained-height": func(r *ExperimentalBatchContextRequest) { r.Height = 87; r.HeaderHash = f.Headers[0].Header.HeaderHash },
		"tip-not-deep":      func(r *ExperimentalBatchContextRequest) { r.Height = 90; r.HeaderHash = r.TipHash },
		"wrong-header":      func(r *ExperimentalBatchContextRequest) { r.HeaderHash[0] ^= 1 },
		"zero-header":       func(r *ExperimentalBatchContextRequest) { r.HeaderHash = chain.Hash{} },
		"wrong-height":      func(r *ExperimentalBatchContextRequest) { r.Height = 88 },
		"wrong-tip-height":  func(r *ExperimentalBatchContextRequest) { r.TipHeight-- },
		"wrong-tip-hash":    func(r *ExperimentalBatchContextRequest) { r.TipHash[0] ^= 1 },
		"wrong-batch-key":   func(r *ExperimentalBatchContextRequest) { r.BatchID = 9 },
	} {
		t.Run(name, func(t *testing.T) {
			r := f.Request
			change(&r)
			result, err := f.query.QueryWitnesses(r, f.witness)
			if err == nil || !reflect.DeepEqual(result, ExperimentalBatchContextResult{}) {
				t.Fatal("identity supplied a partial row", err)
			}
		})
	}
	var zero ExperimentalBatchContextQuery
	if _, err := zero.Context(); err != ErrUninitializedState {
		t.Fatal(err)
	}
	if result, err := zero.Query(f.Request, f.proofs()); err != ErrUninitializedState || !reflect.DeepEqual(result, ExperimentalBatchContextResult{}) {
		t.Fatal(err)
	}
	if _, err := json.Marshal(f.query); err == nil {
		t.Fatal("opaque query serialized")
	}
	before := f.query
	if json.Unmarshal([]byte("{}"), &f.query) != ErrExperimentalBatchContextOpaque || f.query != before {
		t.Fatal("caller replaced opaque query")
	}
	empty, err := NewExperimentalV3State(f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule, f.query.data.context.Entry.Header.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewExperimentalBatchContextQuery(empty, f.Config.QueryProfile, f.Request.Context); err != ErrExperimentalV3HeaderUnavailable {
		t.Fatal(err)
	}
}

func TestExperimentalBatchContextHintsAndLateFailure(t *testing.T) {
	f := newBatchContextFixture(t)
	for index := 0; index < 3; index++ {
		for _, kind := range []string{"root", "value", "missing-proof", "missing-value", "substituted-proof", "oversized-value", "oversized-proof"} {
			t.Run(string(rune('0'+index))+"/"+kind, func(t *testing.T) {
				w := f.witness
				selected := []*proof.CandidateStateWitness{&w.BatchEntry, &w.DomainRecord, &w.DomainConfig}[index]
				selected.Value = bytes.Clone(selected.Value)
				selected.Proof = bytes.Clone(selected.Proof)
				switch kind {
				case "root":
					selected.Root[0] ^= 1
				case "value":
					selected.Value[0] ^= 1
				case "missing-proof":
					selected.Proof = nil
				case "missing-value":
					selected.Value = nil
				case "substituted-proof":
					selected.Proof = f.witness.BatchEntry.Proof
					if index == 0 {
						selected.Proof = f.witness.DomainRecord.Proof
					}
				case "oversized-value":
					selected.Value = make([]byte, 4097)
				case "oversized-proof":
					selected.Proof = make([]byte, proof.CandidateSMTMaxProofBytes+1)
				}
				result, err := f.query.QueryWitnesses(f.Request, w)
				if err == nil || !reflect.DeepEqual(result, ExperimentalBatchContextResult{}) {
					t.Fatal("failed last hint returned a consumer result", err)
				}
			})
		}
	}
	result, err := f.query.QueryWitnesses(f.Request, f.witness)
	if err != nil || result.DomainConfig.RuntimeUpgradeDelay != 64 {
		t.Fatal("failure damaged captured query", err)
	}
	// Caller inputs, detached raw memberships, typed buffers and trust facts
	// cannot alter the frozen query or another result.
	result.BatchMembership.Value[0] ^= 1
	result.Entry.AssetFlowSummary[0] ^= 1
	result.HeaderTrust[0] = "caller mutation"
	next, err := f.query.QueryWitnesses(f.Request, f.witness)
	if err != nil || !bytes.Equal(next.BatchMembership.Value, f.witness.BatchEntry.Value) ||
		bytes.Equal(next.Entry.AssetFlowSummary, result.Entry.AssetFlowSummary) || reflect.DeepEqual(next.HeaderTrust, result.HeaderTrust) {
		t.Fatal("detached result changed another query", err)
	}
}

func TestExperimentalBatchContextInclusiveBounds(t *testing.T) {
	f := newBatchContextFixture(t)
	base := f.Config.QueryProfile
	base.Limits = ExperimentalBatchContextLimits{MaxTotalProofBytes: 1781, MaxTotalValueBytes: 1312, MaxTotalSiblings: 5}
	for name, change := range map[string]func(*ExperimentalBatchContextProfile){
		"exact": func(p *ExperimentalBatchContextProfile) {
			p.Entry.MaxProofBytes = 967
			p.DomainRecord.MaxProofBytes = 615
			p.DomainConfig.MaxProofBytes = 199
		},
		"entry-proof":  func(p *ExperimentalBatchContextProfile) { p.Entry.MaxProofBytes = 966 },
		"record-proof": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxProofBytes = 614 },
		"config-proof": func(p *ExperimentalBatchContextProfile) { p.DomainConfig.MaxProofBytes = 198 },
		"entry-value": func(p *ExperimentalBatchContextProfile) {
			p.Entry.Limits.MaxValueBytes = 799
			p.Entry.Limits.MaxDynamicBytes = 700
			p.Entry.Limits.MaxAssetFlowSummaryBytes = 700
			p.Entry.Limits.MaxProofDataBytes = 700
		},
		"entry-siblings":  func(p *ExperimentalBatchContextProfile) { p.Entry.MaxSiblings = 1 },
		"record-siblings": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxSiblings = 1 },
		"config-siblings": func(p *ExperimentalBatchContextProfile) { p.DomainConfig.MaxSiblings = 0 },
		"total-proof":     func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalProofBytes-- },
		"total-value":     func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalValueBytes-- },
		"total-siblings":  func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalSiblings-- },
		"zero-siblings":   func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalSiblings = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			change(&p)
			c, err := ExperimentalBatchContextFor(f.state, p)
			if err != nil {
				t.Fatal(err)
			}
			q, err := NewExperimentalBatchContextQuery(f.state, p, c.Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			r := f.Request
			r.Context = c.Fingerprint
			result, err := q.QueryWitnesses(r, f.witness)
			if name == "exact" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, proof.ErrCandidateSMTBounds) || !reflect.DeepEqual(result, ExperimentalBatchContextResult{}) {
				t.Fatal("work cap was not inclusive", err)
			}
		})
	}
}

func noncanonicalBatchContextProof(raw []byte) []byte {
	// Add an explicitly encoded zero sibling at the first unused low level.
	bitmap := bytes.Clone(raw[65:97])
	level := 0
	for bitmap[level/8]&(1<<uint(7-level%8)) != 0 {
		level++
	}
	bitmap[level/8] |= 1 << uint(7-level%8)
	n := int(binary.BigEndian.Uint16(raw[97:99]))
	next := append(bytes.Clone(raw[:65]), bitmap...)
	next = append(next, byte((n+1)>>8), byte(n+1))
	next = append(next, raw[99:99+level*32]...)
	next = append(next, make([]byte, 32)...)
	return append(next, raw[99+level*32:]...)
}

func TestExperimentalBatchContextCanonicalPresenceAndRule(t *testing.T) {
	f := newBatchContextFixture(t)
	for i := 0; i < 3; i++ {
		t.Run("noncanonical-"+string(rune('0'+i)), func(t *testing.T) {
			p := f.proofs()
			selected := []*[]byte{&p.BatchEntry, &p.DomainRecord, &p.DomainConfig}[i]
			*selected = noncanonicalBatchContextProof(*selected)
			result, err := f.query.Query(f.Request, p)
			if err != ErrExperimentalBatchEntryCanonical || !reflect.DeepEqual(result, ExperimentalBatchContextResult{}) {
				t.Fatal(err)
			}
		})
	}
	r := f.Request
	r.BatchID = 1
	p := f.proofs()
	p.BatchEntry = f.absent
	if result, err := f.query.Query(r, p); err != ErrExperimentalBatchContextRequiredRows || !reflect.DeepEqual(result, ExperimentalBatchContextResult{}) {
		t.Fatal("absence became typed value", err)
	}
	result, err := f.query.Query(f.Request, f.proofs())
	if err != nil {
		t.Fatal(err)
	}
	record := result.DomainRecord
	for name, change := range map[string]func(*proof.CandidateDomainRecord){
		"class": func(r *proof.CandidateDomainRecord) { r.DomainClass = 1 }, "runtime": func(r *proof.CandidateDomainRecord) { r.RuntimeKind = 1 },
		"input": func(r *proof.CandidateDomainRecord) { r.InputSource = 1 }, "exec": func(r *proof.CandidateDomainRecord) { r.ExecProfile = 1 },
		"foreign": func(r *proof.CandidateDomainRecord) { r.ForeignProfile = 1 }, "executors": func(r *proof.CandidateDomainRecord) { r.MinExecutors = 2 },
		"proposer": func(r *proof.CandidateDomainRecord) { r.ProposerPolicy = 1 }, "finality": func(r *proof.CandidateDomainRecord) { r.FinalityModel = 1 },
		"status": func(r *proof.CandidateDomainRecord) { r.Status = 2 }, "profile-config": func(r *proof.CandidateDomainRecord) { r.ProfileConfig = []byte{1} },
		"chain-binding": func(r *proof.CandidateDomainRecord) { r.ChainBinding = []byte{1} },
	} {
		t.Run(name, func(t *testing.T) {
			next := record
			change(&next)
			if experimentalPhase1DomainRecord(next) {
				t.Fatal("source rule broadened")
			}
		})
	}
	record.Status = 1
	if !experimentalPhase1DomainRecord(record) {
		t.Fatal("paused source record refused")
	}
	result.Entry.ExecutorPillar = string([]byte{0xff})
	if _, err := json.Marshal(result); err == nil {
		t.Fatal("opaque string silently replaced")
	}
}

func TestExperimentalBatchContextRequiredRowsNoAbsenceFallback(t *testing.T) {
	// Pure policy controls after mathematical matching, not header/proof
	// authentication. The exported query's valid target-absence fixture above
	// additionally exercises the complete owned-state composition.
	present := []proof.CandidateSMTMatch{
		{Present: true, Canonical: true}, {Present: true, Canonical: true}, {Present: true, Canonical: true},
	}
	if err := requireExperimentalBatchContextRows(present); err != nil {
		t.Fatal(err)
	}
	for i := range present {
		t.Run("required-row-"+string(rune('0'+i)), func(t *testing.T) {
			matches := append([]proof.CandidateSMTMatch(nil), present...)
			matches[i].Present = false
			err := requireExperimentalBatchContextRows(matches)
			if err != ErrExperimentalBatchContextRequiredRows || errors.Is(err, ErrExperimentalBatchEntryAbsent) {
				t.Fatal("a required context row became application BatchEntry absence", err)
			}
		})
	}
	if err := requireExperimentalBatchContextRows(present[:2]); err != proof.ErrCandidateSMTEncoding {
		t.Fatal("partial match set became a complete typed query", err)
	}
}

func TestExperimentalBatchContextRestorePruningAndGateway(t *testing.T) {
	f := newBatchContextFixture(t)
	path := filepath.Join(t.TempDir(), "owned-state.json")
	if err := f.state.Save(path); err != nil {
		t.Fatal(err)
	}
	c := f.query.data.context
	restored, err := LoadTrustedExperimentalV3State(path, f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule, c.Entry.Header.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewExperimentalBatchContextQuery(restored, f.Config.QueryProfile, c.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	result, err := query.QueryWitnesses(f.Request, f.witness)
	if err != nil {
		t.Fatal(err)
	}
	original, err := f.query.QueryWitnesses(f.Request, f.witness)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Entry, original.Entry) || result.Root != original.Root ||
		result.QueryFingerprint != original.QueryFingerprint || result.Context != original.Context ||
		result.DomainConfig != original.DomainConfig || !reflect.DeepEqual(result.DomainRecord, original.DomainRecord) {
		t.Fatal("restored query differs from the original consumer result")
	}
	found := false
	for _, trust := range result.HeaderTrust {
		found = found || trust == TrustPersistedState
	}
	if !found {
		t.Fatal("persisted-state trust omitted")
	}
	gateway := proof.CandidateSettlementBatch{DomainID: 1, BatchID: 0, Entry: result.Entry, IsFinalized: true}
	before := experimentalV3JSON(t, result)
	match := result.CompareGateway(gateway)
	if !match.StoredFieldsMatch || !match.FrontierIsFinalizedHint || match.FrontierIdentityAuthenticated {
		t.Fatal(match)
	}
	gateway.Entry.FinalizeAtHeight++
	mismatch := result.CompareGateway(gateway)
	if mismatch.StoredFieldsMatch || mismatch.FrontierIdentityAuthenticated || !bytes.Equal(before, experimentalV3JSON(t, result)) {
		t.Fatal("frontier changed historical proof result")
	}
	// A handle captured before a later extension keeps its original tip.
	empty, err := NewExperimentalV3State(f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule, c.Entry.Header.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	env, earlier := empty.Extend(f.Headers[:2])
	if env.Outcome != OutcomeAccept {
		t.Fatal(env)
	}
	old, err := NewExperimentalBatchContextQuery(earlier, f.Config.QueryProfile, c.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request := f.Request
	request.Height = 87
	request.HeaderHash = f.Headers[0].Header.HeaderHash
	request.TipHeight = 88
	request.TipHash = f.Headers[1].Header.HeaderHash
	if _, err := old.QueryWitnesses(request, f.witness); err != nil {
		t.Fatal(err)
	}
	if next, err := query.QueryWitnesses(request, f.witness); err == nil || !reflect.DeepEqual(next, ExperimentalBatchContextResult{}) {
		t.Fatal("retained/tip scope broadened")
	}
}

func TestExperimentalBatchContextStrictProfilesAndRequests(t *testing.T) {
	f := newBatchContextFixture(t)
	for kind, raw := range map[string][]byte{
		"profile": experimentalV3JSON(t, f.Config.QueryProfile), "record": experimentalV3JSON(t, f.Config.QueryProfile.DomainRecord),
		"config": experimentalV3JSON(t, f.Config.QueryProfile.DomainConfig), "totals": experimentalV3JSON(t, f.Config.QueryProfile.Limits),
		"request": experimentalV3JSON(t, f.Request),
	} {
		for field := range experimentalV3Fields(t, raw) {
			for _, change := range []string{"missing", "null", "duplicate", "alias"} {
				t.Run(kind+"/"+field+"/"+change, func(t *testing.T) {
					fields := experimentalV3Fields(t, raw)
					switch change {
					case "missing":
						delete(fields, field)
					case "null":
						fields[field] = json.RawMessage("null")
					case "alias":
						fields[strings.ToUpper(field)] = fields[field]
						delete(fields, field)
					}
					bad := experimentalV3JSON(t, fields)
					if change == "duplicate" {
						bad = append(bad[:len(bad)-1], ',')
						bad = append(bad, experimentalV3JSON(t, field)...)
						bad = append(bad, ':')
						bad = append(bad, fields[field]...)
						bad = append(bad, '}')
					}
					var target any
					switch kind {
					case "profile":
						v := f.Config.QueryProfile
						target = &v
					case "record":
						v := f.Config.QueryProfile.DomainRecord
						target = &v
					case "config":
						v := f.Config.QueryProfile.DomainConfig
						target = &v
					case "totals":
						v := f.Config.QueryProfile.Limits
						target = &v
					case "request":
						v := f.Request
						target = &v
					}
					before := experimentalV3JSON(t, target)
					if json.Unmarshal(bad, target) == nil || !bytes.Equal(before, experimentalV3JSON(t, target)) {
						t.Fatal("ambiguous input changed receiver")
					}
				})
			}
		}
	}
	for _, raw := range [][]byte{append(experimentalV3JSON(t, f.Config.QueryProfile), []byte("{}")...), bytes.Repeat([]byte(" "), MaxExperimentalBatchEntryProfileBytes+1), []byte("null")} {
		if _, err := DecodeExperimentalBatchContextProfile(raw); err == nil {
			t.Fatal("unbounded or invalid profile")
		}
	}
	if _, err := DecodeExperimentalBatchContextRequest(bytes.Repeat([]byte(" "), 2049)); err == nil {
		t.Fatal("request cap bypassed")
	}
}

func TestExperimentalBatchContextPolicyFingerprintAndBounds(t *testing.T) {
	f := newBatchContextFixture(t)
	base := f.Config.QueryProfile
	for name, change := range map[string]func(*ExperimentalBatchContextProfile){
		"entry-proof": func(p *ExperimentalBatchContextProfile) { p.Entry.MaxProofBytes-- }, "entry-siblings": func(p *ExperimentalBatchContextProfile) { p.Entry.MaxSiblings-- },
		"record-proof": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxProofBytes-- }, "record-siblings": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxSiblings-- },
		"record-value": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxValueBytes-- }, "record-profile": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxProfileConfigBytes-- },
		"record-binding": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxChainBindingBytes-- }, "record-dynamic": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxDynamicBytes-- },
		"config-proof": func(p *ExperimentalBatchContextProfile) { p.DomainConfig.MaxProofBytes-- }, "config-siblings": func(p *ExperimentalBatchContextProfile) { p.DomainConfig.MaxSiblings-- },
		"total-proof": func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalProofBytes-- }, "total-value": func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalValueBytes-- },
		"total-siblings": func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalSiblings-- }, "domain": func(p *ExperimentalBatchContextProfile) { p.Entry.DomainID++ },
		"runtime-metadata": func(p *ExperimentalBatchContextProfile) { p.Entry.RuntimeIdentity[0] ^= 1 },
	} {
		t.Run("pin/"+name, func(t *testing.T) {
			p := base
			change(&p)
			c, err := ExperimentalBatchContextFor(f.state, p)
			if err != nil || c.Fingerprint == f.Request.Context {
				t.Fatal("policy not bound", err)
			}
			if _, err := NewExperimentalBatchContextQuery(f.state, p, f.Request.Context); err != ErrExperimentalBatchContextPin {
				t.Fatal(err)
			}
		})
	}
	for name, change := range map[string]func(*ExperimentalBatchContextProfile){
		"version": func(p *ExperimentalBatchContextProfile) { p.Version = 2 }, "domain-zero": func(p *ExperimentalBatchContextProfile) { p.Entry.DomainID = 0 },
		"rule": func(p *ExperimentalBatchContextProfile) { p.DomainRule += "?" }, "overflow-record": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxProofBytes = ^uint32(0) },
		"overflow-config": func(p *ExperimentalBatchContextProfile) { p.DomainConfig.MaxProofBytes = ^uint32(0) }, "overflow-total": func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalValueBytes = ^uint32(0) },
		"record-short": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxValueBytes = 447 }, "config-long": func(p *ExperimentalBatchContextProfile) { p.DomainConfig.MaxProofBytes = 8360 },
		"record-disabled": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxDynamicBytes = 0 }, "record-siblings": func(p *ExperimentalBatchContextProfile) { p.DomainRecord.MaxSiblings = 257 },
		"config-siblings": func(p *ExperimentalBatchContextProfile) { p.DomainConfig.MaxSiblings = 257 }, "total-disabled": func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalProofBytes = 0 },
		"total-min": func(p *ExperimentalBatchContextProfile) { p.Limits.MaxTotalValueBytes = 1151 },
	} {
		t.Run("invalid/"+name, func(t *testing.T) {
			p := base
			change(&p)
			if p.Validate() != ErrExperimentalBatchContextProfile {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	base.Entry.Source = "private-label-marker"
	c, err := ExperimentalBatchContextFor(f.state, base)
	if err != nil || c.Fingerprint != f.Request.Context || bytes.Contains(experimentalV3JSON(t, c), []byte("private-label-marker")) {
		t.Fatal("provenance became authority", err)
	}
	base.Entry.DomainID = 0
	if base.Entry.Validate() != nil {
		t.Fatal("legacy domain-zero behavior changed")
	}
}

func BenchmarkExperimentalBatchContextQuery(b *testing.B) {
	f := newBatchContextFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.query.QueryWitnesses(f.Request, f.witness); err != nil {
			b.Fatal(err)
		}
	}
}
