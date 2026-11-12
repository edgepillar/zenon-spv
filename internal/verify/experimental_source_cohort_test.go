// SPDX-License-Identifier: MIT

package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestExperimentalV3SourceCohortSelection(t *testing.T) {
	f := experimentalV3Inputs(t)
	for _, revision := range []string{ExperimentalV3NodeRevision, ExperimentalV3ReferenceGasNodeRevision} {
		t.Run(revision, func(t *testing.T) {
			profile := f.profile
			profile.NodeRevision = revision
			decoded, err := DecodeExperimentalV3Profile(experimentalV3JSON(t, profile))
			if err != nil || decoded != profile {
				t.Fatal("explicit source selection did not round trip", err)
			}
			profile.Genesis.ChainID, profile.Anchor.ChainID = MainnetChainID, MainnetChainID
			if !errors.Is(profile.Validate(), ErrExperimentalV3Profile) {
				t.Fatal("source support entered the mainnet profile")
			}
		})
	}
	for _, revision := range []string{"", "main", strings.Repeat("0", 40),
		"f89d645c7f5be85dfe10dc7a510d80df7965d22f", // A Git tree is not a selected commit.
		strings.ToUpper(ExperimentalV3ReferenceGasNodeRevision),
		ExperimentalV3ReferenceGasNodeRevision + " ", "2835c43"} {
		profile := f.profile
		profile.NodeRevision = revision
		if !errors.Is(profile.Validate(), ErrExperimentalV3Profile) {
			t.Fatal("unsupported source selection accepted", revision)
		}
		if _, err := DecodeExperimentalV3Profile(experimentalV3JSON(t, profile)); !errors.Is(err, ErrExperimentalV3Profile) {
			t.Fatal("unsupported encoded source selection accepted", err)
		}
	}
}

func TestExperimentalReferenceGasBatchContextAndCheckpoint(t *testing.T) {
	// Replay existing synthetic header/ABI witnesses under an explicit new source
	// selection. This does not recapture signatures, receipts or a devnet query.
	f := newBatchContextFixture(t)
	before, err := f.query.QueryWitnesses(f.Request, f.witness)
	if err != nil {
		t.Fatal(err)
	}
	oldContext, err := f.query.Context()
	if err != nil {
		t.Fatal(err)
	}
	oldRaw := batchCheckpointBytes(t, f)
	oldProfile := f.Config.HeaderProfile
	profile := oldProfile
	profile.NodeRevision = ExperimentalV3ReferenceGasNodeRevision
	settings, err := PrepareExperimentalV3Configuration(profile, f.Config.HeaderPolicy, f.Config.Schedule)
	if err != nil {
		t.Fatal(err)
	}
	header := settings.Context()
	if state, err := settings.NewState(oldContext.Entry.Header.Fingerprint); !errors.Is(err, ErrContextFingerprintMismatch) || state.data != nil {
		t.Fatal("old source pin entered the new header context", err)
	}
	empty, err := settings.NewState(header.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	envelope, state := empty.Extend(f.Headers)
	if envelope.Outcome != OutcomeAccept || !empty.Empty() {
		t.Fatal("source-selected replay failed or mutated its input", envelope)
	}
	context, err := ExperimentalBatchContextFor(state, f.Config.QueryProfile)
	if err != nil || context.Entry.ExecutorRevision != ExperimentalBatchEntryReferenceGasExecutorRevision ||
		context.Entry.SDKRevision != ExperimentalBatchEntrySDKRevision ||
		oldContext.Entry.ExecutorRevision != ExperimentalBatchEntryExecutorRevision {
		t.Fatal("node/executor source pair changed", err)
	}
	// Independent hashlib/struct framing over the unchanged public unit fixture:
	// 243 header bytes, 302 single-row bytes and 310 three-row bytes.
	for actual, expected := range map[chain.Hash]string{
		header.Fingerprint:        "539dbc070da4f32ecf17a9b6fb6750849cfa94486986095ffccb936f195ee397",
		context.Entry.Fingerprint: "1b87299ca02ada9244e001a3413844998692d5f81f4084616c16445a64f1e978",
		context.Fingerprint:       "29dc0740c26bfaffc4672d5a576ef8b6960174abb166d00d76155282b50dd596",
	} {
		if hex.EncodeToString(actual[:]) != expected {
			t.Fatal("independent context byte vector differs", actual, expected)
		}
	}
	if context.Fingerprint == oldContext.Fingerprint || context.Entry.Fingerprint == oldContext.Entry.Fingerprint {
		t.Fatal("source cohorts share a query context")
	}
	if _, err := NewExperimentalBatchContextQuery(state, f.Config.QueryProfile, f.Request.Context); !errors.Is(err, ErrExperimentalBatchContextPin) {
		t.Fatal("old three-row pin entered the new constructor", err)
	}
	if _, err := NewExperimentalBatchEntryQuery(state, f.Config.QueryProfile.Entry, oldContext.Entry.Fingerprint); !errors.Is(err, ErrExperimentalBatchEntryContext) {
		t.Fatal("old single-row pin entered the new constructor", err)
	}
	query, err := NewExperimentalBatchContextQuery(state, f.Config.QueryProfile, context.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := query.QueryWitnesses(f.Request, f.witness); !errors.Is(err, ErrExperimentalBatchContextPin) {
		t.Fatal("old request entered the new cohort", err)
	}
	request := f.Request
	request.Context = context.Fingerprint
	if _, err := f.query.QueryWitnesses(request, f.witness); !errors.Is(err, ErrExperimentalBatchContextPin) {
		t.Fatal("new request entered the old cohort", err)
	}
	after, err := query.QueryWitnesses(request, f.witness)
	if err != nil || after.Root != before.Root || !reflect.DeepEqual(after.Entry, before.Entry) ||
		!reflect.DeepEqual(after.DomainRecord, before.DomainRecord) || !reflect.DeepEqual(after.DomainConfig, before.DomainConfig) ||
		after.QueryFingerprint == before.QueryFingerprint {
		t.Fatal("explicit source replay changed stored fields or reused query identity", err)
	}
	// Save/load uses the exact new selection; checkpoint bytes and context pins
	// from either source are refused by the other source's prepared state.
	f.state = state
	newRaw := batchCheckpointBytes(t, f)
	for _, attempt := range []struct {
		raw     []byte
		profile ExperimentalV3Profile
		pin     chain.Hash
	}{
		{oldRaw, profile, header.Fingerprint},
		{newRaw, oldProfile, oldContext.Entry.Header.Fingerprint},
	} {
		if restored, err := DecodePinnedTrustedExperimentalV3State(attempt.raw, attempt.profile, f.Config.HeaderPolicy, f.Config.Schedule, attempt.pin, sha256.Sum256(attempt.raw)); err == nil || restored.data != nil {
			t.Fatal("checkpoint crossed source selections", err)
		}
	}
	resumed, err := empty.DecodePinnedTrustedCheckpoint(newRaw, sha256.Sum256(newRaw))
	if err != nil || resumed.data == nil || !resumed.data.trustedLocal {
		t.Fatal("new source checkpoint did not resume", err)
	}
	resumedQuery, err := NewExperimentalBatchContextQuery(resumed, f.Config.QueryProfile, context.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resumedQuery.QueryWitnesses(request, f.witness)
	if err != nil || !reflect.DeepEqual(got.Entry, after.Entry) || got.QueryFingerprint != after.QueryFingerprint {
		t.Fatal("new source checkpoint changed the typed query", err)
	}
}
