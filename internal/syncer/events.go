package syncer

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// watchEvent is a local observation, not a proof receipt. StateTip identifies
// the in-memory retained state, which can differ from the file after a save
// error following replacement. Verification never implies successful saving.
// Keep free-form errors, provenance labels, paths, and peer URLs out of it.
type watchEvent struct {
	SchemaVersion           uint32                     `json:"schema_version"`
	Command                 string                     `json:"command"`
	Event                   string                     `json:"event"`
	StateTip                chain.HashHeight           `json:"state_tip"`
	PreviousTipHeight       *uint64                    `json:"previous_tip_height"`
	CandidateTip            *chain.HashHeight          `json:"candidate_tip"`
	TargetHeight            *uint64                    `json:"target_height"`
	FetchedCount            int                        `json:"fetched_count"`
	Reason                  *string                    `json:"reason"`
	Persistence             string                     `json:"persistence"`
	ConsecutiveSaveFailures int                        `json:"consecutive_save_failures"`
	Error                   *watchError                `json:"error"`
	Verification            *watchVerification         `json:"verification"`
	Context                 verify.VerificationContext `json:"verification_context"`
	StateTrust              []verify.TrustAssumption   `json:"state_trust"`
	SourceTrust             []verify.TrustAssumption   `json:"source_trust"`
	Settings                *watchSettings             `json:"settings"`
	Caveats                 []string                   `json:"caveats"`
}

type watchError struct {
	Stage    string `json:"stage"`
	Category string `json:"category"`
}

type watchVerification struct {
	Outcome          string                   `json:"outcome"`
	Reason           string                   `json:"reason"`
	FailedAt         int                      `json:"failed_at"`
	Proven           []verify.Guarantee       `json:"proven"`
	NotProven        []verify.Guarantee       `json:"not_proven"`
	TrustAssumptions []verify.TrustAssumption `json:"trust_assumptions"`
}

type watchSettings struct {
	Peers                int    `json:"peers"`
	Quorum               int    `json:"quorum"`
	Interval             string `json:"interval"`
	SafetyMargin         uint64 `json:"safety_margin"`
	BatchSize            uint64 `json:"batch_size"`
	MaxStateSaveFailures int    `json:"max_state_save_failures"`
}

func (l *Loop) logStartup(state verify.VerifiedState, maxSaveFailures int) error {
	if l.JSON {
		quorum := l.Multi.Quorum
		if quorum == 0 {
			quorum = len(l.Multi.Peers)
		}
		return l.logEvent(state, watchEvent{Event: "started", Persistence: "not_attempted",
			Settings: &watchSettings{Peers: len(l.Multi.Peers), Quorum: quorum,
				Interval: l.Interval.String(), SafetyMargin: l.SafetyMargin,
				BatchSize: l.BatchSize, MaxStateSaveFailures: maxSaveFailures}})
	}
	tip, _ := state.Tip()
	if err := l.logf("watching: tip=%d, peers=%d, quorum=%d, interval=%s\n",
		tip.Height, len(l.Multi.Peers), l.Multi.Quorum, l.Interval); err != nil {
		return err
	}
	if err := l.logf("state: trust_assumptions=%v\n", state.TrustAssumptions()); err != nil {
		return err
	}
	if l.ShowContext {
		raw, err := state.VerificationContextJSON()
		if err != nil {
			return fmt.Errorf("verification context: %w", err)
		}
		return l.logf("verification_context: %s\n", raw)
	}
	return nil
}

func (l *Loop) logIteration(r TickResult, state verify.VerifiedState, saveErr error, saveFailures, maxSaveFailures int) error {
	if !l.JSON {
		if saveErr != nil {
			return l.logf("state: save failed (%d/%d), retaining tip=%d: %v\n",
				saveFailures, maxSaveFailures, r.Tip, saveErr)
		}
		return l.logTick(r)
	}
	event := watchEvent{PreviousTipHeight: &r.Tip, CandidateTip: r.candidateTip,
		FetchedCount: len(r.FetchedHeights), Persistence: "not_attempted",
		ConsecutiveSaveFailures: saveFailures}
	reason := r.Reason.String()
	event.Reason = &reason
	if r.Target != 0 {
		event.TargetHeight = &r.Target
	}
	if v := r.verification; v != nil {
		event.Verification = &watchVerification{Outcome: v.Outcome.String(), Reason: v.Reason.String(), FailedAt: v.FailedAt,
			Proven: append([]verify.Guarantee{}, v.Proven...), NotProven: append([]verify.Guarantee{}, v.NotProven...),
			TrustAssumptions: append([]verify.TrustAssumption{}, v.TrustAssumptions...)}
	}
	switch {
	case saveErr != nil:
		event.Event, event.Persistence = "save_failed", "failed"
		event.Error = &watchError{Stage: "persistence", Category: "operational"}
	case r.Outcome == verify.OutcomeAccept:
		event.Event, event.Persistence = "advanced", "saved"
		if len(r.FetchedHeights) == 0 {
			event.Event = "caught_up"
		}
	case r.Outcome == verify.OutcomeReject:
		event.Event = "rejected"
	default:
		event.Event = "refused"
	}
	if r.failureStage != "" {
		category := "unavailable"
		switch {
		case errors.Is(r.Err, fetch.ErrNotEnoughPeers):
			category = "quorum_unavailable"
		case errors.Is(r.Err, fetch.ErrPeerDisagreement):
			category = "peer_disagreement"
		}
		event.Error = &watchError{Stage: r.failureStage, Category: category}
	}
	return l.logEvent(state, event)
}

func (l *Loop) logEvent(state verify.VerifiedState, event watchEvent) error {
	if l.Out == nil {
		return nil
	}
	context, err := state.VerificationContext()
	if err != nil {
		return err
	}
	tip, _ := state.Tip()
	event.SchemaVersion, event.Command = 1, "watch"
	event.StateTip = chain.HashHeight{Hash: tip.HeaderHash, Height: tip.Height}
	event.Context = context
	event.StateTrust = append([]verify.TrustAssumption{}, state.TrustAssumptions()...)
	event.SourceTrust = []verify.TrustAssumption{verify.TrustRPCQuorum}
	event.Caveats = []string{
		"Local diagnostics do not prove consensus finality or state values.",
		"Peer agreement does not authenticate independence, network identity, canonicality, or freshness.",
		"Caught-up status is relative to configured peers and does not verify new headers.",
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return &outputFailure{cause: err}
	}
	return l.writeOutput(append(raw, '\n'))
}
