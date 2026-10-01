// Package syncer turns the SPV verifier into a long-running service.
//
// A Loop ticks at the configured interval, multi-peer-fetches the
// frontier, computes a conservative target height (median(frontiers) -
// safety_margin), fetches the next batch of momentums extending the
// persisted retained-window tip, and runs VerifyHeaders. On ACCEPT
// the updated state is persisted via SaveHeaderState before advancing
// in memory or logging ACCEPT. Repeated save failures stop the loop;
// REJECT or REFUSED leave the state file unchanged (Phase 4 invariant).
//
// The transport is the existing internal/fetch.MultiClient (HTTPS
// JSON-RPC with k-of-n agreement). A future libp2p/WebRTC backend
// can swap MultiClient for a different concrete type without
// changing the loop's structure — but no abstract Transport
// interface is introduced today, since premature abstraction over
// a single implementation costs more than it pays.
//
// The loop never re-anchors from genesis: it requires the state file
// to have a non-empty retained window (or a fresh state initialized
// from a recent checkpoint via --genesis-config). Re-anchoring would
// imply skipping ~13M momentums on faith, which is exactly what the
// verifier is designed to refuse.
package syncer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Loop is the configuration for a watch-mode run.
type Loop struct {
	// ShowContext logs captured verification settings once at startup. The
	// diagnostic excludes peer URLs, file paths, and free-form profile Source.
	ShowContext bool

	// Multi is the multi-peer client. May be a MultiClient with a
	// single peer (degenerate but valid) or many peers with a quorum.
	Multi *fetch.MultiClient

	// StatePath is required: the loop must persist on every ACCEPT
	// or the service is no better than running verify-headers in a
	// shell loop.
	StatePath string

	// Genesis is the trust root at startup. If a state file exists
	// at StatePath, it must declare the same Genesis or the loop
	// refuses to start.
	Genesis verify.GenesisTrustRoot

	// Policy controls the retained-window depth W and any other
	// per-iteration limits.
	Policy verify.Policy

	// Authorizer enables Branch 5b producer-auth checks when non-nil.
	// nil keeps legacy Disabled-mode behavior (the per-tick log
	// remains structurally identical for machine consumers).
	Authorizer verify.ProducerAuthorizer

	// Interval is the time between ticks. 10s is the natural cadence
	// (one momentum). Zero selects the default; negative values are invalid.
	Interval time.Duration

	// SafetyMargin is the number of momentums below median(frontiers)
	// the loop refuses to fetch, allowing peers time to catch up without
	// guaranteeing availability. Zero selects the default of six.
	SafetyMargin uint64

	// BatchSize caps how many headers are fetched per tick. At quiet
	// times the loop fetches just the new tip+1..target; at catch-up
	// time it can be limited to keep memory bounded. Zero selects 60 in Run.
	// A positive Policy.MaxHeaders additionally caps each incoming batch.
	BatchSize uint64

	// Out receives startup and per-tick logs. nil discards. A write error or
	// short write stops Run; an earlier successful state save is not rolled back.
	Out io.Writer

	// JSON selects versioned JSON Lines events on Out instead of text logs.
	// Events exclude arbitrary error text and separate verification from saving.
	// Context is included in every event, regardless of ShowContext.
	JSON bool

	// MaxStateSaveFailures bounds consecutive failed save attempts.
	// Zero selects the default of three; negative values are invalid.
	MaxStateSaveFailures int

	// SaveState overrides persistence for embedding and fault injection.
	// nil uses verify.SaveHeaderState. An override must return success
	// only after completing its persistence contract. It receives a detached
	// snapshot, so retaining or mutating it cannot change loop state.
	SaveState func(string, verify.HeaderState) error
}

// Defaults
const (
	DefaultInterval             = 10 * time.Second
	DefaultSafetyMargin         = uint64(6)
	DefaultBatchSize            = uint64(60)
	DefaultMaxStateSaveFailures = 3
)

// TickResult describes the outcome of a single iteration.
type TickResult struct {
	Tip            uint64
	Target         uint64
	FetchedHeights []uint64
	Outcome        verify.Outcome
	Reason         verify.ReasonCode
	Message        string
	Err            error
	verification   *verify.Result
	candidateTip   *chain.HashHeight
	failureStage   string
}

// Run executes the loop until ctx is cancelled. Returns nil on
// graceful shutdown (ctx.Done) and a non-nil error on unrecoverable
// setup failure or MaxStateSaveFailures consecutive failed save
// attempts, or on a startup/tick output failure. A successful save resets
// the counter. Output failures do not roll back completed saves. Verification
// failures (REJECT/REFUSED) remain nonfatal when reporting succeeds.
func (l *Loop) Run(ctx context.Context) (runErr error) {
	saveState := func(path string, state verify.VerifiedState) error { return state.Save(path) }
	if adapter := l.SaveState; adapter != nil {
		saveState = func(path string, state verify.VerifiedState) error { return adapter(path, state.Snapshot()) }
	}
	if l.Multi == nil {
		return errors.New("syncer: Multi client required")
	}
	if err := l.Multi.Validate(); err != nil {
		return fmt.Errorf("syncer: %w", err)
	}
	if l.StatePath == "" {
		return errors.New("syncer: StatePath required (use verify-headers for ephemeral runs)")
	}
	if l.MaxStateSaveFailures < 0 {
		return errors.New("syncer: MaxStateSaveFailures must not be negative")
	}
	if l.Interval < 0 {
		return errors.New("syncer: Interval must not be negative")
	}
	maxSaveFailures := l.MaxStateSaveFailures
	if maxSaveFailures == 0 {
		maxSaveFailures = DefaultMaxStateSaveFailures
	}
	if l.Interval == 0 {
		l.Interval = DefaultInterval
	}
	if l.SafetyMargin == 0 {
		l.SafetyMargin = DefaultSafetyMargin
	}
	if l.BatchSize == 0 {
		l.BatchSize = DefaultBatchSize
	}

	authOpts := verify.VerifyOptions{Policy: l.Policy}
	if l.Authorizer != nil {
		authOpts.ProducerAuth = verify.ProducerAuthOptions{
			Mode:       verify.ProducerAuthRequired,
			Authorizer: l.Authorizer,
		}
	}
	lock, err := statelock.Acquire(l.StatePath)
	if err != nil {
		return fmt.Errorf("state lock: %w", err)
	}
	defer func() {
		if err := lock.Close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("release state lock: %w", err))
		}
	}()
	state, err := verify.LoadTrustedState(l.StatePath, l.Genesis, authOpts)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	if state.Empty() {
		return errors.New("syncer: refusing to bootstrap from empty state — pre-anchor with `verify-headers --genesis-config <checkpoint> --state <path>` first")
	}

	if err := l.logStartup(state, maxSaveFailures); err != nil {
		return err
	}

	timer := time.NewTimer(0) // fire immediately on first iteration
	defer timer.Stop()
	saveFailures := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			// An immediate catch-up timer and cancellation may both be ready.
			// Observe shutdown before starting another query or emitting a tick.
			if ctx.Err() != nil {
				return nil
			}
			res, newState := l.tick(ctx, state)
			persistedProgress := false
			if res.Outcome == verify.OutcomeAccept {
				if err := saveState(l.StatePath, newState); err != nil {
					saveFailures++
					if outputErr := l.logIteration(res, state, err, saveFailures, maxSaveFailures); outputErr != nil {
						return errors.Join(fmt.Errorf("syncer: state save failed: %w", err), outputErr)
					}
					if saveFailures >= maxSaveFailures {
						return fmt.Errorf("syncer: state save failed after %d consecutive attempts: %w", saveFailures, err)
					}
				} else {
					state = newState
					saveFailures = 0
					persistedProgress = len(res.FetchedHeights) > 0
					if err := l.logIteration(res, state, nil, saveFailures, maxSaveFailures); err != nil {
						return err
					}
				}
			} else {
				if err := l.logIteration(res, state, nil, saveFailures, maxSaveFailures); err != nil {
					return err
				}
			}
			// Only a successfully persisted advance can trigger immediate
			// catch-up. Failed saves retry from the retained state after
			// Interval, including when more headers are available.
			tip, _ := state.Tip()
			if persistedProgress && res.Target > tip.Height {
				timer.Reset(0)
			} else {
				timer.Reset(l.Interval)
			}
		}
	}
}

// tick runs one iteration: fetch frontier, fetch headers, verify,
// return result + maybe-updated state.
func (l *Loop) tick(ctx context.Context, state verify.VerifiedState) (TickResult, verify.VerifiedState) {
	tipHeader, ok := state.Tip()
	if !ok {
		return TickResult{Outcome: verify.OutcomeRefused, Reason: verify.ReasonMissingEvidence,
			Message: "watch requires a nonempty verified state"}, state
	}
	tip := tipHeader.Height
	target, err := l.frontierTarget(ctx)
	if err != nil {
		return TickResult{Tip: tip, Err: err, Outcome: verify.OutcomeRefused, Reason: verify.ReasonMissingEvidence,
			Message: fmt.Sprintf("frontier: %v", err), failureStage: "frontier"}, state
	}
	if target <= tip {
		return TickResult{Tip: tip, Target: target, Outcome: verify.OutcomeAccept, Reason: verify.ReasonOK,
			Message: "caught up"}, state
	}
	count := target - tip
	if l.BatchSize > 0 && count > l.BatchSize {
		count = l.BatchSize
	}
	if l.Policy.MaxHeaders > 0 && count > uint64(l.Policy.MaxHeaders) {
		count = uint64(l.Policy.MaxHeaders)
	}
	start := tip + 1
	headers, err := l.Multi.FetchByHeight(ctx, start, count)
	if err != nil {
		return TickResult{Tip: tip, Target: target, Err: err, Outcome: verify.OutcomeRefused,
			Reason: verify.ReasonMissingEvidence, Message: fmt.Sprintf("fetch: %v", err), failureStage: "fetch"}, state
	}
	heights := make([]uint64, len(headers))
	for i, h := range headers {
		heights[i] = h.Height
	}
	result, newState := state.Extend(headers)
	r := TickResult{
		Tip:            tip,
		Target:         target,
		FetchedHeights: heights,
		Outcome:        result.Outcome,
		Reason:         result.Reason,
		Message:        result.Message,
		verification:   &result,
	}
	if result.Outcome == verify.OutcomeAccept {
		tip, _ := newState.Tip()
		r.candidateTip = &chain.HashHeight{Hash: tip.HeaderHash, Height: tip.Height}
	}
	return r, newState
}

func (l *Loop) frontierTarget(ctx context.Context) (uint64, error) {
	h, err := l.Multi.FetchFrontierAtAgreedHeight(ctx, l.SafetyMargin)
	if err != nil {
		return 0, err
	}
	return h.Height, nil
}

// outputFailure preserves writer error identity without echoing private paths
// or other arbitrary writer messages in ordinary diagnostics.
type outputFailure struct{ cause error }

func (e *outputFailure) Error() string { return "syncer: cannot write watch output" }
func (e *outputFailure) Unwrap() error { return e.cause }

func (l *Loop) logf(format string, args ...any) error {
	if l.Out == nil {
		return nil
	}
	return l.writeOutput([]byte(fmt.Sprintf(format, args...)))
}

func (l *Loop) writeOutput(message []byte) error {
	if l.Out == nil {
		return nil
	}
	// Preserve wrappers that override Write but inherit a WriteString method.
	n, err := l.Out.Write(message)
	if err == nil && n != len(message) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return &outputFailure{cause: err}
	}
	return nil
}

func (l *Loop) logTick(r TickResult) error {
	if r.Outcome == verify.OutcomeAccept && len(r.FetchedHeights) == 0 {
		return l.logf("tick: ACCEPT (caught up at tip=%d, frontier_target=%d)\n", r.Tip, r.Target)
	}
	if r.Outcome == verify.OutcomeAccept {
		return l.logf("tick: ACCEPT tip=%d -> %d (fetched %d, target=%d)\n",
			r.Tip, r.FetchedHeights[len(r.FetchedHeights)-1], len(r.FetchedHeights), r.Target)
	}
	return l.logf("tick: %s %s tip=%d target=%d %s\n", r.Outcome, r.Reason, r.Tip, r.Target, r.Message)
}
