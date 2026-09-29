// Command zenon-spv is the CLI entry point for the Zenon SPV verifier.
//
// Subcommands:
//
//	zenon-spv verify-headers     [--window {low|medium|high}] [--genesis-config <path>] [--state <path>] <bundle.json>
//	zenon-spv verify-commitment  [--window ...] [--genesis-config ...] [--state <path>] <bundle.json>
//	zenon-spv verify-segment     [--window ...] [--genesis-config ...] [--state <path>] <bundle.json>
//	zenon-spv verify-state-value [--window ...] [--genesis-config ...] [--state <path>] <bundle.json>
//	zenon-spv watch              [--peers <urls>|--rpc <url>] --state <path> [--genesis-config ...] [--window ...] [--interval <dur>] [--safety-margin <n>] [--batch-size <n>] [--quorum <k>]
//
// watch turns the verifier into a stateful service: load (or
// initialize via prior verify-* run) state, then tick at --interval,
// multi-peer-fetching new momentums and verifying them with k-of-n
// redundancy. State persists after each ACCEPT; REJECT and REFUSED
// leave state untouched. Exits 0 on graceful shutdown
// (SIGINT/SIGTERM), 70 on unrecoverable startup error.
//
// --state <path> turns the verifier into a stateful service: if the
// file exists, the verifier extends from the persisted retained
// window's tip; if missing, it initializes from the configured
// genesis trust root and persists after a successful ACCEPT.
// On REJECT or REFUSED, the state file is unchanged.
//
// On resume (state file loaded), the bundle's claimed_genesis field
// is informational — the persisted state's genesis is authoritative.
// On a fresh start, claimed_genesis must match the configured trust
// root or REJECT/GenesisMismatch.
//
// verify-commitment runs verify-headers first and then validates each
// CommitmentEvidence in the bundle's `commitments` array. verify-segment
// runs verify-headers, verify-commitment, and then validates each
// AccountSegment's blocks (per-block hash recompute, Ed25519 signature,
// account-chain linkage, commitment lookup). verify-state-value runs
// verify-headers and then validates each StateValueProof in the
// bundle's `state_value_proofs` array — refused-by-design today
// because no consensus-bound authenticated state root exists in
// current-protocol go-zenon (see docs/state-commitment-audit.md).
// Exit codes reflect the worst outcome (REJECT > REFUSED > ACCEPT in
// severity); a header-level failure short-circuits before commitments,
// segments, or state-value proofs are evaluated.
//
// Default genesis is the embedded mainnet trust root
// (chain_id=1, height=1; see internal/verify/genesis.go and
// zenon-spv-vault/decisions/0002-genesis-trust-anchor.md). Override
// with --genesis-config <path> or all three ZENON_SPV_GENESIS_HASH,
// ZENON_SPV_CHAIN_ID, and ZENON_SPV_GENESIS_HEIGHT environment variables
// when verifying testnet/devnet or pinning a different anchor.
//
// Exit codes:
//
//	0   ACCEPT
//	1   REJECT
//	2   REFUSED
//	64  EX_USAGE       — bad invocation
//	70  EX_SOFTWARE    — internal error
//
// ACCEPT means local consistency only, per
// zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md
// §G1–G3. It does not imply finality, canonical-chain agreement, or
// censorship resistance (see NG3, NG4, NG6 in the same document).
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/syncer"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const usage = `zenon-spv — resource-bounded Zenon SPV verifier

Usage:
  zenon-spv verify-headers     [--window {low|medium|high}] [--genesis-config <path>] [--state <path>] [--schedule <path>] <bundle.json>
  zenon-spv verify-commitment  [--window ...] [--genesis-config ...] [--state <path>] [--schedule <path>] <bundle.json>
  zenon-spv verify-segment     [--window ...] [--genesis-config ...] [--state <path>] [--schedule <path>] <bundle.json>
  zenon-spv verify-state-value [--window ...] [--genesis-config ...] [--state <path>] [--schedule <path>] <bundle.json>
  zenon-spv watch              [--peers <urls>|--rpc <url>] --state <path> [--schedule <path>] [--genesis-config ...]
                               [--window ...] [--interval <dur>] [--safety-margin <n>] [--batch-size <n>] [--quorum <k>]

Subcommands:
  verify-headers      Verify a HeaderBundle JSON file. Exits 0 on ACCEPT,
                      1 on REJECT, 2 on REFUSED.

  verify-commitment   Verify the bundle's headers, then verify each
                      commitment in the bundle's "commitments" array.
                      Exits 0 only if all commitments ACCEPT; 1 on any
                      REJECT (including a header-level REJECT); 2 on
                      any REFUSED.

  verify-segment      Verify the bundle's headers and commitments, then
                      verify each block in every AccountSegment (hash
                      recompute, Ed25519 signature, account-chain
                      linkage, commitment lookup). Exit codes follow
                      the worst-block-wins convention.

  verify-state-value  Verify the bundle's headers, then verify each
                      entry in "state_value_proofs". REFUSED for every
                      CommitmentKind today (no consensus-bound state
                      root exists in current-protocol go-zenon; see
                      docs/state-commitment-audit.md). Shipped now
                      for forward compatibility with a future
                      accepting kind.

  watch               Run as a stateful service. Tick at --interval
                      (default 10s), multi-peer-fetch new momentums,
                      verify and persist. SIGINT/SIGTERM for graceful
                      shutdown.

Genesis trust root defaults to the embedded mainnet anchor only when no anchor
override is configured. Override via --genesis-config (strict JSON, max 16 KiB)
or all three environment variables: ZENON_SPV_GENESIS_HASH, ZENON_SPV_CHAIN_ID,
and ZENON_SPV_GENESIS_HEIGHT. Partial or empty environment overrides fail.
Height must be positive and the hash nonzero. A config file overrides env.

--window accepts exactly low, medium, or high (default low). Invalid or empty
values fail with exit 64 before configuration or evidence is loaded. Put all
verify-* flags before the bundle path; watch accepts flags only.

--protocol-profile <path> loads an anchor-bound, operator-attested momentum
activation profile for verify-* and watch. V2 requires this flag. Profiles
expire at their configured height and must match persisted state exactly.
They do not independently prove activation. See docs/header-versions.md.

--show-context prints a diagnostic JSON object with captured verifier settings
and a configuration fingerprint. Available on verify-* and watch; excludes
private audit metadata and does not imply verification success.

--schedule <path> loads an operator-attested per-momentum producer
schedule (Branch 5b). When set, the verifier requires each header's
producer to match the schedule's expected (height, timestamp,
producing-address) triple; failure to load aborts the run. Without
--schedule the verifier prints a tier-1 caveat noting that producer
authorization is not enforced.

Caveat: ACCEPT means local consistency only (bounded-verification §G1–G3).
It does not imply finality or global agreement.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(64)
	}
	switch os.Args[1] {
	case "verify-headers":
		os.Exit(runVerifyHeaders(os.Args[2:]))
	case "verify-commitment":
		os.Exit(runVerifyCommitment(os.Args[2:]))
	case "verify-segment":
		os.Exit(runVerifySegment(os.Args[2:]))
	case "verify-state-value":
		os.Exit(runVerifyStateValue(os.Args[2:]))
	case "watch":
		os.Exit(runWatch(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n%s", os.Args[1], usage)
		os.Exit(64)
	}
}

func runVerifyCommitment(args []string) int {
	ctx, code := prepareVerifierContext("verify-commitment", args)
	if code != 0 {
		return code
	}
	headerResult, newState := ctx.state.Extend(ctx.bundle.Headers)
	printResult("headers", headerResult)
	if headerResult.Outcome != verify.OutcomeAccept {
		return outcomeExitCode(headerResult.Outcome)
	}

	if len(ctx.bundle.Commitments) == 0 {
		fmt.Println("commitments: REFUSED ReasonMissingEvidence (no commitments in bundle)")
		return 2
	}

	worst := verify.OutcomeAccept
	for i, c := range ctx.bundle.Commitments {
		r := newState.VerifyCommitment(c)
		printResult(fmt.Sprintf("commitment[%d] height=%d addr=%x", i, c.Height, c.Target.Address), r)
		switch r.Outcome {
		case verify.OutcomeRefused:
			if worst != verify.OutcomeReject {
				worst = verify.OutcomeRefused
			}
		case verify.OutcomeReject:
			worst = verify.OutcomeReject
		}
	}
	if worst == verify.OutcomeAccept {
		printAcceptCaveat(os.Stdout, ctx.opts)
		if err := persistIfRequested(ctx.statePath, newState); err != nil {
			fmt.Fprintf(os.Stderr, "state: %v\n", err)
			return 70
		}
	}
	return outcomeExitCode(worst)
}

func runVerifyHeaders(args []string) int {
	ctx, code := prepareVerifierContext("verify-headers", args)
	if code != 0 {
		return code
	}
	result, newState := ctx.state.Extend(ctx.bundle.Headers)
	printResult("", result)
	if result.Outcome == verify.OutcomeAccept {
		printAcceptCaveat(os.Stdout, ctx.opts)
		if err := persistIfRequested(ctx.statePath, newState); err != nil {
			fmt.Fprintf(os.Stderr, "state: %v\n", err)
			return 70
		}
	}
	return outcomeExitCode(result.Outcome)
}

func runVerifySegment(args []string) int {
	ctx, code := prepareVerifierContext("verify-segment", args)
	if code != 0 {
		return code
	}
	headerResult, newState := ctx.state.Extend(ctx.bundle.Headers)
	printResult("headers", headerResult)
	if headerResult.Outcome != verify.OutcomeAccept {
		return outcomeExitCode(headerResult.Outcome)
	}

	if len(ctx.bundle.Segments) == 0 {
		fmt.Println("segments: REFUSED ReasonMissingEvidence (no segments in bundle)")
		return 2
	}

	worst := verify.OutcomeAccept
	for si, seg := range ctx.bundle.Segments {
		segRes := newState.VerifySegment(seg, ctx.bundle.Commitments)
		fmt.Printf("segment[%d] address=%x blocks=%d:\n", si, seg.Address, len(seg.Blocks))
		for bi, r := range segRes.Blocks {
			printResult(segmentBlockLabel(bi, seg), r)
		}
		switch segRes.Worst() {
		case verify.OutcomeReject:
			worst = verify.OutcomeReject
		case verify.OutcomeRefused:
			if worst != verify.OutcomeReject {
				worst = verify.OutcomeRefused
			}
		}
	}
	if worst == verify.OutcomeAccept {
		printAcceptCaveat(os.Stdout, ctx.opts)
		if err := persistIfRequested(ctx.statePath, newState); err != nil {
			fmt.Fprintf(os.Stderr, "state: %v\n", err)
			return 70
		}
	}
	return outcomeExitCode(worst)
}

// runVerifyStateValue verifies any StateValueProof entries in the
// bundle. Every CommitmentKind is REFUSED today because no
// consensus-bound authenticated state root exists in
// current-protocol go-zenon (see docs/state-commitment-audit.md
// and docs/state-proof-implementation-plan.md). The subcommand
// exists for forward compatibility — when a real accepting kind
// is added in a future PR, this CLI surface stays stable.
func runVerifyStateValue(args []string) int {
	ctx, code := prepareVerifierContext("verify-state-value", args)
	if code != 0 {
		return code
	}
	headerResult, newState := ctx.state.Extend(ctx.bundle.Headers)
	printResult("headers", headerResult)
	if headerResult.Outcome != verify.OutcomeAccept {
		// Forked-chain / bad-genesis / etc. failures surface here
		// BEFORE state-value verification runs. This is the
		// structural reason the forked-chain attack is a CLI
		// integration concern rather than a VerifyStateValue
		// unit-test concern (see Commit 6's attacks file).
		return outcomeExitCode(headerResult.Outcome)
	}

	if len(ctx.bundle.StateValueProofs) == 0 {
		fmt.Println("state_value_proofs: REFUSED ReasonMissingEvidence (no state_value_proofs in bundle)")
		return 2
	}

	worst := verify.OutcomeAccept
	for i, p := range ctx.bundle.StateValueProofs {
		res := newState.VerifyStateValue(p)
		printResult(fmt.Sprintf("state_value_proof[%d] height=%d kind=%s",
			i, p.MomentumHeight, p.CommitmentKind), res)
		switch res.Outcome {
		case verify.OutcomeReject:
			worst = verify.OutcomeReject
		case verify.OutcomeRefused:
			if worst != verify.OutcomeReject {
				worst = verify.OutcomeRefused
			}
		}
	}
	if worst == verify.OutcomeAccept {
		// Unreachable today — VerifyStateValue refuses every kind.
		// The shape is preserved so a future accepting kind plugs in
		// without an extra CLI edit.
		printAcceptCaveat(os.Stdout, ctx.opts)
		if err := persistIfRequested(ctx.statePath, newState); err != nil {
			fmt.Fprintf(os.Stderr, "state: %v\n", err)
			return 70
		}
	}
	return outcomeExitCode(worst)
}

// verifierContext bundles everything the verify-* subcommands
// need from their shared prelude: parsed flags, loaded genesis,
// loaded bundle, owned VerifiedState (loaded from --state if
// present), and the active VerifyOptions (Policy + optional
// producer authorizer loaded via --schedule).
type verifierContext struct {
	bundle    proof.HeaderBundle
	state     verify.VerifiedState
	opts      verify.VerifyOptions
	statePath string
}

// prepareVerifierContext parses common flags, loads the bundle and
// genesis, runs cross-bundle/trust-root sanity checks, and returns a
// ready verifierContext or a non-zero exit code on failure. If the
// returned exitCode is non-zero, the caller should return it
// directly without further work.
func prepareVerifierContext(name string, args []string) (verifierContext, int) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tier := fs.String("window", "low", "policy window tier: low | medium | high")
	genesisConfig := fs.String("genesis-config", "", "path to genesis trust root JSON file (overrides env)")
	profilePath := fs.String("protocol-profile", "", "path to an operator-attested momentum activation profile")
	showContext := fs.Bool("show-context", false, "print captured verification settings without private provenance metadata")
	statePath := fs.String("state", "", "path to persisted HeaderState; load if present, save after ACCEPT")
	schedulePath := fs.String("schedule", "", "path to producer schedule JSON; when set, header producer authorization is required (tier-2 caveat)")
	if err := fs.Parse(args); err != nil {
		return verifierContext{}, 64
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "%s: expected exactly one bundle path\n", name)
		fs.Usage()
		return verifierContext{}, 64
	}
	bundlePath := fs.Arg(0)
	policy, err := parseWindowPolicy(*tier)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return verifierContext{}, 64
	}

	genesis, err := loadGenesis(*genesisConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "genesis: %v\n", err)
		return verifierContext{}, 70
	}
	if err := configureProtocolProfile(&policy, *profilePath, genesis); err != nil {
		fmt.Fprintf(os.Stderr, "protocol profile: %v\n", err)
		return verifierContext{}, 70
	}
	bundle, err := proof.LoadHeaderBundleBounded(bundlePath, policy.MaxBundleBytes)
	if err != nil {
		if errors.Is(err, proof.ErrBundleTooLarge) {
			// REFUSED, not REJECT: too-big is a guardrail breach,
			// not proof of badness. Exit code 2 per the documented
			// matrix.
			fmt.Printf("REFUSED %s %v\n", verify.ReasonOversizedBundle, err)
			return verifierContext{}, 2
		}
		fmt.Fprintf(os.Stderr, "bundle: %v\n", err)
		return verifierContext{}, 70
	}
	if bundle.ChainID != genesis.ChainID {
		fmt.Printf("REJECT %s bundle chain_id=%d != trust-root chain_id=%d\n",
			verify.ReasonChainIDMismatch, bundle.ChainID, genesis.ChainID)
		return verifierContext{}, 1
	}
	opts := verify.VerifyOptions{Policy: policy}
	if *schedulePath != "" {
		sched, err := verify.LoadProducerSchedule(*schedulePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "schedule: %v\n", err)
			return verifierContext{}, 70
		}
		if sched.ChainID != genesis.ChainID {
			fmt.Fprintf(os.Stderr, "schedule: chain_id=%d != trust-root chain_id=%d\n",
				sched.ChainID, genesis.ChainID)
			return verifierContext{}, 70
		}
		opts.ProducerAuth = verify.ProducerAuthOptions{
			Mode:       verify.ProducerAuthRequired,
			Authorizer: verify.NewScheduleAuthorizer(sched),
		}
	}

	var state verify.VerifiedState
	if *statePath != "" {
		state, err = verify.LoadTrustedState(*statePath, genesis, opts)
	} else {
		state, err = verify.NewVerifiedState(genesis, opts)
	}
	if err != nil {
		var authorization *verify.StateAuthorizationError
		if errors.As(err, &authorization) {
			fmt.Printf("state: %s\n", authorization.Result)
			return verifierContext{}, outcomeExitCode(authorization.Result.Outcome)
		}
		fmt.Fprintf(os.Stderr, "state: %v\n", err)
		return verifierContext{}, 70
	}
	// A fresh start must bind the bundle to the configured anchor.
	// On resume the file has already been checked against that anchor.
	if state.Empty() && bundle.ClaimedGenesis != genesis.HeaderHash {
		fmt.Printf("REJECT %s claimed_genesis=%x != trust-root=%x\n",
			verify.ReasonGenesisMismatch, bundle.ClaimedGenesis, genesis.HeaderHash)
		return verifierContext{}, 1
	}

	// Aggregate resource-bound preflight (Branch 2b). Per-item
	// caps (e.g., MaxFlatEvidenceMembers) live inside the verifier
	// for callers that bypass the CLI; the AGGREGATE caps must run
	// before the verifier sees the bundle so a malicious shape
	// (many small items each under the per-item cap) is refused
	// before any heavy work.
	if r := preflightBundleBounds(bundle, policy); r.Outcome != verify.OutcomeAccept {
		fmt.Printf("bundle: %s\n", r)
		return verifierContext{}, outcomeExitCode(r.Outcome)
	}

	if *showContext {
		raw, err := state.VerificationContextJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "verification context: %v\n", err)
			return verifierContext{}, 70
		}
		fmt.Printf("verification_context: %s\n", raw)
	}
	return verifierContext{
		bundle:    bundle,
		state:     state,
		opts:      opts,
		statePath: *statePath,
	}, 0
}

// preflightBundleBounds enforces per-bundle resource caps before evaluation.
// Commitment limits share the core preflight used by VerifySegment. The
// remaining checks cover counts and totals spanning separate segments/proofs
// that an individual verifier call cannot see.
//
// Returns ACCEPT when every aggregate cap holds (or is disabled);
// otherwise REFUSED with the appropriate ReasonOversized* code.
// Per-item REJECT cases are not produced here — those are evaluation
// outcomes, not preflight ones.
func preflightBundleBounds(bundle proof.HeaderBundle, policy verify.Policy) verify.Result {
	if r := verify.PreflightCommitmentBounds(bundle.Commitments, policy); r.Outcome != verify.OutcomeAccept {
		return r
	}
	if policy.MaxSegments > 0 && len(bundle.Segments) > policy.MaxSegments {
		return verify.Result{
			Outcome:  verify.OutcomeRefused,
			Reason:   verify.ReasonOversizedSegment,
			Message:  fmt.Sprintf("segments=%d > MaxSegments=%d", len(bundle.Segments), policy.MaxSegments),
			FailedAt: -1,
		}
	}
	if policy.MaxTotalSegmentBlocks > 0 {
		remaining := policy.MaxTotalSegmentBlocks
		for _, segment := range bundle.Segments {
			if len(segment.Blocks) > remaining {
				return verify.Result{
					Outcome:  verify.OutcomeRefused,
					Reason:   verify.ReasonOversizedSegment,
					Message:  fmt.Sprintf("aggregate segment blocks > MaxTotalSegmentBlocks=%d", policy.MaxTotalSegmentBlocks),
					FailedAt: -1,
				}
			}
			remaining -= len(segment.Blocks)
		}
	}
	// State-value-proof aggregate cap (state-proof PR / Phase 2).
	// This lives in the CLI preflight, NOT in
	// proof.LoadHeaderBundleBounded: `internal/proof` is already
	// imported by `internal/verify`, so a verify.Policy reference
	// inside proof would create a package cycle. The loader stays
	// byte-only.
	if policy.MaxStateValueProofs > 0 && len(bundle.StateValueProofs) > policy.MaxStateValueProofs {
		return verify.Result{
			Outcome:  verify.OutcomeRefused,
			Reason:   verify.ReasonOversizedStateProof,
			Message:  fmt.Sprintf("state_value_proofs=%d > MaxStateValueProofs=%d", len(bundle.StateValueProofs), policy.MaxStateValueProofs),
			FailedAt: -1,
		}
	}
	return verify.Result{Outcome: verify.OutcomeAccept, Reason: verify.ReasonOK, FailedAt: -1}
}

// persistIfRequested writes state to path if path is non-empty.
// A no-op when --state was not set.
func persistIfRequested(path string, state verify.VerifiedState) error {
	if path == "" {
		return nil
	}
	return state.Save(path)
}

// runWatch is the watch-mode entry point. Runs until SIGINT/SIGTERM.
func runWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rpcURL := fs.String("rpc", os.Getenv("ZENON_SPV_RPC"), "single-peer RPC URL (or set ZENON_SPV_RPC)")
	peersFlag := fs.String("peers", os.Getenv("ZENON_SPV_PEERS"), "comma-separated peer URLs (or set ZENON_SPV_PEERS)")
	quorum := fs.Int("quorum", 0, "minimum agreeing peers; 0 = require unanimous (len(peers))")
	tier := fs.String("window", "low", "policy window tier: low | medium | high")
	genesisConfig := fs.String("genesis-config", "", "path to genesis trust root JSON file (overrides env)")
	profilePath := fs.String("protocol-profile", "", "path to an operator-attested momentum activation profile")
	showContext := fs.Bool("show-context", false, "log captured verification settings without private provenance metadata")
	statePath := fs.String("state", "", "path to persisted HeaderState (required)")
	schedulePath := fs.String("schedule", "", "path to producer schedule JSON; when set, header producer authorization is required (tier-2 caveat)")
	interval := fs.Duration("interval", syncer.DefaultInterval, "tick interval between iterations (0 = default 10s; negative values invalid)")
	safetyMargin := fs.Uint64("safety-margin", syncer.DefaultSafetyMargin, "drop this many heights below median(frontiers) per tick (0 = default 6)")
	batchSize := fs.Uint64("batch-size", syncer.DefaultBatchSize, "max headers to fetch per tick, also capped by verifier policy (0 = default 60)")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "watch does not accept positional arguments")
		return 64
	}
	policy, err := parseWindowPolicy(*tier)
	if err != nil {
		fmt.Fprintf(os.Stderr, "watch: %v\n", err)
		return 64
	}
	if *interval < 0 {
		fmt.Fprintln(os.Stderr, "watch: --interval must not be negative")
		return 64
	}
	if *statePath == "" {
		fmt.Fprintln(os.Stderr, "watch: --state <path> is required (the loop must persist on every ACCEPT)")
		return 64
	}

	urls := splitWatchPeers(*peersFlag)
	if len(urls) == 0 && *rpcURL != "" {
		urls = []string{*rpcURL}
	}
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "watch: --peers or --rpc required (or set ZENON_SPV_PEERS / ZENON_SPV_RPC)")
		return 64
	}
	if *quorum < 0 || *quorum > len(urls) {
		fmt.Fprintln(os.Stderr, "watch: --quorum must be 0 (unanimous) or between 1 and the number of peers")
		return 64
	}
	multi := fetch.NewMultiClient(urls)
	if *quorum > 0 {
		multi.Quorum = *quorum
	}

	genesis, err := loadGenesis(*genesisConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "genesis: %v\n", err)
		return 70
	}
	if err := configureProtocolProfile(&policy, *profilePath, genesis); err != nil {
		fmt.Fprintf(os.Stderr, "protocol profile: %v\n", err)
		return 70
	}

	var authorizer verify.ProducerAuthorizer
	if *schedulePath != "" {
		sched, err := verify.LoadProducerSchedule(*schedulePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "schedule: %v\n", err)
			return 70
		}
		if sched.ChainID != genesis.ChainID {
			fmt.Fprintf(os.Stderr, "schedule: chain_id=%d != trust-root chain_id=%d\n",
				sched.ChainID, genesis.ChainID)
			return 70
		}
		authorizer = verify.NewScheduleAuthorizer(sched)
	}

	loop := &syncer.Loop{
		Multi:        multi,
		StatePath:    *statePath,
		Genesis:      genesis,
		Policy:       policy,
		Authorizer:   authorizer,
		Interval:     *interval,
		SafetyMargin: *safetyMargin,
		BatchSize:    *batchSize,
		Out:          os.Stderr,
		ShowContext:  *showContext,
	}

	// Surface the ACCEPT caveat once at startup. Per-tick ACCEPT logs
	// in the syncer are stable for machine consumers; the human banner
	// here carries the trust-assumption note. Tier is determined by
	// whether --schedule was provided (tier 1 vs tier 2).
	startupOpts := verify.VerifyOptions{Policy: policy}
	if authorizer != nil {
		startupOpts.ProducerAuth = verify.ProducerAuthOptions{
			Mode:       verify.ProducerAuthRequired,
			Authorizer: authorizer,
		}
	}
	printAcceptCaveat(os.Stderr, startupOpts)
	printSourceTrust(os.Stderr, []verify.TrustAssumption{verify.TrustRPCQuorum})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := loop.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "watch: %v\n", err)
		return 70
	}
	return 0
}

// The library's PolicyForTier preserves its legacy fallback for callers that
// rely on it. A misspelled explicit CLI choice must not lower the requested W.
func parseWindowPolicy(tier string) (verify.Policy, error) {
	switch tier {
	case "low", "medium", "high":
		return verify.PolicyForTier(tier), nil
	default:
		return verify.Policy{}, errors.New("--window must be low, medium, or high")
	}
}

func splitWatchPeers(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// printAcceptCaveat writes the producer-auth caveat for an ACCEPT
// verdict to w. Kept out of canonical Result.String() so machine
// consumers see stable output; surfaced at the human CLI level so an
// integrator cannot mistake ACCEPT for a stronger guarantee than
// this build provides. The tier is selected from opts.ProducerAuth
// (tier 1 when no authorizer; tier 2 under operator-attested
// schedule). See internal/verify/caveats.go for tier definitions.

// segmentBlockLabel formats the printable label for the bi-th
// entry in a SegmentResult's Blocks slice. Normally this maps
// 1:1 to seg.Blocks[bi]. But VerifySegment also returns a single
// synthetic Result for empty or oversized segments (see
// internal/verify/segment.go), in which case segRes.Blocks has
// more entries than seg.Blocks and a naive index lookup panics.
// Return a generic "segment-result[bi]" label for those cases.
func segmentBlockLabel(bi int, seg proof.AccountSegment) string {
	if bi < len(seg.Blocks) {
		return fmt.Sprintf("  block[%d] height=%d", bi, seg.Blocks[bi].Height)
	}
	return fmt.Sprintf("  segment-result[%d]", bi)
}

func printResult(label string, r verify.Result) { printResultTo(os.Stdout, label, r) }

// printResultTo is the io.Writer-parameterized form of printResult,
// used by tests that need to capture the structured output into a
// bytes.Buffer. Production callers should use printResult.
func printResultTo(w io.Writer, label string, r verify.Result) {
	// Writes to w are best-effort: w is typically os.Stdout (where
	// the error is unrecoverable) or a bytes.Buffer in tests
	// (where errors don't happen). Explicit discard satisfies
	// errcheck and documents the intent.
	if label != "" {
		_, _ = fmt.Fprintf(w, "%s: %s\n", label, r)
	} else {
		_, _ = fmt.Fprintln(w, r)
	}
	printGuaranteesTo(w, "proven", r.Proven)
	printGuaranteesTo(w, "not_proven", r.NotProven)
	printTrustAssumptionsTo(w, "trust_assumptions", r.TrustAssumptions)
}

func printGuaranteesTo(w io.Writer, label string, xs []verify.Guarantee) {
	if len(xs) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "%s:\n", label)
	for _, x := range xs {
		_, _ = fmt.Fprintf(w, "  - %s\n", x)
	}
}

func printTrustAssumptionsTo(w io.Writer, label string, xs []verify.TrustAssumption) {
	if len(xs) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "%s:\n", label)
	for _, x := range xs {
		_, _ = fmt.Fprintf(w, "  - %s\n", x)
	}
}

func printSourceTrust(w io.Writer, xs []verify.TrustAssumption) {
	if len(xs) == 0 {
		return
	}

	_, _ = fmt.Fprintln(w, "source_trust:")
	for _, x := range xs {
		_, _ = fmt.Fprintf(w, "  - %s\n", x)
	}
}

func printAcceptCaveat(w io.Writer, opts verify.VerifyOptions) {
	if opts.Policy.ProtocolProfile != nil {
		_, _ = fmt.Fprintln(w, "CAVEAT: momentum activation is checked against an operator-attested protocol profile; network activation is not independently proven.")
	}
	caveat := verify.AcceptanceCaveatWithOptions(opts)
	if caveat == "" {
		// Tier 3 — locally derived; future phase. Skip the line
		// rather than emit a noisy empty caveat.
		return
	}
	_, _ = fmt.Fprintln(w, caveat)
}

// outcomeExitCode maps an Outcome to the documented exit-code matrix:
//
//	ACCEPT  → 0
//	REJECT  → 1
//	REFUSED → 2
//	other   → 70 (EX_SOFTWARE)
func outcomeExitCode(o verify.Outcome) int {
	switch o {
	case verify.OutcomeAccept:
		return 0
	case verify.OutcomeReject:
		return 1
	case verify.OutcomeRefused:
		return 2
	default:
		return 70
	}
}

func loadGenesis(path string) (verify.GenesisTrustRoot, error) {
	if path != "" {
		return verify.LoadGenesisFromConfig(path)
	}
	hashHex, hasHash := os.LookupEnv("ZENON_SPV_GENESIS_HASH")
	chainIDStr, hasChainID := os.LookupEnv("ZENON_SPV_CHAIN_ID")
	heightStr, hasHeight := os.LookupEnv("ZENON_SPV_GENESIS_HEIGHT")
	if !hasHash && !hasChainID && !hasHeight {
		return verify.MainnetGenesis()
	}
	hashHex = strings.TrimSpace(hashHex)
	chainIDStr = strings.TrimSpace(chainIDStr)
	heightStr = strings.TrimSpace(heightStr)
	if hashHex == "" || chainIDStr == "" || heightStr == "" {
		return verify.GenesisTrustRoot{}, errors.New("anchor environment override requires nonempty ZENON_SPV_GENESIS_HASH, ZENON_SPV_CHAIN_ID, and ZENON_SPV_GENESIS_HEIGHT")
	}
	hashHex = strings.TrimPrefix(hashHex, "0x")
	if len(hashHex) != 2*chain.HashSize {
		return verify.GenesisTrustRoot{}, fmt.Errorf("ZENON_SPV_GENESIS_HASH: invalid hex length")
	}
	raw, err := hex.DecodeString(hashHex)
	if err != nil {
		return verify.GenesisTrustRoot{}, errors.New("ZENON_SPV_GENESIS_HASH: invalid hex")
	}
	var hash chain.Hash
	copy(hash[:], raw)

	chainID, err := strconv.ParseUint(chainIDStr, 10, 64)
	if err != nil {
		return verify.GenesisTrustRoot{}, errors.New("ZENON_SPV_CHAIN_ID: expected an unsigned decimal 64-bit integer")
	}
	height, err := strconv.ParseUint(heightStr, 10, 64)
	if err != nil {
		return verify.GenesisTrustRoot{}, errors.New("ZENON_SPV_GENESIS_HEIGHT: expected an unsigned decimal 64-bit integer")
	}
	anchor := verify.GenesisTrustRoot{
		ChainID:    chainID,
		Height:     height,
		HeaderHash: hash,
	}
	if err := anchor.Validate(); err != nil {
		return verify.GenesisTrustRoot{}, err
	}
	return anchor, nil
}

func configureProtocolProfile(policy *verify.Policy, path string, anchor verify.GenesisTrustRoot) error {
	if path == "" {
		return nil
	}
	profile, err := verify.LoadProtocolProfile(path)
	if err != nil {
		return err
	}
	if profile.Anchor != anchor {
		return verify.ErrProtocolProfileMismatch
	}
	policy.ProtocolProfile = profile
	return nil
}
