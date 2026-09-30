# Documentation Index

This folder mixes current operator guidance with historical review
artifacts. Start with the current docs below; use the review files as
audit history.

## Current guidance

- [`architecture.md`](architecture.md) — shipped verifier components,
  current guarantees, and forward roadmap.
- [`trust-model.md`](trust-model.md) — what each `ACCEPT` does and does
  not prove.
- [`verification-contract.md`](verification-contract.md) — native-client
  trust inputs, bounded results, and acceptance gates for further work.
- [`verified-state-api.md`](verified-state-api.md) — immutable application
  state, captured policy, and trusted local resume.
- [`retained-state-queries.md`](retained-state-queries.md) — explicit CLI proof
  queries against a trusted local window, without state writes or new headers.
- [`state-writer-locks.md`](state-writer-locks.md) — exclusive ownership across
  stateful commands, read-only query coexistence, and companion-file rules.
- [`verification-context.md`](verification-context.md) — opt-in settings
  diagnostics, metadata exclusion, and reproducible configuration fingerprints.
- [`verification-reports.md`](verification-reports.md) — versioned JSON command
  reports, per-proof guarantees, and separate persistence and error outcomes.
- [`build-identity.md`](build-identity.md) — privacy-filtered executable source
  metadata and explicit unknown/modified build handling.
- [`conformance.md`](conformance.md) — implemented conformance cases,
  known gaps, and production follow-ups.
- [`compiled-query-conformance.md`](compiled-query-conformance.md) — compiled
  collector/verifier processes, loopback peer faults, and retained-query reports.
- [`local-watch-scenarios.md`](local-watch-scenarios.md) — reproducible
  multi-peer RPC faults, verification outcomes, and persistence checks.
- [`rpc-query-binding.md`](rpc-query-binding.md) — local query validation,
  response height/account binding, and quorum treatment of mismatched replies.
- [`rpc-diagnostics.md`](rpc-diagnostics.md) — endpoint-free error formatting,
  retained error causes, peer positions, and private-data boundaries.
- [`account-amount-validation.md`](account-amount-validation.md) — signed-value
  ambiguity prevention across RPC and offline proof inputs, with node vectors.
- [`account-envelope-validation.md`](account-envelope-validation.md) — supported
  account layouts, anchor chain binding, and post-genesis block shape checks.
- [`contract-batches.md`](contract-batches.md) — node-derived batch ordering,
  direct child inclusion, and descendant-hash conformance boundaries.
- [`fetch-bundle.md`](fetch-bundle.md) — explicit peer selection, bounded
  query options, output behavior, and checkpoint provenance for bundle assembly.
- [`producer-set-verification.md`](producer-set-verification.md) —
  opt-in producer authorization via operator-attested per-momentum
  schedules.
- [`resource-bound-measurements.md`](resource-bound-measurements.md) —
  empirical basis for the resource limits now wired into `Policy`.
- [`state-proof-plan.md`](state-proof-plan.md) — next plan for moving
  from account-header inclusion toward balance/state-value proofs.
- [`state-proof-implementation-plan.md`](state-proof-implementation-plan.md)
  — concrete commit-by-commit roadmap that executes the state-proof
  plan above as a single PR.
- [`state-commitment-audit.md`](state-commitment-audit.md) — Phase 0
  audit; source-cited findings on what go-zenon does (and does not)
  authenticate today, and the external dependencies that would be
  required for an accepting `StateValueProof` path.
- [`sentry-sentinel-role.md`](sentry-sentinel-role.md) — the role
  boundary between provider availability and proof authority;
  prevents Sentinel-attested values from ever being labeled
  `STATE_VALUE_INCLUSION`.

## Historical review material

- [`peer-review.md`](peer-review.md) — original 2026-05 peer-review fix
  list.
- [`peer-review-plan.md`](peer-review-plan.md) — implementation plan for
  that peer-review batch; retained as history now that the core fixes
  are represented in code and current docs.
- [`adversarial-review-brief.md`](adversarial-review-brief.md) —
  original adversarial review prompt; some statements are intentionally
  stale and are superseded by the finding reports and current docs.
- [`adversarial-review-findings-claude.md`](adversarial-review-findings-claude.md)
  and [`adversarial-review-findings-codex.md`](adversarial-review-findings-codex.md)
  — finding reports with post-review resolution notes.
- [`stress-test-from-reference.md`](stress-test-from-reference.md) —
  historical stress-test report for the imported reference branch.
