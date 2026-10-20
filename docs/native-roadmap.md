# Native verifier roadmap

The active plan has two tracks: qualify the existing v1/v2 inclusion application,
and coordinate one accepted-header balance-proof delivery. The native verifier
keeps explicit anchor, profile, producer-schedule and context-pin trust boundaries.
The [verification contract](verification-contract.md) defines its guarantees.

## Selected review candidate

Keep [`6ecc2310538d511e3b26bea4c658082853266a11`](https://github.com/edgepillar/zenon-spv/commit/6ecc2310538d511e3b26bea4c658082853266a11)
fixed for review. Its [exact-main CI run](https://github.com/edgepillar/zenon-spv/actions/runs/39066131743)
passed on Linux amd64, macOS Intel amd64 and Windows amd64. The private,
unsigned handoff binds 892 tracked files, 555 Go/module/JSON inputs, 48 native
evidence families, nine archives, 21 ordinary executables and all 59 selected
scenarios per platform. Five Windows skip records remain explicit; the Linux
and macOS scenario ledgers contain zero. This does not qualify an ARM release,
independent human review or authenticated distribution.

The frozen handoff manifest has SHA-256
`a2d38fea7a8672f8fe626f50aea9885d1a5087bdd210abf75d26fa4fc82b588d`.
Its private evidence and unsigned hash do not authenticate their own origin.
Later documentation changes are tracked separately. A later executable
candidate needs its own source, binary, report, scenario and skip reconciliation;
historical observations keep their original revisions.

## Current delivery order

| Milestone | Owner and current state | Required exit |
| --- | --- | --- |
| M0: one review candidate | Maintainer and release reviewer. Mechanical source/binary/report/scenario binding is complete for the selected revision; independent acceptance is open. | Preserve the exact candidate and its failures, complete case inventory, platform limits and change ledger during review. |
| M1: real v1/v2 consumer | The operator selected the existing CLI for testnet account-block inclusion observation. A bounded operator-trusted development comparison of the frozen candidate is recorded; independent consumer/network acceptance remains open. | The selected real consumer obtains its bounded inclusion result across the declared advancing-history and failure plan. Claim independent qualification only with demonstrated independent selection, corroboration and provenance. |
| M2: partial-SMT agreement and recovery | Node maintainer, SPV maintainer and protocol reviewer. Candidate specification and finite experimental fixes exist; agreement and full node qualification remain open. | Agree key/value/proof/activation/resource rules and qualify full momentum hash/height binding through recovery, retention and reorg on one selected node revision. |
| M3: one accepted-v3 balance flow | SPV maintainer and consumer integrator, after M2. Runtime v3 and state-value acceptance remain refused. | Bind an owned accepted header/context to its StateRoot, a locally derived address/token key, bounded proof and strict typed consumer result, while preserving v1/v2 compatibility and default refusal. |
| M4: representative node/import workload | Node/snapshot maintainer, operator and performance reviewer. Recorded component cases remain scoped evidence. | Meet declared hardware/workload budgets and qualify actual import, retention, reorg, interruption and activation paths, including the trust or derivation of excluded snapshot state. |
| M5: scoped reviewed distribution | Independent reviewers and release maintainer. Open for native inclusion and state proofs separately. | Resolve the exact candidate's review findings, qualify its consumer/workload and authenticate source, binary, report and update/rollback distribution. A state-proof release also needs M2–M4 and an activation-aware read-only state-proof pilot. |

M1 can proceed alongside M2. A second operator is not a prerequisite for an
explicitly operator-trusted development experiment. Independent network
qualification has additional selection, corroboration and provenance gates.

## Start the real consumer pilot

Use the existing [block observer](block-observer.md) and
[operator procedure](operator-pilot.md). The [query consumer](query-report-consumer.md)
checks exact targets, context/tip, required guarantees and allowed trust.
The [outer reader](observer-report-consumer.md) additionally checks the actual
observer completion through its protected report channel.

Before collecting another candidate, the consumer owner and operator select:

- The concrete read-only use, exact real account address/height/hash targets,
  intended tip and required guarantees. Candidate proof fields cannot select
  their own expectations.
- The authenticated anchor/generation, v1/v2 activation profile and producer
  schedule sources, plus protected saved-state provenance and the approved
  context pin. Agreement between RPC responses does not authenticate these.
- Target hardware, K/W, query batch, concurrency, deadlines, memory/disk/network
  limits and acceptance thresholds. Record the accounting scope of each limit.
- A finite execution plan covering state advancement, fresh-process restart,
  delayed queries, disconnect, stale/forked/malformed peers, coverage expiry and
  persistence/output failures. Preserve saved progress after downstream failure.

Retain every actual attempt, actual child exit and incomplete output. Separate
real network observations, captured-response faults and synthetic loopback cases.
Do not renew trust inputs, replace expectations, retry a failed phase or roll
state back implicitly. Follow [trust-input lifecycle](trust-input-lifecycle.md)
when the operator explicitly selects a renewal.

The [earlier advancing-history experiment](advancing-history-observation.md)
already records three historical ticks through one gateway, strict delayed/tip
refusals, restart-related faults and unchanged-profile expiry. Its source,
targets, provider and unsigned evidence remain specific to that experiment.
It does not establish a pilot of the selected review candidate or independent
consumer/network acceptance.

## Separate state-root research

The [candidate contract](state-root-candidate-contract.md) defines a partial
balance/storage commitment. Plasma, account frontier and mailbox state remain
outside that projection. Agree exact balance-key and value-width rules,
present-zero versus absence, canonical proof encoding, byte limits and
activation/profile semantics before enabling acceptance. Keep this partial SMT
distinct from the broader reserved `IAVL_STATE` kind.

The known node gate is full retained-root momentum identity through startup,
recovery, import and live reorg. The
[experimental identity work](state-tree-hash-bound-versions.md),
[startup quarantine](state-tree-startup-quarantine.md),
[offline rebuild](state-tree-offline-rebuild-successor.md) and
[raw-store roundtrip](state-tree-raw-kv-roundtrip-successor.md) retain their exact
source/caller/component limits. Successful primitive or recorded comparisons
do not qualify an unexecuted chain wrapper or production recovery path.

The [public Chain lifecycle comparison](public-chain-terminal-lifecycle.md)
additionally reproduces two `Chain.Init` panics and a false `Start` success on
stopped real managers, then checks a separate experimental outer guard. Its six
sequential cases include normal initialization and clean manager reopen; full
node recovery, reorg and concurrent lifecycle qualification remain open. The
original task's late whole-module-graph failure is retained explicitly.

Cache recovery also needs the selected ledger's full identifier. The
[rollback identity experiment](cache-identifier-rollback.md) validates the
retained rollback path. The separate
[forward-replay preflight experiment](cache-forward-replay.md) reproduces a
foreign behind-cache base becoming ready at a matching current identifier,
then checks refusal before writing and valid empty/behind-cache replay. Its
changed runtime reruns the prior rollback component controls. These finite
experiments leave M2 agreement and full node qualification open.

The [patch-snapshot lifetime experiment](patch-snapshot-lifetime.md) separately
checks explicit release in two short-lived readers, returned-patch lifetime and
acquisition errors. Its integrated candidate retains the earlier 58 native pass
names and adds 15; a separate 22-root original DB regression produces 27 pass
names. Portable checks read recorded observations, including six controlled
GC-disabled cases per generation. These are ownership controls, not evidence of
a permanent leak or representative production memory requirements.

For M3, obtain the expected root from the owned accepted v3 header/context.
Derive the selected address/token key locally and carry exact presence,
absence and value semantics through transport, saved state and the consumer.
Preserve default refusal and v1/v2 behavior until the stated gates pass.

For M4, select representative key-family churn, retained/archive data, snapshot
import and proof-service traffic on declared hardware. Snapshot chunk digests
and recomputed SMT roots are distinct objects. A partial root cannot authenticate
excluded state. Keep actual node execution, current replay checks, allocation,
process memory, disk and whole-pipeline latency scopes separate.

## Separate consensus research

Specify authenticated election inputs, slot authorization, producer transitions,
activation, conflict resolution, long-offline recovery, weak-subjectivity and
freshness assumptions before implementing their acceptance rules. Signatures,
operator schedules, peer agreement and green CI do not establish canonicality
or consensus finality.

## Reuse and later tracks

Continue selectively extending `edgepillar/zenon-spv`. Pinned node behavior and
SDK model/RPC adapters inform compatibility; keep wallet/runtime dependencies
outside the verifier. The research history records the prototype comparisons,
TminusZ threat-model input and later browser-client possibilities.

Bitcoin and Portal need separately selected use cases, protocol conformance,
reorg/freshness models and review. Wallets, signing, transactions, custody and
irreversible asset release are outside this native read-only delivery.

## Recorded research history

The [research appendix](native-research-history.md) preserves the previous
637-line roadmap verbatim, with its source revision and SHA-256. Follow its
links for completed component experiments, byte oracles, process boundaries and
resource observations. The source-pinned experiment documents remain authoritative
for their own scopes. Select new research or optimization work for a concrete
defect, a profile decision, demonstrated cost or a selected consumer requirement.

### Recorded account transaction method conformance

See the [archived section](native-research-history.md#recorded-account-transaction-method-conformance).

### Actual node missing-account context gate

See the [archived section](native-research-history.md#actual-node-missing-account-context-gate).

### Recorded account basic checks with memory stores

See the [archived section](native-research-history.md#recorded-account-basic-checks-with-memory-stores).

### Recorded receive protocol-store boundaries

See the [archived section](native-research-history.md#recorded-receive-protocol-store-boundaries).

### Recorded account PoW byte and method boundaries

See the [archived section](native-research-history.md#recorded-account-pow-byte-and-method-boundaries).

### Qualification cost: selected target hex validation

See the [archived section](native-research-history.md#qualification-cost-selected-target-hex-validation).
