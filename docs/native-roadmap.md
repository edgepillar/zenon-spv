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
Later changes include executable code and tests, as well as documentation and
research. The [frozen-to-baseline change ledger](review-candidate-changes.md)
retains the historical `879fbce33dd77f483f7aba18994fb037f248e842` observations
and the completed `d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff` pipeline. It
enumerates the complete 15-file root-module Go delta and separate Python/workflow
changes through qualified `1b8a33fd351ee5b7c697aac21940323ee1f81c74`. Its
general main CI covers seven jobs and all 34 actual artifacts, including the
source-bound candidate stream and existing recorded scopes. The preceding
`8767708` ten-job/37-artifact general and transport qualification, `bc0be26`
34-archive and `b6358c1` 28-archive qualifications remain pinned in the ledger;
unchanged workflow path filters do not schedule or requalify transport scopes.
It
also distinguishes original review revisions from their identity-normalized
counterparts. A later documentation-only workflow supplies no new native
execution; retain the latest runtime-qualified revision explicitly. These source
and mechanical CI observations do not transfer independent review to a changed
revision. Every later executable candidate needs its own source, binary, report,
scenario and skip reconciliation; historical observations keep their original
revisions.

The [source scenario companion](scenario-inventory.md) supports that review
without changing the frozen executable candidate. It checks the retained offline
report against the literal registry in a separately selected clean source
checkout. Payload validation, actual execution, independent human acceptance and
authenticated distribution remain distinct requirements.

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

The next state-root input is the [R1 inventory and measurement intake](state-root-r1-intake.md).
Collect a consistent, source-bound raw-ledger inventory and declared workload
before choosing commitment-domain, activation or hardware budgets. Existing
primitive and source-genesis cases are reusable controls, not representative
network measurements. Snapshot transport/import preparation can proceed with
explicit trust and completeness limits before root activation. Reuse the
existing v3 codec and sparse-proof primitives when M2 permits the M3 flow;
another recorded experiment family does not replace the missing agreement or
representative data.

The [bounded R1 transport tool](../tools/ledger-transport/README.md) prepares the
snapshot transport track without enabling state values. It hashes fixed chunks
and the whole selected stream in one pass, retaining only a small manifest and
result. It writes no chunk files and keeps real-data, consistency, complete-state,
accepted-header/root, profile/activation and independent-review gates open.

Its separate [archive directory preflight](../tools/ledger-transport/README.md#observe-an-archive-directory-before-acquiring-its-payload)
can observe a selected bounded ZIP/ZIP64 tail without downloading or opening
member payloads. The [R1 intake](state-root-r1-intake.md#current-public-archive-observation)
records the current 1 MiB public-source observation and conservative acquisition
accounting. Directory claims do not verify the whole archive, consistent node
capture, real ledger inventory or representative measurements. Publisher and
full-frontier inputs remain separate gates.

The [source-genesis export comparison](source-genesis-ledger-export.md) checks
one unchanged node's real logical frontier against the ordinary exporter,
completion consumer, transport and inventory. It matches 103,824 records and
11,779,928 put-wire bytes without another producer/build/transfer after the
controller failures. Those failures remain retained. This is finite source-layout
and workflow compatibility; it supplies no representative R1 dataset or M2–M5
acceptance.

The same comparison now follows one owned raw ledger through the original
storage manager's empty Put, zero32 replacement, Delete and three Pops. All
seven closed snapshots match independently selected full streams, and the final
stream restores the original digest. The probe distinguishes iterator
tombstones from present-empty values with the same view's `Get`/`Has` semantics.
These are synthetic storage commits, not validated network Momentums or a test
of derived SMT root retention/recovery. Representative R1, M2 agreement and the
accepted-header M3 balance flow remain separate exits.

The export path now uses [bounded output buffering](ledger-export-buffering.md)
to reduce small writes without changing the selected put stream or completion
gates. Finite encoder allocation/write observations prepare the R1 transport
track; they do not supply representative data or hardware acceptance.

The independent inventory similarly uses [bounded input buffering](ledger-inventory-buffering.md)
to amortize small reads and hash updates while keeping its selected-byte, field,
ordering and actual EOF checks. It creates no input copy or large fixture file.
This is a measurement-pipeline improvement; representative R1 data, M2 agreement
and accepted-header state proofs remain separate gates.

The [completed-export inventory helper](../tools/ledger-export/README.md#recount-a-completed-export-with-the-selected-limits)
passes the matched selection and resource limits directly to the existing
inventory reader on the same retained stream. It removes the manual transfer of
four caps while preserving actual completion, independent byte recount and EOF
checks. It supplies no new node execution, representative dataset or state proof.

CI now verifies the downloaded root-module cache after its builds/tests, with
network lookup and toolchain switching disabled, and rejects `go.mod`/`go.sum`
drift. This checks the main build list's cached content under
[Go's verification semantics](https://go.dev/ref/mod#go-mod-verify). It does not
qualify the six separate research module caches, dependency provenance or a
reproducible/authenticated release. The ordinary build, source binding, artifact
and independent acceptance checks remain necessary.

## Start the real consumer pilot

Use the existing [block observer](block-observer.md) and
[operator procedure](operator-pilot.md). The [query consumer](query-report-consumer.md)
checks exact targets, context/tip, required guarantees and allowed trust.
The [outer reader](observer-report-consumer.md) additionally checks the actual
observer completion through its protected report channel.

The ordinary observer also routes Linux/macOS interrupt and termination
signals through cancellation, joined child completion and private staging
cleanup. Controlled verifier/consumer processes exercise those boundaries;
they leave the real consumer, network and trust-input acceptance gates open.

The [owned-state persistence comparison](owned-state-persistence.md) reuses the
immutable handle's established window validation when saving. Mutable inputs and
loaded files retain their full checks; the bounded atomic writer and serialized
bytes stay the same. Its local cost observations leave the consumer, network,
independent-review and distribution gates open.

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

The [ledger rollback-target experiment](momentum-rollback-target.md) checks a nil
height lookup before mutation and compares the complete target identifier. Two
ordinary real-ledger probes record four parent API panics and zero candidate
panics, preserving valid rollback and manager reopen. Eleven focused native unit
results preserve lookup errors and existing partial-pop classifications. These
controls do not execute `Chain.Init`, a cache, state tree or network, and leave M2
agreement and full node qualification open.

The [public startup-record experiment](public-chain-startup-records.md) checks
the stored genesis and frontier before downstream initialization, including
their complete identifiers and computed body hashes. Two ordinary real-manager
processes record four parent API panics and five inconsistent successful starts;
the candidate refuses those cases and preserves healthy reopen. Seventeen
focused native test passes preserve initial genesis insertion, lookup errors,
terminal lifecycle and prior rollback controls. These selected unsigned fixtures
leave profile agreement, concurrent lifecycle and full node recovery open.

The [public Chain reorg/reopen comparison](public-chain-reorg-reopen.md) adds
distinct balance roots, the selected callers' real insert-lock maintenance
order, rollback and fresh-process reopen. One ordinary binary records 15 exact
root/proof matches and 16 missing/foreign-version refusals. The four new momenta
are unsigned empty-content local fixtures; cache account-block extraction,
network-valid history, profile agreement and full node qualification remain
open. State-value acceptance stays refused.

The [public cache-store context comparison](cache-store-context.md) separately
checks identifier admission for height-indexed cache views. Two baseline processes
returned four foreign-hash views while the state-root API refused those same
identifiers; the experimental public Chain successor returned none. All 17 prior
native lifecycle/rollback passes and 12 new context controls remain recorded.
The zero-valued source-genesis cache fixture leaves populated extraction,
cache-value correctness, concurrent history changes and full-node qualification
open. Plasma and fused cache data remain outside the partial SMT proof domain.

The [cache iterator read-error comparison](cache-read-errors.md) additionally
checks populated extraction, healthy absence and views retained after normal
manager Stop. Six baseline reads hid a real iterator error; the experimental
successor propagates that error. Four raw records remain byte-bound through
reopen and across variants. A separate 41-root/50-result native invocation
retains the previous chain/cache controls. The ordinary probes select only
a cache manager and extractor; nominal identifiers, these cache values and
selected unit regressions do not qualify consensus, the full node or state
proof acceptance.

The [core-manager pre-start Stop comparison](zenon-worker-prestart-stop.md)
extends the selected experiment through keyless `Zenon` managers. Two baseline
API calls panicked before downstream cleanup; the constructor-channel successor
returns normally. Six qualified ordinary processes include two keyless internal
service start/stop controls and fresh-process reopen. Fifty native roots and
59 pass results preserve the preceding regressions. The interrupted extra
attempt remains UNKNOWN. No wallet or peer server is started, and these finite
results do not qualify repeated Stop, concurrent lifecycle, consensus validity
or a full node. M2 agreement and state-value acceptance remain open/refused.

The [core-manager close-error comparison](core-stop-error-cleanup.md) checks the
next cleanup boundary with real owned handles. A cache close error left the
baseline's final consensus database open; the successor finishes cleanup and
retains both genuine errors in the two-handle control. Six ordinary processes,
53 native roots and 62 passes bind the selected behavior. The ordinary node
entry point compiled and was not executed. An output-capped test attempt stays
failed; a test-only diagnostic handler bounded the resumed output without
repeating successful comparison processes. These results do not close the
agreement, accepted-header, realistic-workload or independent-review gates.

The [repeated core Stop comparison](core-repeated-stop.md) adds the next
bounded manager-lifecycle correction: repeated Stop callers retain the first
completed result, while a panicked first Stop leaves later callers refused.
Six ordinary processes, 58 native roots/71 passes and five Go race roots/nine
passes preserve the prior error and source-genesis queries. This selected
Stop-only concurrency does not qualify concurrent Init/Start/Stop, full-node
restart, M2 profile agreement or accepted state values.

The [core Init/Stop admission experiment](core-init-stop-admission.md) separately
reproduces Init making a tree ready after a controlled incomplete core Stop.
Its successor refuses that admission and serializes Init with Stop. Four
ordinary processes, two selected race processes and five existing native roots
with nine passes bind this changed runtime. The source preparer reproduces both
484-file build inputs. Start concurrency, arbitrary manager failures, full-node
qualification, M2 agreement and accepted state values remain open.

The [native candidate v3 codec](candidate-v3-header-codec.md) adds bounded
projected-header decoding and the selected 208-byte hash layout. Its tests
compare all six recorded v3 preimages/hashes and preserve four v1/v2 cases.
The codec returns untrusted data and keeps the native version gate, saved
context and state-value refusal unchanged. It is M3 format preparation;
profile agreement and an actually accepted header remain required.

The [native candidate sparse proof comparison](candidate-smt-proof.md) adds
bounded proof reconstruction and local address/token key derivation. It preserves
the original 41 node outcomes, explicit zero/absence and encoding differences.
Its caller-selected root is still unauthenticated; this primitive does not
construct accepted state or complete M3.

For M3, obtain the expected root from the owned accepted v3 header/context.
Derive the selected address/token key locally and carry exact presence,
absence and value semantics through transport, saved state and the consumer.
Preserve default refusal and v1/v2 behavior until the stated gates pass.

For M4, select representative key-family churn, retained/archive data, snapshot
import and proof-service traffic on declared hardware. Snapshot chunk digests
and recomputed SMT roots are distinct objects. A partial root cannot authenticate
excluded state. Keep actual node execution, current replay checks, allocation,
process memory, disk and whole-pipeline latency scopes separate.

The [public Chain proof workload](public-chain-proof-workload.md) adds real disk
ledger/cache/tree requests on source-genesis data. One ordinary binary serves
four preselected processes, including fresh-process reopen; 128 independent
witnesses bind all 16,384 timed request pairs. Single observations with 1, 4 and
16 workers do not qualify a concurrency speedup or production budget. A failed
collector is preserved while its completed first case is reused without another
build or case retry. Full VM, import/churn/retention concurrency, activation and
the accepted-header state-value gates remain open.

The [public Chain read/Stop observations](public-chain-proof-stop.md) extend that
work to a finite concurrent batch against real managers. The race recording has
one successful caller interval overlapping Stop. The ordinary recording has none
and remains `INCONCLUSIVE`; combined overlap qualification remains false. The
portable reader checks the retained corrected-process outputs and preserves that distinction. A
producer framing correction retains the first failure and leaves the independent
witness catalog and candidate runtime unchanged. No internal database interleaving,
production resource budget, full M4 workload or accepted-header proof is established.

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

### Qualification cost: repeated complete fixture graphs

Measured hosted step durations and a local reader profile select the
[bounded graph reuse extension](conformance-graph-reuse.md). The workspace and
projected-driver readers keep their complete existing controls and recorded
byte comparisons while sharing source-pinned pure results within each serial
process. No disk cache, new node workload or runtime acceptance is introduced.
The import-scale, child-lifecycle and sparse-projection selections additionally
retain all 90 original controls. Selected local comparisons preserve every
original report object while trading about 44–54 MiB of child RSS for less
repeated hashing; representative workload and whole-CI gains remain unqualified.
Keep exact-head CI, artifact reconciliation and the separate M0–M5 gates.

### Qualification cost: fresh file-checker processes

Measured child waits and a separate original-checker profile select the
[explicit child hex execution](conformance-child-hex.md). All 23 existing control
methods remain required. A separate driver selects three fresh CLIs with the
pinned original entrypoint and source/exit/console recipes. The original control
and runner files stay byte-identical and the direct path remains available.
No global import hook, disk cache, new node workload or runtime
acceptance is introduced. Preserve exact-source CI, artifact reconciliation and
the independent M0–M5 gates.

### Qualification cost: repeated Git source trees

A completed hosted step and full local profile select the separate
[bounded Git tree reuse scope](conformance-git-tree-reuse.md). It preserves all
18 original cache rollback controls and their complete reader result while
keeping source validation fresh. Only pure source-tree reconstructions with
complete identical inputs are reused within one serial process. Local
counterbalanced observations report lower child wall time and peak RSS; whole-CI
and production resource budgets remain unqualified. No recorded source, native
backend, protocol rule or state-value acceptance changes.

### Qualification cost: repeated sparse leaf paths

The [bounded leaf commitment scope](retention-leaf-reuse.md) separately selects
the complete larger-retention checker and all 24 original controls. It caches
only a pure depth/path/value leaf commitment, while rebuilding every graph's
node and edge dictionaries and retaining all root/proof/refcount checks. One
local full-checker comparison preserves its report and avoids 18.5 million
repeated parent hashes; its 2 MiB logical payload cap does not qualify total RSS,
representative node resources or whole-CI speedup. The old checker, producer
source pins and recordings remain byte-identical. No node execution or runtime
state-value acceptance is introduced.

### Qualification cost: fresh import checker CLIs

The [explicit import resource child recipes](import-resource-child-hex.md)
extend the existing translated hex path to two default fresh CLI calls. All 45
original parent controls, their source bytes and the separate prior-source
refusal process remain required. Nineteen additional controls bind complete
original console fingerprints, source/exit/recipe checks and restored test-local
dispatch. Single local suite observations fall from about 20 seconds to about
4–5 seconds; whole-CI, RSS and production budgets remain unqualified. No Go/node
measurement, representative R1 data or state-value acceptance is introduced.
