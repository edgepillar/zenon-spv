# Separate recorded-oracle CI lane

The CI workflow runs 26 recorded-data steps in a separate job on Linux amd64,
macOS Intel amd64 and Windows amd64. Two larger-retention invocations use the
[bounded leaf commitment scope](retention-leaf-reuse.md), with a separate control
invocation. Two complete import control suites use
[explicit fresh child CLI recipes](import-resource-child-hex.md), with a separate
recipe-control invocation. The combined workspace command verifies the recorded
observations first and then runs all five envelope controls in the same Python
process. The recorded check constructs the reference import model. The envelope
controls reuse that model and validate their own inputs. The dedicated workspace
runner emits a source-bound completion receipt after both checks succeed and their
scopes close. The CI step also runs the workspace runner controls.
The same runner pairs the original recorded check and the complete control
suite for file-backed NodeTree import, reference-child lifecycle, driver and
build resources, sparse oracle projection and complete driver projection.
Each pair validates the recording with the original checker before its controls
run. Both phases share the checker's expected document and one bounded
in-memory graph scope keyed by the complete ordered state bytes. Each control
still validates its own inputs. The runner retains the original checker report
in the job log and emits a separate source-bound receipt with all control names
and graph accounting after both phases finish.

The workspace and driver/build pairs share one process and one bounded scale
model. The first pair computes the model with the original reference checker.
The second pair verifies the same source files, corpus digest, reference
function and selection before decoding a private copy of the model. The
256 KiB serialized-model limit applies between the pairs. The controller
restores both original functions and clears the model after both reports and
all 26 controls complete. Other pairs retain their own processes.
The native verifier jobs run on separate hosted runners alongside this lane.
See the [GitHub-hosted runner model](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)
for its VM isolation and runner-image limits.

The source checkers, original reference implementations, producer inputs,
recorded fixtures and resource counters are unchanged. No test filter, case,
repetition, retention grid, deadline or acceptance budget is removed. The Go
jobs retain their complete ordinary/race tests, builds, module-cache checks,
native resource observations and candidate export/consumer checks.

## Selection and isolation

The moved commands previously appeared once in the Linux job and once in the
macOS/Windows matrix. They require the existing Python 3.13 setup and repository
files. They check recorded resources rather than launching a new node, database
workload or Go build. Some existing controls still launch fresh Python CLIs and
use their own temporary test files.

The current 26-step inventory has SHA-256
`e38ae1b3ae132831a082d07473861eb58788e280a9717e752531120e7406a8c0`.
Its encoding is the ordered list of name/run objects, with sorted JSON keys,
compact separators, unexpanded workflow expressions and a final LF. The
preceding 27-step inventory with separate workspaces had SHA-256
`549a728ca9de3d33156f1ffb0902639d7f12a671ecfb0797893d1fcb3e96e0d9`.
The earlier 32-command inventory with separate tree checks had SHA-256
`b6740942f8c048d4a0f9490eddbfa1fcef396ad1952561293a8413425dd69eab`. The earlier
33-command inventory with separate workspace invocations had SHA-256
`c285ca19653067b71f8132e09ec07e50178eef5ec927c096c368d349d3879b6b`.
The 32-command leaf-scope inventory had SHA-256
`60f485ae21bfc88c968ddb251accefe716c87fa247ce15f4d5a452f53b8bf280`. The original
31-command inventory had SHA-256
`16fbc16ba92476d4e64d5ea5377e7702dcdb032eaa41d2e2073263418cfb60f0`.
Each inventory identifies its own evidence. The serial baseline is commit
`59ab5184d2e983f2322ff9e730a86cd19217970b`; its workflow bytes have SHA-256
`407cf9a5da9fca75957f570981694ecc7bd17a4f29ae3ce4f697f40a17d4421a`.

Before its controls, each lane writes one selection manifest of at most 8 KiB.
It binds the actual checkout and tree, PR feature revision, run/attempt/event,
platform/runtime, exact Git workflow content and working-checkout relation.
Only exact content or an explicitly recorded CRLF-only conversion is admitted.
The manifest selects the command inventory; it does not report test success or
authenticate execution. Require the actual hosted job and every selected step
to complete successfully, and reconcile their source/run/platform identity.

The scheduling change's artifact is that small JSON manifest, retained for 14
days. The later leaf scope and import child scope each upload three small result
reports per platform. Always-run uploads preserve available reports after a control
fails; incomplete output is not completion. No fixture, source
tree, database, executable or second payload ZIP is copied into it. Native
candidate artifacts keep their existing identities and qualification scope.
Use the approved local task-storage manager for bounded artifact transport and
retain each verified object once. Do not download native payloads merely to
qualify this workflow-only scheduling change.

## Timing evidence and acceptance

One local Darwin arm64 comparison ran each of the five pairs once in each
mode with the same recorded inputs. The paired run retained all 141 controls
and reproduced each original checker report. Full reference graph calls fell
from 349 to 184. The elapsed time for the ten separate processes was 134.76
seconds. The five paired processes took 70.15 seconds. The graph cache wrote
no files. These timings describe the selected local runs.

The hosted baseline took 271 seconds for the ten selected Linux steps, 508
seconds for macOS and 375 seconds for Windows. [Baseline CI](https://github.com/edgepillar/zenon-spv/actions/runs/44926642106)

In baseline CI run
[40224397389](https://github.com/edgepillar/zenon-spv/actions/runs/40224397389),
the successful Linux, Windows and macOS jobs took 1,750, 2,232 and 3,010 seconds.
The macOS control steps included 79 seconds for child hex execution, 74 seconds
for owned patch callback reuse and 73 seconds for whole owned patch import.
These are individual hosted observations with an unauthenticated hardware and
load context. They do not establish a portable performance budget.

The scheduling change permits overlap without sharing a runner with native
measurements. Available hosted-runner concurrency, queue time and workload
variance affect the result. Record new exact-source job timings before claiming
an observed improvement; do not infer a guaranteed CI speedup from this plan.

Qualification must compare the complete per-platform command inventory with
the serial baseline, preserve every remaining native step and validate the new
manifest-producing code. All three native and three recorded jobs, plus the
separate change-scope job, must pass for a selected full-runtime PR and merged
source. Reconcile each small lane artifact with the actual jobs, source tree,
workflow bytes and selected command inventory. Green CI and mechanical artifact
checks do not qualify real R1 data, agreed state-root rules, accepted state
values, independent review or authenticated distribution.
