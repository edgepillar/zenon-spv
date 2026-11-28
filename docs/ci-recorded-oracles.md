# Separate recorded-oracle CI lane

The CI workflow runs 22 recorded-data steps in a separate job on Linux amd64,
macOS Intel amd64 and Windows amd64. Two larger-retention invocations use the
[bounded leaf commitment scope](retention-leaf-reuse.md), with a separate control
invocation. Two complete import control suites use
[explicit fresh child CLI recipes](import-resource-child-hex.md), with a separate
recipe-control invocation.

One Python process checks the recorded workspace, driver/build resources,
file-backed NodeTree import, reference-child lifecycle, sparse oracle projection,
and complete driver projection. For each pair, the original checker verifies
the recording before the complete control suite runs. The pair shares one
bounded graph scope keyed by the complete ordered state bytes. Its original
report and separate source-bound completion record include the full check results
and the control names.

The first pair computes the scale model with the original reference checker.
The other five pairs verify the source files, corpus digest, reference function,
and selection before decoding their own copies from the bounded 256 KiB
serialized model. Individual pairs retain independent check inputs and the
controller restores each selected function when that pair finishes. The final
completion record requires one computation and five reuses, with the model
cleared. The original per-pair commands remain available for separate replay.
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

The current 22-step inventory has SHA-256
`303d665899283f8d95286c26b1b85c5f033e591b48e605c052ec4a561e8037d0`.
Its encoding is the ordered list of name/run objects, with sorted JSON keys,
compact separators, unexpanded workflow expressions and a final LF. The prior
26-step inventory with two shared scale readers had SHA-256
`e38ae1b3ae132831a082d07473861eb58788e280a9717e752531120e7406a8c0`.
The preceding 27-step inventory with separate workspaces had SHA-256
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

The recorded-oracle archive contains the small selection manifest and the
grouped check's original results and completion records in
`scale-model-checks.jsonl`. A complete file has six original reports, six
per-pair completion records and the final model-reuse record. The leaf and
import-child scopes upload their own small reports per platform. Always-run
uploads preserve available reports after a control fails. Actual job and step
outcomes and the final completion record establish whether the grouped check
finished. The archive contains reports and their pins. Use the approved local
task-storage manager for bounded artifact transport and retain each verified
object once.

## Timing evidence and acceptance

One Darwin arm64 run with Python 3.9.6 compared the five prior invocations
with the grouped invocation. Both ran all 146 controls and produced the same
six original checker reports byte for byte. Model computations fell from
five to one. Total elapsed time was 69.51 seconds for the prior invocations
and 19.90 seconds for the grouped invocation. The grouped output used 61,452
bytes and the model cache wrote no files. These are local observations over
the recorded inputs.

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
