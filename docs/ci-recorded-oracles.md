# Separate recorded-oracle CI lane

The CI workflow runs 33 recorded-data commands in a separate job on Linux amd64,
macOS Intel amd64 and Windows amd64. The original 31-command selection keeps
all its controls and selected programs. Two larger-retention invocations now
use the explicit [bounded leaf commitment scope](retention-leaf-reuse.md); a new
control invocation checks that scope. Two complete import control suites now
use [explicit fresh child CLI recipes](import-resource-child-hex.md), with one
additional recipe-control invocation. The other 30 commands retain their
names and arguments from the 32-command leaf-scope selection. Commands remain sequential within that job. The
native verifier jobs run on separate hosted runners alongside this lane.
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

The current 33-command inventory has SHA-256
`c285ca19653067b71f8132e09ec07e50178eef5ec927c096c368d349d3879b6b`.
Its encoding is the ordered list of name/run objects, with sorted JSON keys,
compact separators and a final LF. Workflow expressions remain unexpanded in
that inventory. The preceding 32-command leaf-scope inventory remains
`60f485ae21bfc88c968ddb251accefe716c87fa247ce15f4d5a452f53b8bf280`.
The original 31-command inventory remains
`16fbc16ba92476d4e64d5ea5377e7702dcdb032eaa41d2e2073263418cfb60f0`;
do not relabel its earlier evidence as the new scope's qualification. The serial baseline is commit
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
