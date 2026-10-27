# Explicit import resource child CLI recipes

The two complete recorded import control suites used the translated target-hex
path in their parent process, while their fresh default CLI checks still used
the original scalar path. A source-pinned profile found repeated validation in
`check_patch_targets.py::target_refusal`, rather than graph construction, as the
costly part of that original CLI. Profiling changes timing and is not a resource
budget or portable performance measurement.

The [new driver](../tools/gen-state-root-vectors/run_import_resource_controls.py)
selects the same complete 24 resource controls or 21 prior/candidate comparison
controls. The [child helper](../tools/gen-state-root-vectors/import_resource_child_hex.py)
selects only each suite's one default CLI call. The original test source,
assertions, ordering, recorded inputs, checker and `__main__` error guard remain
unchanged. The old `run_target_hex.py`, file-checker child helper and their
recorded source pins remain unchanged as well.

## Exact call and source scope

Each selected default CLI still starts in a fresh Python interpreter. The child
executes its pinned original entrypoint with its original default arguments,
under the existing explicit `reference` or `translated` target-hex recipe. The
parent receives the actual child's return object, stdout, stderr and exit.
The source-bound recipe travels through a separate bounded report file; no
recipe is stripped from or appended to the original console output.

Only the already imported test module's `subprocess` binding changes. The global
stdlib is not patched. Unknown programs, arguments, keyword types, call order,
threads, source hashes or nested/replaced dispatch refuse. The binding is
restored on ordinary exit and exceptions. This is an explicit test seam, not a
filesystem or process sandbox or authenticated execution attestation.

The comparison suite also retains its separate unselected-baseline refusal
process. That command, its generated test paths, arguments and 30-second timeout
pass through unchanged. Its actual exit must remain 1. The default successful
CLI keeps its original 120-second timeout. No call is retried, filtered or
replaced with a projected successful return.

Seven unchanged sources are pinned, including both original checkers, both
control suites, the existing target-hex recipe, shared strict report I/O helper
and prior-source rejection driver. The complete default console fingerprints
were separately captured from the original CLIs. Controls require the same
whole stdout, allowing only its declared native LF or Windows CRLF form, empty
stderr and actual exit 0. They also reject mismatched exit, stream, source,
recipe, completion and authority fields. Mocked records remain unit inputs;
the two fresh translated CLI observations are recorded separately.

## Local observations and CI

One local comparison retained the same complete original suite roots and the
same parent target-hex bindings, except for the independently selected driver:

| Complete suite | Original parent-only recipe | Explicit child recipe | Original roots |
| --- | ---: | ---: | ---: |
| Import resource controls | 20.296 s | 4.302 s | 24 |
| Prior/candidate comparison controls | 20.490 s | 4.501 s | 21 |

These are single controller-inclusive elapsed observations. They do not qualify
whole-CI speedup, process RSS, hardware budgets or a production workload.
The 19 additional controls passed without failures, errors or skips. The two
original suites retained three fresh Python processes: two default successful
CLIs and the unchanged prior-source refusal. No Go build, node, dataset download
or archive copy was needed for this comparison.

The original CLIs still report the same recorded 144 and 288 resource samples.
Those are historical producer observations, not new Go or node measurements.
All original source, corpus, sample, callback, ownership and refusal checks
remain required.

The [recorded CI lane](ci-recorded-oracles.md) selects 33 commands: all preceding
32 command names remain in order, two import-suite invocations use the new
driver, and one invocation runs the new recipe controls. All native Go jobs,
benchmarks, ordinary/race tests, timeouts, candidate binaries and acceptance
rules remain unchanged.

Each platform uploads one `import-resource-child-<platform>` artifact containing
exactly `controls.json`, `resources.json` and `comparison.json`. The control
report binds its exact checkout source files and two real child observations;
each complete-suite report binds the parent recipe, all original root names,
actual child records and restored local dispatch. These small reports contain
no source tree, dataset, executable or nested archive. Partial reports can be
retained after failure and do not qualify completion. Require actual successful
jobs/steps and separately reconcile every artifact against the selected source,
run, attempt, platform, SHA-256, original console fingerprints and complete test
inventory. A local result does not qualify a new revision's hosted CI.

The existing strict I/O helper bounds a canonical recipe at 256 KiB and requires
a new ordinary report path with a physical directory ancestry. Only owned
temporary report directories are created and closed; no disk cache, hard links,
shared evidence aliases or historical cleanup is introduced. The selected child
also checks its console byte bounds. These are implementation bounds, not a
total process-memory or OS-enforced quota claim.

This work qualifies offline checker recipes. It does not supply representative
R1 data, snapshot completeness, agreed profile rules, header authentication,
network activation, state-value acceptance, independent review or authenticated
distribution. Runtime state-value refusal and the M0–M5 gates remain in place.
