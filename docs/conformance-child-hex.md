# Explicit hex selection in fresh file-checker processes

The file-handoff control program starts three fresh Python CLIs. The existing
parent hex selection does not propagate into those processes. In PR run
`39778691048`, the complete control step took 129 seconds on macOS Intel and
98 seconds on Windows. These are hosted step observations, not hardware budgets.

A local instrumented parent took 42.09 seconds, including 37.37 seconds in three
subprocess waits. A separate profile of one original valid checker computation
took 57.48 seconds under profiling. Its pointwise hex predicate visited
750,872,654 characters. Profiling changes cost; these samples do not measure
ordinary CLI latency, memory peaks or a whole-CI improvement.

## Separate driver and unchanged historical sources

`run_file_controls.py` is an explicit execution choice for the complete
`check_patch_file_resources_test.py` suite. Each selected child is a fresh
interpreter. It imports the pinned original checker, selects the existing
independently checked hex predicate, and executes the original CLI entrypoint
guard. The checker, error handler, recorded corpus, samples and producer bindings
are unchanged.

The offline-rebuild corpus binds 189 research input files, including the original
control file and `run_target_hex.py`. All 189 remain byte-identical. The new
driver and test-local module facade have their own execution pins; no historical
source record or manifest is rebound.

The helper resolves the fresh directory returned by `TemporaryDirectory` before
constructing its report filename. This supports platforms whose default temporary
root has symlink ancestors. Explicit CLI report paths still pass the original
strict component checks, exclusive creation, size bound and readback identity
checks. The report controls also check refusal of the unresolved alias when the
platform supplies one.

All 23 original control methods, their assertions and order remain required.
A semantic AST fingerprint checks the entire original control class. Only that
already imported test module's `subprocess` binding selects a private facade;
the global stdlib module and later imports remain unchanged. The default direct
original path still uses the original `subprocess.run`.

The selection changes no prospective-map copies, entry/byte limits, refusal
order or recorded resource values. It uses the existing bounded builtin-string
translation implementation. It creates no result cache, disk cache, incremental
counter, backend, Go build or reference execution.

## Console, source and completion binding

Each child writes a bounded canonical recipe to a new report file in the
caller's owned temporary directory. It never appends a recipe to the original
console. Native text encoding and newline handling occur before the captured
bytes are emitted unchanged, including Windows CRLF behavior.

The parent checks complete source bindings from a separate import, selected
mode/revision, helper source, restored function ownership and the actual child's
exit and complete stdout/stderr. Expected negative exits remain negative; a
declared exit cannot substitute for the actual subprocess result. A complete
execution recipe requires three children with exits `0, 1, 1`, all 23 passing
controls and restored test-module ownership.

The original parent hex recipe keeps its own scope: it installs no import hook
and does not automatically modify later imports or subprocesses. The new child
recipe describes three separate explicit selections. The parent execution
recipe pins `run_file_controls.py` as the actual driver. It does not claim that
`run_target_hex.py` executed. Neither report authenticates execution origin or
establishes a production resource budget.

The focused controls require source/AST bindings, explicit facade ownership,
failure and nested restoration, thread ownership, exact command selection,
complete report shape, actual exit/stream equality, bounded exclusive report
files, independent returned records and preservation of all 189 historical
source inputs. They also refuse filtered, skipped, incomplete or untyped suites.
Fresh ordinary CLI comparisons require exact success and failure console parity
with the direct original checker. Synthetic mocked records remain unit inputs.
Hosted checks need their own exact-source qualification.

The AST fingerprint encodes parsed node types, named fields, constants, bytes
and ordered children directly. It normalizes only the empty `type_params` list
added in newer Python grammars; nonempty parameters, changed assertions,
literal types and method order remain inputs. It does not depend on the
version-specific debugging presentation of `ast.dump`. See the
[Python AST grammar](https://docs.python.org/3.13/library/ast.html).

Temporary reports belong to the fresh invocation and are removed after its
joined child is checked. Protected qualification logs and recipes use the
approved task-storage workflow. Historical evidence, worktrees and unpublished
storage-tool changes are outside this work.

## Complete-program comparison

Compare the complete direct-original and explicitly selected paths in fresh
processes, preserving all 23 method identities and results. Their source and
semantic bindings must match after excluding only the independently checked
execution-driver provenance. The different driver file and its SHA-256 remain
explicit; neither execution is relabelled as the other.

One local uninstrumented sequence used baseline, selected, selected, baseline
order. All four invocations completed the original 23 methods. The projected
parent recipes matched exactly, with only the separately verified current
driver source entry excluded from that comparison.

| Complete original 23-control program | First observation | Second observation |
| --- | ---: | ---: |
| Original direct CLI children | 38.89 s | 39.80 s |
| Separate driver with explicit child selections | 6.53 s | 6.39 s |

The focused 23-control suite separately took 21.86 seconds with Python 3.9 and
17.25 seconds with Python 3.12 on the same local host. These are individual
observations, not an interpreter or whole-CI performance comparison. The prior
7 offline-rebuild, 29 hex and 16 batch controls also passed unchanged.

The separate focused suite includes a fresh direct-original success comparison,
so its cost must also be included when assessing CI. Program timings include
imports and joined children and exclude task-storage supervision. Finite local
observations do not establish a whole-CI speedup, memory peak or production
budget. Local test revision labels are distinct from hosted source qualification.

## Reproduce

Use an owned bounded temporary directory and retain actual command outcomes.
Both complete execution paths remain available:

```sh
python -I -B tools/gen-state-root-vectors/selected_child_hex_test.py -v
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_patch_file_resources_test.py --mode translated --source-revision "$SOURCE_REVISION"
python -I -B tools/gen-state-root-vectors/run_file_controls.py --mode translated --source-revision "$SOURCE_REVISION"
```

This is qualification maintenance. Native inclusion trust inputs, the frozen
review candidate, M0–M5 acceptance gates and default state-value refusal remain
unchanged.
