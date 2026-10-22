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

## Explicit selection and unchanged checks

`run_target_hex.py --reuse-child-hex` selects a test-local CLI dispatch only for
`check_patch_file_resources_test.py`. Each child is still a fresh interpreter.
It imports the pinned original checker, selects the existing independently
checked hex predicate in that process, and executes the original CLI entrypoint
guard. The checker, its original error handler, recorded corpus, samples and
producer source bindings are unchanged.

All 23 existing control methods, their assertions and their order remain
required. The only changes inside those methods route the same three calls
through the explicit dispatch. An AST fingerprint checks the entire original
control class after restoring those three call names. Without the new option,
the dispatch remains the original direct `subprocess.run`.

The selection changes no prospective-map copies, entry/byte limits, refusal
order or recorded resource values. It uses the existing bounded builtin-string
translation implementation; it introduces no new result cache, disk cache,
incremental counter, backend, Go build or reference execution.

## Console, source and completion binding

The child writes a separate bounded canonical recipe to a new report file in
the caller's owned temporary directory. It never appends that recipe to the
original console. Native text encoding and newline handling occur before the
captured bytes are emitted unchanged, including Windows CRLF behavior.

The parent checks complete source bindings from a separate import, selected
mode/revision, helper source, restored function ownership and the actual child's
exit and complete captured stdout/stderr bytes. Expected negative exits remain
negative; a declared exit cannot substitute for the actual subprocess result.
The complete parent recipe requires three children with exits `0, 1, 1`, the
original 23 passing controls and restored dispatch ownership.

The original parent hex recipe keeps its own scope: it still installs no import
hook and does not automatically modify later imports or subprocesses. The new
child recipe describes three separate explicit selections. Neither report
authenticates execution origin or establishes a production resource budget.

Twenty focused controls require the source/AST bindings, explicit dispatch
ownership, failure and nested restoration, thread ownership, exact command
selection, complete report shape, actual exit/stream equality, bounded exclusive
report files and independent returned records. Fresh ordinary CLI comparisons
also require exact success and failure console parity with the direct original
checker. Synthetic mocked records remain unit inputs, not native execution
evidence. Hosted platform checks require their own exact-source qualification.

The AST fingerprint encodes parsed node types, named fields, constants, bytes
and ordered children directly. It normalizes only the empty `type_params` list
added in newer Python grammars; nonempty type parameters, changed assertions,
literal types and method order remain inputs. It does not depend on the
version-specific debugging presentation of `ast.dump`. See the
[Python AST grammar](https://docs.python.org/3.13/library/ast.html).

Temporary reports belong to that fresh invocation and are removed after the
joined child is checked. Protected qualification logs and recipes use the
approved task-storage workflow. Historical evidence, worktrees and unpublished
storage-tool changes are outside this work.

## Local complete-program comparison

One uninstrumented local comparison preselected baseline, selected, selected,
baseline order. Each invocation used a fresh parent interpreter and completed
all 23 existing methods. Every complete parent hex-recipe object and ordered
method list was identical. Each selected invocation additionally bound three
fresh children with actual exits `0, 1, 1` and their unfiltered console bytes.

| Complete 23-control program | First observation | Second observation |
| --- | ---: | ---: |
| Direct original CLI children | 39.30 s | 39.96 s |
| Explicit selected CLI children | 6.49 s | 6.49 s |

The separate 20-control suite took 21.27 seconds with Python 3.9 and 16.74
seconds with Python 3.12 in two local passes. It includes a fresh direct
original success comparison, so its cost must also be included when assessing CI.
The table measures the selected complete program,
including imports and joined children, and excludes task-storage supervision.
It does not establish a whole-CI speedup, a memory peak or a production budget.
The local revision argument was a synthetic test label; retained source inputs
identify the precommit programs separately from hosted exact-source execution.

## Reproduce

Use an owned bounded temporary directory and retain actual command outcomes.
Both complete execution paths remain available:

```sh
python -I -B tools/gen-state-root-vectors/selected_child_hex_test.py -v
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_patch_file_resources_test.py --mode translated --source-revision "$SOURCE_REVISION"
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_patch_file_resources_test.py --mode translated --source-revision "$SOURCE_REVISION" --reuse-child-hex
```

This is qualification maintenance. Native inclusion trust inputs, the frozen
review candidate, M0–M5 acceptance gates and default state-value refusal remain
unchanged.
