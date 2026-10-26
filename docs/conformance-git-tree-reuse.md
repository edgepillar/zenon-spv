# Bounded Git tree reconstruction reuse

The complete cache rollback recording controls repeatedly reconstruct the same
Git source trees while checking adverse payloads. An explicit process-local
execution scope reuses these pure results. Source files, source validation,
recordings, the original checker and all 18 original controls keep their bytes
and behavior. No runtime verifier or node implementation changes.

## Selected cost and inputs

In hosted run 40293219575, the macOS Intel cache rollback control step took
55 seconds. A separate full-suite local profile identified repeated source
planning as the principal cost. With the complete runner and one additional
whole-reader comparison, the direct profile makes 148 fresh expected-source
calls and 5,476 Git tree reconstructions.

The bounded profile keeps all 148 source validation calls. It performs nine
original tree computations and 5,467 complete-key hits. Both modes run the same
18 literal test identities and return the same complete original reader report.
The instrumented timing includes profiler overhead and does not measure ordinary
latency, process memory or a whole-CI speedup.

This scope selects only two already imported private instances of the pinned
regenerate.py function. The ten-file source allowlist and ordered instance
inventory are checked before entry and again on exit. Every miss calls the
unchanged original function. Function code, ownership, dependencies and the
caller thread are checked during calls. Later imports keep their original
functions. No global import hook or source-validation cache is installed.

## Complete keys, bounds and lifetime

Keys contain every ordered filename and every admitted mode, Git blob ID,
SHA-256 and byte-count field. A digest or reported tree cannot replace that
complete input. Ordering is preserved, including the original implementation's
behavior for prefix collisions. Input snapshots are compared again before
retaining or returning an answer. Cached Git object IDs and keys are immutable.
Cooperating serial callers must keep inputs stable; this is not an atomic
snapshot of data concurrently changed by another thread.

The default limits are 32 entries and 8 MiB of logical cached content. Admitted
maps contain at most 4,096 builtin entries with bounded builtin scalar fields.
Unsupported or larger inputs take the original path. Oversize results are
returned without retention; entry and byte pressure evict old results and a
later miss recomputes them. No required source or payload check is dropped.
Logical accounting includes all admitted field/value bytes and the result;
it does not bound Python object overhead or process RSS.

Every selected function is restored and the cache is cleared after normal
completion or an exception, including a Python interruption. Nested scopes,
changed source/function bindings and calls from a different thread are refused.
These controls do not qualify hardware power loss. There is no disk cache,
archive, hard link, dependency download, compiler or reference-node execution.

## Whole-program observations

Four fresh Python 3.9 processes on Darwin ARM64 ran in direct, bounded, bounded,
direct order. BSD time measured the child wall time and waited-child peak RSS
through exit; these values exclude the task manager and whole-system memory.
Both samples per mode preserve every original control name and the complete
original reader object.

| Complete controls plus reader | Direct median | Bounded median |
| --- | ---: | ---: |
| Child wall time | 12.81 s | 9.06 s |
| Child peak RSS | 37.61 MiB | 33.77 MiB |

The observed local wall reduction is approximately 29%; peak RSS is about
3.84 MiB lower. The bounded scope retains nine entries with 702,370 peak
logical bytes and no eviction in these samples. Context exit leaves zero
retained entries. These are finite working-source observations with explicit
execution hashes. The revision argument identifies their qualified base;
subsequent exact-commit hosted qualification is separate. No representative
hardware, whole-CI or production resource budget is established.

## Execution and controls

The separate runner pins the original test file, loads its literal complete
inventory and requires 18 actual tests with zero skips, failures, errors,
expected failures or unexpected successes. Zero-test discovery is refused.
It also compares the complete unchanged reader result and emits a small
source-bound completion manifest after restoration. A source-revision argument
is caller-selected metadata, not authenticated distribution.

```sh
python -I -B tools/conformance_tree_reuse_test.py -v
python -I -B tools/gen-state-root-vectors/run_cache_rollback_controls_test.py -v
python -I -B tools/gen-state-root-vectors/run_cache_rollback_controls.py \
  --mode direct --source-revision "$SOURCE_REVISION"
python -I -B tools/gen-state-root-vectors/run_cache_rollback_controls.py \
  --mode bounded --source-revision "$SOURCE_REVISION"
```

All 32 helper controls and 12 runner controls are additional to the original
18. They cover independent Git object framing, complete input metadata,
mutation, ordering, bounds, eviction, unsupported-input fallback, original
errors, dependency/source changes, thread ownership and restoration. The
original direct test command and independent reader remain available.

CI retains the complete original controls and fresh independent reader on Linux,
macOS Intel and Windows. Only this selected control execution uses the explicit
bounded scope and uploads its small JSON completion manifest. Source-bound CI,
artifact qualification and independent review remain separate. M0–M5, explicit
anchors/profiles/schedules/context pins and production state-value refusal keep
their existing boundaries.
