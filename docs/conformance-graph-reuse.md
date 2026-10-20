# Bounded reuse of complete conformance graphs

The recorded driver resource checker imports four private instances of the
same independent compressed-graph oracle. Each instance can encounter a byte
map already checked elsewhere in that same serial Python process. Rebuilding
the identical roots, complete node encodings and edges repeats pure hashing.

An explicit `--reuse-graphs` option on the current execution runner shares these
complete results within the selected driver checker or its complete existing
21-control suite. Every admitted cache miss executes the original source-pinned
`graph` function. The unchanged complete checker still compares every required
root, physical record/refcount, proof, sample, actual child outcome and source
binding. No observation or claimed root supplies an expected oracle result.

The option supports `check_tree_driver_resources.py`,
`check_temp_workspace.py`, `check_projected_driver.py` and their three complete
existing test programs. Their respectively selected graph instance counts are
four, twelve and twelve; the projected driver test program selects sixteen
instances because it also imports the earlier driver's controls. Exact source
pins and ordered instance inventories are required for every selection.
All recorded producer, reader, corpus, sample and runner files remain unchanged.
The unchanged runner preserves its historical source bindings. The extended
helper and the current execution recipe have their own pins; recorded producer source inputs retain their original
meaning. Original commands without the option remain available.

## Input, ownership and lifetime

A cache key contains the full ordered builtin byte-key/value map, including
every path and value byte. A digest, report identity or selected root cannot
replace those inputs. Both the original computation and a hit recheck the
admitted input before retaining or returning a result. The cooperating serial
caller must keep its private inputs stable; this is not an atomic snapshot of
data concurrently modified by another thread.

Cached roots and complete node/edge tuples are immutable. Each call receives
fresh independent dictionaries. Changing a returned dictionary or the caller's
later input cannot alter an earlier cached answer. Source bytes are checked
before reference import and selection. Function and byte-oracle bindings are
checked during calls; source bytes and function ownership are checked again
when leaving the context.

Every selected graph function is restored and the cache is cleared on success
or failure. A nested selection, changed binding or different caller thread is
refused. Later imports and subprocesses retain their original functions. The
cache creates no file, hard link, executable alias or cross-process store.
Fresh executable builds and ordinary child processes remain unchanged.

## Bounds and evidence

The default limits are 64 entries and 64 MiB of logical cached byte content.
The accounting includes input bytes, both roots, complete node keys/encodings
and complete edge keys/children. It does not measure Python object overhead or
process RSS. Admitted states contain at most 4,096 entries with 32-byte paths
and at most 4,096 value bytes per entry.

Non-builtin or larger inputs use the original function without retention.
Results exceeding the cache byte limit also remain ordinary original results.
An entry/byte limit evicts old entries; a later request recomputes a missing
answer. Limits bound reuse and never authorize dropping a required graph or
sample check. There is no persistent cache or whole-process memory claim.

The current runner emits a separate
`bounded-conformance-graph-reuse-execution` manifest alongside its existing hex
recipe and unchanged complete checker summary. The added manifest binds the
program, revision argument, current helper/runner source, selected reference
bytes, the selected function instances, complete test identities, actual graph calls,
lookup hits, bounds, restoration and cache clearing.

The initial driver-only whole-program comparisons preserved every original summary object and
all 21 existing control identities. Each selected process made 54 graph requests:
33 original computations and 21 hits, with 33 retained entries, no eviction and
30,858,784 peak logical cached bytes. The separate 33-control suite compares all
512 single-bit path/value mutations against the pinned original graph, checks
the commitment against a separate full sparse-level oracle, and covers input
and result mutation, bounds, fallback, source/function changes, serial ownership
and failure restoration.

The initial local baseline-then-bounded elapsed observations were not counterbalanced and
include task supervision. They establish neither a whole-CI speedup nor process
memory or production resource budgets. Native Linux/macOS/Windows runs must
retain their own actual counts and full source/artifact qualification. Existing
test selections, content/retention grids, resource samples and all 59 offline
pilot scenarios remain required. Runtime verification, trust inputs, state-value
refusal, network acceptance and release gates are unchanged.

The workspace and projected-driver extension was selected from measured CI
cost. In main run `39505957805`, workspace controls took 117 seconds on macOS
Intel and projected-driver controls took 86 seconds. These are individual
hosted step observations, not an authenticated hardware benchmark. A separate
local workspace-reader profile reported 18.6 cumulative seconds in 54 complete
graph computations. Profiling adds overhead and does not
measure ordinary checker latency or process memory. The extension changes only
the explicit source and instance allowlists; the cache, complete graph function,
byte keys, bounds, fallback and restoration implementation are unchanged.
The six additional controls exercise every expanded selection, input/result
independence, failure restoration, replaced/extra instances and all added
source pins. The original 33 controls remain required.

Complete local comparisons retained every original summary object and all five
workspace and thirty projected-driver control identities. The workspace reader,
workspace controls and projected-driver reader each made 54 graph requests:
33 original computations and 21 hits, with 30,858,784 peak logical cached bytes.
The projected-driver controls made 57 requests: 34 original computations and
23 hits, with 30,859,849 peak logical cached bytes. No eviction occurred.
Observed serial elapsed
times, including task supervision, were:

| Complete program | Without reuse | With reuse | Samples per mode |
| --- | ---: | ---: | ---: |
| Workspace reader | 19.60 s | 14.56 s | 2, median; forward then reverse order |
| Workspace controls | 22.26 s | 16.65 s | 1 |
| Projected-driver reader | 20.62 s | 15.90 s | 1 |
| Projected-driver controls | 23.72 s | 18.16 s | 1 |

These finite local observations are not a representative hardware benchmark,
process-memory measurement or whole-CI speedup. The other three pairs ran
without-reuse first. Each invocation used a fresh Python process; no persistent
cache, new download, archive, node experiment or Go build was created.

## Reproduce

Use an owned bounded workspace and cached dependencies. These portable commands
execute no reference node, Go build, LevelDB workload or new lifecycle observer.

```sh
python -I -B tools/conformance_graph_reuse_test.py -v
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_tree_driver_resources_test.py --mode translated --source-revision "$SOURCE_REVISION"
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_tree_driver_resources_test.py --mode translated --source-revision "$SOURCE_REVISION" --reuse-graphs
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_tree_driver_resources.py --mode translated --source-revision "$SOURCE_REVISION" --reuse-graphs
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_temp_workspace_test.py --mode translated --source-revision "$SOURCE_REVISION" --reuse-graphs
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_temp_workspace.py --mode translated --source-revision "$SOURCE_REVISION" --reuse-graphs
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_projected_driver_test.py --mode translated --source-revision "$SOURCE_REVISION" --reuse-graphs
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_projected_driver.py --mode translated --source-revision "$SOURCE_REVISION" --reuse-graphs
```
