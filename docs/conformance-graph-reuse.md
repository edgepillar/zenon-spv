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

The option supports only `check_tree_driver_resources.py` and
`check_tree_driver_resources_test.py`. All original producer, checker, corpus
and sample files remain unchanged. The current runner and new helper have their
own execution pins; recorded producer source inputs retain their original
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
bytes, four function instances, complete test identities, actual graph calls,
lookup hits, bounds, restoration and cache clearing.

Local whole-program comparisons preserved every original summary object and
all 21 existing control identities. Each selected process made 54 graph requests:
33 original computations and 21 hits, with 33 retained entries, no eviction and
30,858,784 peak logical cached bytes. The separate 33-control suite compares all
512 single-bit path/value mutations against the pinned original graph, checks
the commitment against a separate full sparse-level oracle, and covers input
and result mutation, bounds, fallback, source/function changes, serial ownership
and failure restoration.

The local baseline-then-bounded elapsed observations are not counterbalanced and
include task supervision. They establish neither a whole-CI speedup nor process
memory or production resource budgets. Native Linux/macOS/Windows runs must
retain their own actual counts and full source/artifact qualification. Existing
test selections, content/retention grids, resource samples and all 59 offline
pilot scenarios remain required. Runtime verification, trust inputs, state-value
refusal, network acceptance and release gates are unchanged.

## Reproduce

Use an owned bounded workspace and cached dependencies. These portable commands
execute no reference node, Go build, LevelDB workload or new lifecycle observer.

```sh
python -I -B tools/conformance_graph_reuse_test.py -v
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_tree_driver_resources_test.py --mode translated --source-revision "$SOURCE_REVISION"
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_tree_driver_resources_test.py --mode translated --source-revision "$SOURCE_REVISION" --reuse-graphs
python -I -B tools/gen-state-root-vectors/run_target_hex.py --program check_tree_driver_resources.py --mode translated --source-revision "$SOURCE_REVISION" --reuse-graphs
```
