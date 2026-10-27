# Bounded leaf commitment reuse in the recorded retention oracle

The optional `tools/conformance_leaf_reuse.py` scope reuses an unchanged leaf's
pure hash chain in the complete recorded 512/4096-key retention comparison.
The original checker, its byte oracle, producer source pins and recordings are
unchanged. It creates no database, fixture copy, disk cache or native executable.

The key is the complete `(depth, path bytes, value bytes)` tuple. Depth matters:
the same leaf can have a different remaining sparse path in another graph.
Empty, zero and absent values retain their distinct reference behavior. Each
graph still visits every selected leaf, hashes all internal branches and creates
fresh node and edge dictionaries in the original order. It uses no observed root
as a key and skips no proof, refcount, storage or completion check.

Only the explicitly selected, source-pinned `check_tree_scale.py` module (or its
complete original test suite) installs the scope. Its graph and byte dependencies
must have their original function identities and code. The scope requires one
serial caller; changed dependencies, a nested installation or another caller
thread refuse. Unsupported input types and sizes call the original graph.
The source pins are checked again at close, the original function is restored and
the process-local cache is cleared on success or exception. This is a cooperative
qualification tool, not authentication against another same-user writer.

The cache retains at most 8,192 entries and 2 MiB of logical key/result payload.
Input maps are capped at 4,096 entries and cached values at 4,096 bytes. LRU
eviction or a result exceeding the selected payload budget causes recomputation.
Python container overhead, the original full sparse tree and total process RSS
are separate quantities; the payload bound is not an RSS budget.

## Local comparison and verification scope

One local fresh-process comparison of the complete recorded checker retained an
identical report for all 252 root/proof cells, both histories and the twelve
originally recorded child outcomes. No new node or resource producer ran.
Controller-inclusive elapsed time was 10.386 seconds in reference mode and
2.711 seconds with reuse. This includes task-manager observation and capture;
it is one observation, not a controlled CPU benchmark or whole-CI speedup claim.

That reused invocation made 38 complete graph requests and 80,922 leaf requests:
4,746 misses and 76,176 hits. It computed 1,153,576 leaf parent hashes and avoided
18,509,805 repeated calls. Peak retained logical payload was 616,980 bytes in
4,746 entries, without eviction. These are counters for this finite oracle, not
representative node retention, hardware or production resource measurements.

The new controls compare complete root, commitment, node and edge bytes and
dictionary order against the unchanged original graph. They also exercise input
edits, depth changes, empty/zero/absent values, independent mutable results,
eviction, oversize fallback, original errors, thread/dependency refusal and
cleanup after exceptions. The complete original 24-root retention suite also
runs through the selected scope; no test or negative case is omitted.

```sh
python -I -B tools/conformance_leaf_reuse_test.py
python -I -B tools/gen-state-root-vectors/run_retention_leaves.py \
  --program check_tree_scale_test.py --mode reused --source-revision "$SOURCE_REVISION"
python -I -B tools/gen-state-root-vectors/run_retention_leaves.py \
  --program check_tree_scale.py --mode reused --source-revision "$SOURCE_REVISION"
```

Select `--mode reference` to run the unchanged calculation in a new process.
Do not repeat a completed reference capture or native experiment for bookkeeping.
Use the approved owned task manager for new qualification, preserve actual exit
and complete output and keep the production free-space floor plus reservations.

CI runs the new controls and both complete selected invocations on Linux amd64,
macOS Intel amd64 and Windows amd64. It uploads only three small JSON/JSONL
reports per platform, with the actual control names, current helper/runner/source
digests and reuse counters. The caller-provided revision field alone does not
authenticate the run. Bind it to actual workflow, job, step and artifact records.
Failed or incomplete jobs and outputs remain failure/UNKNOWN evidence.

This is current oracle execution evidence, separate from the old recorded
producer inputs and resource captures. It changes no native verifier, trust
anchor, profile or schedule. Representative R1 data, M2 agreement, accepted-v3
header-bound StateRoot and independent review remain separate gates. Runtime
state-value acceptance remains REFUSED.
