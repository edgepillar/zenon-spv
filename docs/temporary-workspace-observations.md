# Temporary input and database observations

The offline reference wrapper selects the same literal 512/4096-key histories,
16 versions and eight retained versions. It delegates one build and all 24
ordered plain/allocation children to the existing lifecycle driver. Complete
file imports, map deltas, storage DAG/refcounts and every root/proof byte remain
independently checked. No node service, network acquisition or accepted
state-value consumer starts.

Each reference child receives a distinct owned `TMPDIR`. The wrapper observes
regular-file lengths and `st_blocks * 512` there before spawn, periodically
during its existing waits, and after reaping. Literal `input-*.raw` files and the
database directory have separate counters. Copied source/build files, compiler
and module caches, captured streams and evidence remain outside this directory.
The unchanged child creates and removes its own test fixtures and database.

These are **non-atomic stat traversals**. Concurrent writes, renames and deletion
can change the directory during one row. Vanished entries are retained, and
every actual point, partial failure and observation duration is recorded. The
reported maxima are the largest observed traversal values. They establish
neither true peak disk nor an instantaneous footprint; logical length and
allocated file blocks are also separate measures. Sampling I/O and scheduling
are included in these new child wall observations, so earlier recordings have
a different observation scope.

The selected observation interval is 100 ms, with at most 2,048 points per child,
8,192 directory entries per traversal, depth eight and a 256 MiB aggregate
logical-file acceptance ceiling. Each original command retains its 600-second
policy. These are finite acceptance/periodic controls, not hard disk bounds or
a hard whole-driver deadline. Symlinks and nonregular entries are refused. The
observer is for an owned test directory; it supplies no sandbox or hostile
shared-directory resolver. Source inputs and the compact report ceiling are
checked independently. Existing output/evidence paths are never overwritten.

The reproducer requires Darwin/Linux resource APIs. Its default offline caches
are reused without clearing; cold/warm cache status is unqualified. The checker
and envelope controls run on Linux, macOS and Windows without executing the
reference node or collecting a new workload measurement. Actual directory/stat
controls execute on Linux/macOS; Windows explicitly skips that Unix observer
suite. Synthetic envelopes in the control suite are not resource samples.

```sh
python -I -B tools/gen-state-root-vectors/observe_temp_workspace_test.py -v
python -I -B tools/gen-state-root-vectors/check_temp_workspace_test.py -v
python -I -B tools/gen-state-root-vectors/reproduce_temp_workspace.py \
  --node-source PINNED_NODE_SOURCE --go SELECTED_GO \
  --output NEW_PRIVATE_DIRECTORY/workspace-samples.json \
  --evidence-directory NEW_PRIVATE_DIRECTORY/workspace-evidence
python -I -B tools/gen-state-root-vectors/check_temp_workspace.py \
  --samples NEW_PRIVATE_DIRECTORY/workspace-samples.json
```

The separately selected local macOS ARM64 batch used Go 1.25.14 and retained all
24 fresh plain/allocation children in their original order. All 1,331 actual
stat rows, streams, exits, source selections and complete conformance bytes were
retained without retries or filtering. Each case below has 12 fresh children.
The ranges describe maxima of non-atomic traversals per child, in bytes.

| Initial keys | Observed points | Input file bytes observed | Database logical bytes observed | Database allocated bytes observed |
|---|---:|---:|---:|---:|
| 512 | 180 | 41849 | 420129 to 766513 | 442368 to 847872 |
| 4096 | 1151 | 281977 | 1803324 to 3373026 | 2527232 to 4079616 |

Vanished entries were retained in the raw rows. The results are finite local
observations of synthetic fixtures, not a real-archive, cold-cache or target
hardware budget. No timing improvement or simultaneous footprint is inferred.

Unsigned records do not authenticate source execution, target hardware, a real
archive/snapshot, complete or excluded state, retained Momentum hashes, accepted
headers/profile/activation, canonicality, finality or freshness. Compiler peak
memory, simultaneous pipeline memory, peak disk, real-data budgets, independent
review and authenticated release remain separate gates. Anchor, producer
schedule and context-pin requirements remain explicit. Every production
state-value consumer remains `REFUSED`.
