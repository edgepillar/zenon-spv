# Bounded recorded-retention table reuse

The complete recorded source-default retention program remains one 27-control
suite followed by its unchanged independent reader. Its 32,768-height witness
replay, six recorded processes, 900 proof matches, 180 pruned-proof refusals and
complete payload hashes remain required. This change reuses only the immutable
bytes of an already expanded table with identical complete inputs.

## Selected cost

At qualified main `834d551fc285bb2ec0cc7617e0164caa0023eadf`,
[CI run 43417753556](https://github.com/edgepillar/zenon-spv/actions/runs/43417753556)
spent 74 seconds in the macOS Intel recorded source-default retention step.
That is one hosted observation, not a hardware or whole-CI benchmark.
A separate complete local profile made 44 table expansions, with 3.26 cumulative
seconds in that function. The one required full history derivation took 8.18
cumulative seconds and is unchanged. Profiling overhead is not ordinary latency.

## Exact input and execution scope

The optional `--reuse-tables` flag on
`tools/gen-state-root-vectors/run_default_retention_checks.py` selects the new
`tools/conformance_table_reuse.py` scope. Without the flag, the direct path and
its receipt shape remain available. With the flag, the same suite and reader
run; a separate `table_reuse` receipt describes the computations and cache.
The original reader, model, 27-control file, corpus and producer inputs retain
their exact bytes and historical identities.

Each key retains the complete typed table metadata and all 32,768 ordered root
strings. It distinguishes booleans from integers, list order, dictionary order,
every nested field and every root byte. A hash, object identity, observed root
or table digest cannot replace those inputs. Even a changed valid root before
the pruned horizon makes a fresh expansion; invalid roots keep the original
refusal. Immutable output bytes can be shared; mutable input or report objects
are never returned from the cache.

Every miss calls the original pinned expansion. The original reader continues
to compare all expanded payload lengths/digests, history roots, proofs and
process/resource rows. Failed expansions are not cached. Unsupported types,
large metadata and results exceeding the bounds take the original path without
retention. Eviction recomputes a later miss and does not omit a required check.

The default bounds are four entries and 32 MiB of logical retained content,
including complete input keys and output bytes. Table metadata admits at most
4,096 nodes, 256 KiB of scalar content and 12 nested levels. Root count is fixed
at 32,768. These bounds exclude Python object overhead and process RSS.

Source bytes and function ownership are pinned. Dependency and snapshot/wrapper
bindings are checked during calls; source bytes are checked again on exit.
A process-local lease rejects concurrent or nested scope admission, including
during constructor source reads. Calls from another thread refuse. Only the
selected private reader instance is patched; later imports stay unchanged.
Success, exceptions and Python interruption restore the original function and
clear retained entries. These are cooperative serial-input guarantees, not an
atomic snapshot of concurrently modified data, a sandbox or power-loss proof.
The scope creates no disk cache, archive, hard link, download or node workload.

## Complete-program comparisons

Four fresh Python 3.9.6 processes on Darwin ARM64 ran in direct, bounded,
bounded, direct order. Each invocation ran all 27 original controls and the
complete reader. All four stdout streams exactly match the original 2,076-byte
report, SHA-256
`dc189500670563c4b51c4cc4fb809eee622fc47357ac45b869fc5e615e45c80d`.
The revision argument identifies the qualified base; separate working-file
hashes bind the measured implementation. Hosted qualification of a new commit
is a separate requirement.

| Whole program | Direct median | Bounded median | Samples per mode |
| --- | ---: | ---: | ---: |
| Child wall time | 12.27 s | 10.57 s | 2 |
| Waited-child peak RSS | 143.55 MiB | 151.93 MiB | 2 |

BSD `time` measured the child through exit. These figures exclude task-manager
work and whole-system memory. The finite local wall reduction is about 14%,
with about 8.38 MiB more peak child RSS. They do not establish a representative
hardware, whole-CI or production resource budget.

Both bounded samples made 44 expansion requests: five original computations,
39 hits and one eviction. Peak logical retained content was 25,996,710 bytes;
scope exit retained zero entries and bytes. The full history derivation and
every original report object stayed unchanged. No recorded node resource value
was replaced by these Python-process measurements.

## Controls and use

The 26 new helper controls cover complete keys, pruned prefixes, exact bytes,
input ownership, typed scalars, original errors, fallback, capacity, source and
dependency changes, concurrent construction, thread ownership and restoration.
Five mode controls cover the opt-in execution seam, failure/output boundaries
and actual usage processes. All 19 prior runner controls and all 27 original
recording controls remain required. Large-byte assertion failures emit bounded
length/hash diagnostics instead of dumping complete tables into CI stderr.

```sh
python -I -B tools/conformance_table_reuse_test.py -v
python -I -B tools/gen-state-root-vectors/run_default_retention_tables_test.py -v
python -I -B tools/gen-state-root-vectors/run_default_retention_checks_test.py -v
python -I -B tools/gen-state-root-vectors/run_default_retention_checks.py \
  --source-revision "$SOURCE_REVISION"
python -I -B tools/gen-state-root-vectors/run_default_retention_checks.py \
  --reuse-tables --source-revision "$SOURCE_REVISION"
```

Linux, macOS Intel and Windows keep their exact-source CI and artifact gates.
This is recorded-data qualification. Runtime verification, explicit
anchor/profile/schedule/context inputs, representative R1 data, actual network
consumer acceptance, independent review and release/production gates remain
separate. The original report still says `consumer_result: REFUSED` and does
not claim accepted-header root binding or newly executed node measurements.
