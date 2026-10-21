# Cache iterator read errors

The selected experimental cache returned successful zero amounts and a successful
inactive-spork result after its real database manager had been stopped. A direct
iterator over the same closed handle reported `leveldb.ErrClosed`. The initial
`Last` failure in `cacheStore.findValue` returned an empty value without checking
`Error`; the public amount and spork getters consequently lost that error.

The experimental successor checks the initial iterator error and returns the
original error. Healthy empty results, populated values, historical reverse
selection, backward-iteration errors and the height-one spork shortcut remain
unchanged. Callers still own view lifetime and history serialization. This is a
sequential error-handling comparison, not concurrent-lifecycle qualification.

## Recorded real-manager comparison

The [source patch](../tools/gen-state-root-vectors/testdata/candidate-cache-read-errors-patch.json)
extends digitalSloth/go-zenon at
[9c71ae82fc983e16f914ae085d4034030c8ebe3b](https://github.com/digitalSloth/go-zenon/commit/9c71ae82fc983e16f914ae085d4034030c8ebe3b)
and the preceding experimental runtime
69b0844bccc68273b2b367cda7706d933d45358f. The successor runtime tree
c5e413c43794b3ba32763484670db2b100295a15 adds one unit source and changes only
the initial error check in `chain/cache/store.go`. Other function bytes and
all preceding experimental changes are preserved.

One ordinary build per variant ran two ordinary processes on Darwin ARM64 with
Go 1.25.14. The first process opened an empty real cache database, extracted
selected chain-plasma and fused-amount patches, queried populated and absent
values, stopped its own manager normally, then queried previously acquired
views. The second process reopened that same closed cache, repeated the
queries and closed it again.

| Observation per variant | Baseline | Successor |
| --- | ---: | ---: |
| Ordinary processes | 2 | 2 |
| Getter observations | 19 | 19 |
| Healthy or genuinely empty getter results | 13 | 13 |
| Closed-view calls without the expected database error | 6 | 0 |
| Direct closed-iterator error observations | 2 | 2 |

The nominal identifier at height two is a fixed cache-component selection, not a
computed or verified momentum header. One nonempty account-block row selects
the actual cache extractor; no account block is executed or inserted into a
ledger. These ordinary processes exercise a cache manager and extractor only.
They execute no public Chain, state tree, VM, wallet, signing or peer network.
Plasma and fused amounts remain outside the partial SMT proof domain.

A separate ordinary Go test invocation selected three packages. All 41 root tests
and 50 pass results completed with zero skips: 29 preceding chain pass names,
six existing cache/storage roots, and 12 new cache roots producing 15 pass
results. These units also execute selected public Chain manager regressions.
They include a real merged iterator's unsupported reverse traversal and retained
views after a real cache manager closes. They do not qualify a full node.

## Independent bytes and evidence limits

The [record](../tools/gen-state-root-vectors/testdata/native-cache-read-errors.json)
retains all four exact JSONL payloads: 58 events and 38 getter observations.
The independent model selects literal values before backend execution and
reconstructs the input patch, extracted cache patch, protobuf frontier,
existence marker, rollback journal and all four raw database records. It
computes the complete logical image digest using ordered keys/values and
64-bit lengths. All six closed-image observations match through reopen and
across both variants.

These are complete logical-record comparisons, not equality of LevelDB files
or hardware crash/power-loss qualification. Payload hashes and the private,
unsigned original capture do not authenticate their own origin. The portable
reader checks the retained bytes and source/build/test inventories; it
executes no reference backend or resource observer.

## Reproduction and resource bounds

Run the portable checks without a node or new dependency download:

    python -I -B tools/gen-state-root-vectors/prepare_cache_read_errors_test.py -v
    python -I -B tools/gen-state-root-vectors/check_cache_read_errors_test.py -v
    python -I -B tools/gen-state-root-vectors/check_cache_read_errors.py \
      --source-revision "$SOURCE_REVISION"

For another backend comparison, use approved task-managed scratch and the
unchanged pinned node source. The preparer refuses existing or linked
destinations, verifies every source file, and emits the exact unit, build and
two-process recipe:

    python -I -B tools/gen-state-root-vectors/prepare_cache_read_errors.py prepare \
      --node-source "$PINNED_NODE_SOURCE" --workspace "$NEW_OWNED_WORKSPACE" \
      --go "$PINNED_GO" --variant candidate

Retain the production free-space floor of 10 GiB plus the expected 2 GiB
allocation and other reservations. The suggested task quota is 3 GiB. The
recorded successor unit command and ordinary build shared one owned build
cache. Verified source/dependency objects were reused, the baseline was not
rerun for the successor, and no new external source, dependency or artifact
transports occurred. Close all processes and handles before clearing only the
declared generated workspace; retain failures and exact source/output pins.

The native verifier's state-value result remains REFUSED. This comparison
does not establish cache-value authentication, accepted-header binding,
profile agreement, activation, independent review or authenticated
distribution. The separate [M2–M5 gates](native-roadmap.md) remain open.
