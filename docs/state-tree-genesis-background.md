# Source-genesis background build observations

The experimental terminal-node tree now has a recorded execution of its actual
`Chain.Init`, `Chain.Start`, background build batches and `Chain.Stop` paths on
the pinned node's embedded genesis projection. Nine complete component processes
cover pruned/archive builds, clean reopen and a controlled stop/resume. This is
M4 component evidence. A complete node, representative production retention,
accepted v3 headers and production state values remain unqualified.

## Source and independently selected input

The original node is
[`digitalSloth/go-zenon@33d7d1ee1b6a915c40aea196e2a10f1e893d171f`](https://github.com/digitalSloth/go-zenon/tree/33d7d1ee1b6a915c40aea196e2a10f1e893d171f):
439 blobs, Git tree `40d71efb7e462d5bbd0f27d83ed7588e121c3cb6`.
The [retained-identity](state-tree-hash-bound-versions.md) and
[terminal Stop](state-tree-terminal-stop.md) proposals produce runtime tree
`d3d9215bc9ea23b2e700aad53ebb23d4bdea3428`, excluding the component probes.
This experiment injects no scheduler checkpoints into runtime source. The
retained disk marker is 3; this is separate from Momentum version 3.

The source-only [input generator](../tools/gen-state-root-vectors/genesis-input/main.go)
calls the node's embedded genesis constructor in memory. It checks the unsigned
version-1 envelope, empty signature/public key, chain identifier 1 and source
genesis hash `9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0`.
It starts no node or service and performs no signing or broadcast. Two fresh
generator processes produced the same 10,849,399-byte raw patch, SHA-256
`a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75`.
This is a source-selected genesis, not an authenticated testnet checkpoint or
consumer trust anchor.

An independent Bech32/u256 decoder compared all 14,091 source balance entries
with the complete dump. Its 103,821 logical keys project to 19,257 nonempty SMT
leaves: 14,091 balances and 5,166 contract-storage values. The projection excludes
84,564 other logical keys. The independent initial root is
`864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d`.
Fifteen witnesses include balances, storage, two missing balances and an existing
excluded ledger key. Absence from this projection does not prove ledger absence.

Height 1 applies that source-derived state. Heights 2–4,096 cycle through eight
selected balance keys: delete at multiples of 11; otherwise store 32 zero bytes
at multiples of 7; otherwise store uint256 big-endian `1,000,000 + height`.
Identifiers are unsigned SHA3 hashes of `synthetic-hash-bound-node-v1/G/HEIGHT`.
These suffix patches are not VM transition validation or accepted headers.

Before any new backend run, separate Python models sealed all 4,096 roots and
the selected canonical proof bytes at heights 1, 3,840, 3,841, 3,968 and 4,096.
The initial/full-final two-layer reconstruction and the selected-witness update
forest agree. Six old roots, 22 canonical old proofs and 76 finite update
comparisons also remain controls. The final independent root is
`886e79750c9cbe90479e8e4a4f3afe81a07f26bdc11601bbee79a86a5415d465`.

## Executed lifecycle and retention

The manager, cache and genesis interfaces are controlled in-memory adapters;
the tree worker and its private on-disk LevelDB are the actual component.
`Init` leaves the large gap unready. `Start` executes the actual build; selected
root/proof reads, `Stop`, read-only closed inspection and a new instance's clean
`Init` are checked against the independent expectations. Each selected patch is
requested exactly once, including across the controlled restart.

The test-only retention override is 256. The implementation prunes heights
**strictly below** `frontier - retention`, so final height 4,096 keeps roots
**3,840 through 4,096 inclusive: 257 roots**. The bulk endpoint at 3,840 remains
available; height 3,839 refuses. Archive mode retains all 4,096 roots. This
experiment records the actual boundary and does not change the retention policy.

All retained root/hash pairs are checked. Before stop, after close and after
clean reopen, each case has the same complete logical-record digest/counts and
selected queries. Wrong-hash queries refuse separately from missing versions.
After Stop, public reads refuse as not ready and direct backend reads report
database closed. The race stop/resume case holds the first manager patch call,
publishes stop intent, commits height 1, joins and closes, then continues on a
fresh component instance. This controlled stop is not SIGKILL or power loss.

## Recorded resource scope

Go 1.25.14 with CGO, `GOMAXPROCS=2`, frozen modules and a local offline proxy was
used on one macOS arm64 host. The normal binary was built once for the corrected
probe, retained by SHA-256 and reused as an independent APFS clone. The race
binary was built once separately. Three fresh normal processes per policy and
one race process per policy were retained; stop/resume has one additional race
process. Compiler caches are separate from each database and are removed by
their owning task after evidence retention.

| Normal policy, three processes | Pruned | Archive |
| --- | ---: | ---: |
| Final retained root/hash pairs | 257 | 4,096 |
| Logical records | 84,366 | 189,342 |
| Logical key/value bytes | 7,503,024 | 17,593,329 |
| Final closed regular-file bytes, observed range | 6,842,898–6,845,888 | 15,046,041–15,047,736 |
| Whole waited-process peak RSS bytes, observed range | 179,552,256–195,084,288 | 172,867,584–180,174,848 |
| Whole waited-process wall seconds, observed range | 2.293–3.523 | 9.192–9.250 |

Waited-process RSS and CPU include controlled fixture setup, input decoding,
queries, snapshots and test output. They exclude the compiler/controller and
are not isolated NodeTree allocation measurements. Internal phase timers have
a narrower scope; the component workflow timer excludes initial input decoding
and the final physical-file hashing. Race observations qualify only the declared
functional schedules and are excluded from the normal resource table.

File lengths are post-close observations, not peak disk use, allocated-block
measurements or physical APFS reclaim. There is no controlled cold-cache
comparison, agreed hardware/concurrency budget, full production retention grid,
representative ongoing VM workload or complete-node measurement. Complete
logical-record digests are compared across lifecycle phases; every node/refcount
byte in this larger state was not independently reconstructed. All 4,096 roots
and the 1,350 selected before/after proof observations retain their own scope.

The first new probe process exited 2 because its metadata decoder used node
prefix `01` for version roots, whose actual prefix is `03`. Its actual streams
and failed database were retained. The corrected process completed, but the
initial checker reused an older A/B/X-only helper for the new G label. That
checker defect was corrected; the complete original process was rechecked and
retained as the first normal pruned sample without executing it again. Neither
case caused a runtime patch or a hidden replacement of a failed measurement.

## Reproduction and portable checks

Use approved owned task storage with explicit output, task/scratch/object quotas
and the 10 GiB free-space floor plus expected allocations/reservations. Keep
source/toolchain acquisition separate. Preserve original streams and failure
state before removing newly owned disposable databases. Successful database
scratch is removed after the complete reports and checked inputs are retained;
the measured physical database files are not exported as a release artifact.
No historical cache or existing database is adopted or cleaned by these tools.

The [preparer](../tools/gen-state-root-vectors/prepare_genesis_background.py)
verifies the full node snapshot, exact patch/inverse, unchanged module lock and
explicit six-file compiler overlay. It stages only a nonexistent caller-owned
workspace. Its resource/race modes return build/run plans and the four required
run environment selections; they execute no commands. Build each selected mode
once, use a fresh case directory per process and bound both output streams.
The [wait4 wrapper](../tools/gen-state-root-vectors/measure_genesis_background.py)
measures the foreground component process on macOS/Linux and performs no cleanup.
Windows process-memory measurement is not implemented by that wrapper.

The input generator must be built as its explicit single Go file inside a
prepared module with the full selected source replacement. Its stdout is binary
patch data and requires a 32 MiB cap, SHA-256 verification and one retained CAS
object. Its metadata goes to stderr. Do not turn binary stdout into a second ZIP.
Then independently reconstruct the complete initial/final projection and history:

```sh
python3 -I -B tools/gen-state-root-vectors/derive_genesis_background.py \
  --input VERIFIED_SOURCE_GENESIS_DUMP --node-source PINNED_COMPLETE_NODE_SOURCE
```

The compact [recorded corpus](../tools/gen-state-root-vectors/testdata/candidate-genesis-background.json)
stores equal root/query tables once and uses explicit references. Original full
outputs remain separate protected evidence. Its source pins, prelaunch evidence
hashes, closed sample manifest and actual exit/completeness fields are retained;
these hashes are not distribution authentication. Portable checks run without
new node, LevelDB, CGO or network execution:

```sh
python3 -I -B tools/gen-state-root-vectors/check_genesis_models_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_genesis_background_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_genesis_background_corpus.py
```

The 13 model/decoder controls and 29 recorded-data controls run in native CI.
The recorded checker replays the full fixture history from pinned independent
witnesses; it does not recompute the complete initial 103,821-key input. The
separate full deriver performs that work and compares all source balances.
No current MIT verifier acceptance, v1/v2 consumer trust, anchor, schedule or
context pin changes. M1 consumer selection, M2 profile/activation agreement, M3
accepted-header typed binding, representative M4 budgets/snapshots and M5
independent review/authenticated distribution remain open. Consumers remain
`REFUSED` for production state values.
