# Public Chain proof request workload

This finite M4 observation uses real disk ledger, cache and state-tree managers
through public `Chain.Init`, `StateRoot`, `GetProof` and `Stop`. It selects
[`go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/commit/9c71ae82fc983e16f914ae085d4034030c8ebe3b)
with the unchanged experimental runtime tree
`053c87e5bc4addd1bb70a467cb34facd439e66bc`. The ordinary entry point adds one
file, producing the 472-blob build tree
`db77238ebf21ceb968be6a48e5c1f1212b6b7118`. No runtime patch is added here.

One ordinary Go 1.25.14 Darwin arm64 binary serves four preselected processes:
fresh stores with 1, 4 and 16 closed-loop request workers, then a fresh OS process
reopening the last stores with 4 workers. `Chain.Start`, `Node`, wallets,
signing, user transaction submission and chain networking are not selected.
No controlled ledger/cache adapters replace the real managers.

The ordinary binary has SHA-256
`21ac545701c654c409248f29c4cfbb629009db35c79bcf420acc448fede98442`.
Its complete build inventory matches the 25 selected modules against the node's
own source sums. The complete module archive graph remains `NOT_QUALIFIED`.

## Independent byte expectations

The preserved source-genesis batch has 10,849,399 bytes and SHA-256
`a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75`.
An independent decoder checks all 14,091 source balance rows and reconstructs
the complete 19,257-leaf balance/storage projection. Its root is
`864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d`.
This unsigned source-derived genesis is not an authenticated network checkpoint.
Its v1 momentum has a zero header StateRoot.

Before the backend runs, the Python model selects 128 distinct keys:

- 80 balances distributed across the source map, including all three rows of
  the smaller token family and 77 rows of the larger family.
- 32 storage keys, including sixteen largest source values and a dispersed set.
- Eight absent balance keys and eight existing ledger keys excluded from the
  partial projection. The latter do not establish absence from the full ledger.

The initial source-selection preflight refused an incorrect forty-per-token
assumption. It launched no backend and remains recorded. The corrected budget
keeps all 128 selections. Full root and canonical witness derivation took one
17.1-second Python call; it is not repeated for every process or portable check.

The [selection](../tools/gen-state-root-vectors/testdata/public-chain-proof-workload-selection.json)
has SHA-256 `e7d0c92ad88490b1167806b4b70cef88792bf974cec0725257c1b0f24979c006`.
The [independent expectations](../tools/gen-state-root-vectors/testdata/public-chain-proof-workload-expectations.json)
have SHA-256 `527c6ec3257f8e883204306055d7b1789ee6902537d38303e06d6394c7f94946`.
Expected values and proof bytes are not input to the ordinary child. It receives
only the fixed source identity, keys, worker choices and request count.

Each process completes 4,096 timed `StateRoot`/`GetProof` pairs. All first-cycle
128 value/presence/proof observations and the ordered digest of every request
match the sealed independent expectations. The complete four-process sequence
has 16,384 timed pairs, 32,768 timed API calls and eight separate post-Stop
refusal calls. These counts exclude internal manager work during initialization.

## Recorded resource observations

These are single observations per worker choice, plus one fresh-process reopen,
on one Darwin arm64 host with `GOMAXPROCS=2`, `GOGC=100`, ordinary CGO builds,
no race instrumentation and no forced GC or cache flushing. Cache state,
authenticated hardware identity and a production consumer budget are unqualified.

| Workers / stores | Timed batch seconds | API-pair p95 milliseconds | SELF lifetime peak RSS through final capture, MiB |
| --- | ---: | ---: | ---: |
| 1 / fresh | 0.226 | 0.112 | 583.05 |
| 4 / fresh | 0.252 | 0.740 | 594.27 |
| 16 / fresh | 0.246 | 2.461 | 572.00 |
| 4 / fresh-process reopen | 0.214 | 1.763 | 545.09 |

These observations do not demonstrate a concurrency speedup. The selected
runtime serializes root/proof reads with one NodeTree mutex; changing that
locking policy needs separate correctness and workload qualification.

The timed batch includes request bookkeeping and digest calculation. Each
API-pair latency covers only that worker's two API calls, including time waiting
for their locks, and excludes time before the worker begins the request. This is
a fixed closed-loop request model, not an open-arrival service capacity test.

Heap values are snapshots, not peaks. SELF usage snapshots enclose setup and
postprocessing in addition to the timed batch. Native CPU microsecond counters
are converted to nanoseconds without claiming nanosecond precision. RSS covers
the ordinary process through capture, including source-genesis construction and
manager initialization; it is neither isolated tree memory nor a measured peak
through OS-process exit. Compiler, supervisor and whole-pipeline memory remain
separate and unmeasured here.

The three closed stores contain 18,394,329–18,397,949 bytes when their file lengths
are summed. These are closed-file observations, not peak disk allocation,
allocated APFS blocks or measured physical reclaim. Query checks preserve full
frontier identifiers; fresh-process reopen preserves the selected results.

## Failures and owned storage

One portable source-control invocation found a missing helper call in the new
recipe before native compilation; its failure is preserved. All 31 final
portable byte/source/record controls and the standalone recorded reader pass
locally. Hosted CI needs its own exact-source qualification.

The first native process completed successfully, but the initial collector
incorrectly required empty stderr. The pinned Chain emits exactly
`Initialized NoM. Height: 1, Hash: ...` for the selected full genesis identifier.
The original streams, successful component exit, collector failure and closed
database image remain protected. The successor collector admits only that exact
source-bound diagnostic. It reuses the completed first process and retained
ordinary binary, then runs only the three previously unexecuted cases.
There is one build, four processes and no repeated component case.

The first owned task reserves 2 GiB with a 3 GiB quota. The resumed task reserves
512 MiB with a 1 GiB quota. Both preserve the 10 GiB production free-space floor
plus allocations and other reservations. Each probe has a 300-second deadline
and a 1 MiB stdout cap. The independent binary alias is an APFS clone, not a
hard link. Existing verified inputs are reused; no new external archive or
dependency transport occurs, and only the 25 selected module ZIPs are served
from retained inputs during compilation.

Actual exits, complete streams, source/binary pins, closed workspace images and
durable process checks precede owned temporary removal. Both native tasks are
closed and their scratch is absent. Historical caches, unrelated worktrees,
unpublished storage-tool changes and earlier held evidence are untouched.

## Reproduction and remaining gates

Use a verified complete original source, the pinned source-genesis batch, a new
owned workspace and explicit resource supervision. The preparer refuses existing
or overlapping destinations and returns commands without executing them.

```sh
python3 -I -B tools/gen-state-root-vectors/public_chain_proof_workload_model.py \
  --input "$PINNED_SOURCE_GENESIS_BATCH" --node-source "$VERIFIED_ORIGINAL_NODE_SOURCE"
python3 -I -B tools/gen-state-root-vectors/prepare_public_chain_proof_workload.py prepare \
  --node-source "$VERIFIED_ORIGINAL_NODE_SOURCE" --workspace "$NEW_OWNED_WORKSPACE" \
  --go "$PINNED_GO"
python3 -I -B -m unittest discover -s tools/gen-state-root-vectors \
  -p '*public_chain_proof_workload_test.py' -v
python3 -I -B tools/gen-state-root-vectors/check_public_chain_proof_workload.py
```

The [recorded corpus](../tools/gen-state-root-vectors/testdata/native-public-chain-proof-workload.json)
retains actual stream bytes and explicit scope. Portable readers independently
reconstruct its expected canonical witnesses and check its records. They build
and execute no reference node and produce no new resource measurement.

This adds a real-manager proof-read workload to M4. Representative continuous VM
history, snapshot/import trust, churn, retention/reorg concurrency, interruption,
activation sequencing, hardware acceptance budgets and full-node qualification
remain open. M2 profile agreement, M3 accepted-header binding and M5 independent
review/distribution remain separate. State-value acceptance and the consumer
result stay **REFUSED**; no canonicality, finality or network activation follows.
