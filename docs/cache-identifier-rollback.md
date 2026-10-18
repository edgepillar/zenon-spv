# Native cache rollback identity experiment

The selected node's public `Chain.Init()` can succeed with different ledger and
cache hashes at the same height. When its cache is ahead, `chainCache.rollbackTo`
stops after reaching the target height and never compares the retained hash.
The same cache is refused on the following clean reopen. This is a reproduced
local recovery defect, not evidence of a remote SPV acceptance bypass.

This M2 experiment selects `digitalSloth/go-zenon` at
`9c71ae82fc983e16f914ae085d4034030c8ebe3b`, its complete 467-blob source manifest
and its own module files. The experimental parent runtime is
`8420610538a6a51fd43ed4c6f0e2feb2db8f120f`; the cache fix produces
`49db80f94e48e980f84de35299f80c6f3b4dcb54`. The complete-file descriptor changes
only `chain/cache.go` and `chain/cache/storage/db.go` relative to that parent.
Neither the original upstream repository nor the SPV runtime is changed.

## Experimental behavior

The native cache manager validates the entire retained hash/height path, up to
its existing 100-step window, before its first rollback write. It uses one
snapshot under the manager's writer lock and scans one reverse patch at a time.
It does not duplicate the complete cache or assemble one large rollback batch.
Missing history, malformed frontier transitions and a different target hash
refuse before any write. The cache schema and SMT profile are unchanged.

The original `CacheManager` interface stays source compatible. An optional
`IdentifierRollbackManager` capability supplies validated rollback. Alternate
managers without that capability refuse a rollback; there is no height-only
fallback. An exact existing identifier remains a no-op. The caller also checks
the full identifier after a successful backend result.

Applying the validated path still requires separate native write batches.
An I/O error can leave earlier acknowledged steps committed, and a failed write
can have an uncertain outcome. Errors are propagated with the acknowledged step
count. This is not atomicity of the entire rollback window, crash recovery or
power-loss qualification. No automatic retry or database deletion is added.

## Recorded execution

Two ordinary Go 1.25.14 Darwin ARM64 entrypoint builds produced eight complete
process observations. The first parent binary was retained and reused for two
additional controls. There were no new node or dependency downloads. All eight
process exits were zero; their semantic outcomes differ:

| Native cache fixture | Parent | Experimental candidate |
| --- | --- | --- |
| Canonical cache and clean reopen | Ready, matching identities | Ready, matching identities |
| Foreign hash at the ledger height | Refused, cache unchanged | Refused, cache unchanged |
| Ahead cache with the wrong retained hash | Init succeeds with mixed identities; next reopen refuses | Refused before writing, cache unchanged |
| Correct target retained below an ahead frontier | Rolls back and reopens | Rolls back and reopens |

All cases use the selected source's embedded unsigned genesis and real on-disk
ledger, cache and NodeTree managers through public `Init`, query and `Stop` calls.
The two foreign cache faults explicitly contain frontier/rollback metadata only;
they are not complete alternate-chain cache applications or valid signed
momentums. `Chain.Start()` is never called. Available state-tree queries match
the preselected canonical root, value and complete proof.

Race-enabled native tests separately executed 12 test roots and 22 passing test
results across cache storage and the chain-cache caller, with no skips. They
cover wrong hashes, successful content recovery and reopen, an empty predecessor,
the 100-step boundary, missing earlier patches, malformed history and current
frontiers, first/second write rejection, stopped handles, unsupported alternate
managers and a backend that returns nil without reaching the target. The write
controls deliberately distinguish unchanged data from partial acknowledged
progress. They are controlled component tests, not live reorg or concurrency
qualification of the full service.

## Rechecking and resource scope

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_cache_identifier_rollback_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_identifier_rollback_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_identifier_rollback.py
```

The 27 portable controls and reader reconstruct both complete build trees. They
reconstruct the two small cache metadata images independently from protobuf,
goleveldb batch bytes, namespace prefixes and ordered SHA-256 framing. One
independent 256-level fold checks the preselected canonical proof. The reader
checks all 66 recorded events and 13 public queries. It runs no node, compiler,
network request or new genesis projection. Node-internal test sources use
`.go.txt` containers and are copied unchanged to explicit `_test.go` targets in
the prepared node; they are not packages in the enclosing SPV module.

The source-reproducible execution workspaces were closed and removed after process,
file-identity and complete manifest checks. Their post-run logical file totals were
316,731,980 and 574,252,912 bytes, respectively, with protected inputs, command
outputs and manifests retained. Separately registered original-source and proxy
aliases are outside those execution-directory totals. These are neither peak disk measurements nor
measured physical APFS reclaim. One protected CAS payload per digest, an
independent execution clone and bounded private caches avoid repeated archives
and a second parent build.

The first portable preparer-control run was interrupted by the supervising
storage tool's refusal of an intentional symlink fixture (exit -9, incomplete
output); that failure is preserved. Its explicitly approved isolated fixture
cleanup removed only the symlink and two empty directories. The revised test
checks the link predicate through a filesystem mock. Existing parent controls
still test real symlinks in hosted CI. This does not change any compiled node
source or reclassify the interrupted run as a pass.

Whole-module-graph verification remains **NOT_QUALIFIED** after the earlier
missing unused proxy input; it was not retried or converted into a pass. The 25
linked modules were checked against 75 retained inputs and the node's own
`go.sum`. A portable reader check is recorded-byte evidence on its host, not
native execution of this node there. Raw private stderr/receipt hashes and large
canonical-cache digests remain recorded observations, not independent receipt
authentication or full database reconstruction.

The node/client profile agreement, realistic retained reorg and interruption
workloads, accepted-v3-header binding, independent review and authenticated
distribution remain open. Network activation, canonicality, consensus finality
and state-value acceptance are not established. The SPV state-value consumer
continues to return **REFUSED**. Storage tooling is outside this change.
