# Successor source-default retention qualification

This separate M4 component experiment selects
[`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/tree/9c71ae82fc983e16f914ae085d4034030c8ebe3b).
Its complete 467-blob source tree is
`d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6`. The experimental retained-identity
and terminal-instance proposals produce runtime tree
`2ab95e67aa184e7faa3f080c6b08d8980a8e16f9`, excluding test probes.
The earlier [33d7 resource observations](state-tree-default-retention.md) remain
unchanged and are not evidence that this source executed.

## Fresh input and independent selection

The unsigned source-genesis generator was freshly compiled against this node's
own `go.mod` and `go.sum`. Two complete fresh generator processes emitted the
same 10,849,399 bytes with SHA-256
`a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75`.
This equals the earlier finite byte contract; the new process records have
separate source, compiler and binary bindings. Equal bytes share one protected
object. Existing source records and manifests were not relabelled.

The independent decoder checked every batch event and all 14,091 source balance
rows. The 103,821 logical keys produce 19,257 nonempty committed leaves: balances
and contract storage only. A complete sparse-tree recomputation gives root
`864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d`.
This is source-derived genesis, not an authenticated network checkpoint.
Generating it executes the source's in-memory genesis derivation; it starts no
NodeTree backend, chain service, wallet operation, signing or network broadcast.

The source-genesis import path needs six additional modules beyond the earlier
recovery-only build. Their 18 ZIP/module/info payloads total 947,066 bytes.
Module ZIP and `go.mod` h1 sums match the selected source's own `go.sum`; complete
payload SHA-256, transport exits and caps are retained separately. Compilation
uses an offline proxy and readonly module selection. An initial offline compile
refusal for missing modules is preserved, and executed no generator or backend.

The workload contains 32,768 unsigned controlled heights and 256 distinct balance
addresses selected across the complete source balance map. Genesis is height 1;
subsequent heights apply the same independently specified delete, stored-zero
and nonzero mutations as the earlier experiment. All expected roots and selected
canonical proof bytes are sealed before backend execution. This reuses finite
algorithms and an equal input contract, not prior node execution evidence.

## Actual component boundary

One ordinary Go 1.25.14 CGO binary is reused for three fresh processes per policy,
in the preselected order: pruned samples, then archive samples. Scheduler
checkpoints and race instrumentation are excluded from these resource samples.
The exact full source, source module files, runtime patches, helper files,
compiler overlays and build/test selection are verified before and after work.

Controlled manager/cache/genesis adapters feed the actual chain `Init`, `Start`,
background worker, `Stop`, closed inspection and clean reopen. The node source
defaults are rollback cache 100 plus retention margin 17,280, bulk cap 10,000,
tail cap 10 and a one-second batch budget. Both retention and bulk overrides
remain zero. The selected identifiers and suffix patches are synthetic; this
does not execute a full node or continuous VM transaction history.

The independently sealed expectation SHA-256 is
`684e318dfaa6444cc9179397e6a5bca7d02d079cec17bb73957b065bb46cdaa0`;
the selection SHA-256 is
`28b2d094ce936217e279397fbb3b500753a107ad355f2bbffed945ce63d35ef8`.
The ordinary component binary is
`531a047229051c0b66e14cabeb936954e605bc99e53a51264e991199299d4fee`.

At frontier 32,768, the inclusive pruned horizon is 15,388 through 32,768:
17,381 root/hash pairs. Archive mode retains all 32,768 pairs. Each case checks
three logical-record snapshots and two sets of fifteen proof keys at six
selected heights. It does not individually query every mutation key or
independently reconstruct every node/refcount record byte.

All six preselected processes completed without a component retry. Across two
query sets per process, 900 canonical proof observations matched and 180 pruned
queries refused with no-version. Wrong-hash and origin queries retain their
separate source contracts; generic absence is limited to the committed projection.

| Three ordinary observations per policy | Pruned | Archive |
| --- | ---: | ---: |
| Retained root/hash pairs | 17,381 | 32,768 |
| Logical records | 609,448 | 1,076,346 |
| Logical key/value bytes | 58,324,301 | 103,493,643 |
| Sum of file lengths after final close | 48,123,400–48,126,253 | 84,583,616–84,583,992 |
| Whole-process elapsed seconds | 35.520–36.113 | 76.993–80.025 |
| Whole-process peak RSS bytes | 302,972,928–306,429,952 | 349,519,872–373,571,584 |

These are three observations on one macOS arm64 host, with `GOMAXPROCS=2` and
`GOGC=100`. File lengths are not allocated APFS bytes, peak disk use or guaranteed
reclaim. The final disposable compiler workspace contained 271,017,702 logical
bytes before checked removal; this is not a peak or physical-disk measurement.
No controlled cross-version performance improvement is claimed.

## Resource supervision and evidence retention

The private caller declares a 2 GiB expected allocation and a 3 GiB task quota
before starting. The shared scratch limit is 4 GiB; admission also preserves a
10 GiB free-space floor plus expected allocation and other reservations.
Each child has a 600-second deadline, a sampled 2 GiB RSS stop threshold,
64 MiB stdout and 1 MiB stderr caps. The supervising managed command has a
separate 720-second deadline. Sampled monitoring is not an OS-enforced quota.

Whole-process resource observations include fixture setup, background work and
queries. They are neither isolated tree memory nor complete-node memory.
Preselecting six samples avoids filtering or retrying component results.

After a process ends, the caller preserves complete logical payload and outcome
records, verifies their protected SHA-256 objects, then acknowledges durable
retention. Only then may the supervised worker remove its own unchanged fresh
database. Actual workspace absence is checked before the next sample.
Failures preserve diagnostics and a bounded database image before any such
cleanup; unknown files or uncertain process ownership remain HOLD.
Historical data, worktrees and unpublished storage-tool changes are outside
this cleanup authority. There is no recursive evidence ZIP or hard-linked copy.

The recorded corpus stores each distinct complete logical table once. Its
explicit reversible codec reconstructs the original complete byte count and
SHA-256 before an independent witness replay checks all roots and selected
canonical proofs. Portable CI checks that record; it performs no new reference
node build, LevelDB execution or native resource measurement.

The six complete logical outputs total 25,544,931 bytes but have only two distinct
payloads, totaling 8,514,977 bytes. Both match already verified objects by complete
SHA-256, so the fresh process records reference those bytes without duplicating
them or adopting historical filesystem data. The
[recorded corpus](../tools/gen-state-root-vectors/testdata/successor-default-retention.json)
contains the explicit reconstruction codec and separate new source/process pins.
The [fresh genesis manifest](../tools/gen-state-root-vectors/testdata/successor-genesis-input-execution.json)
keeps the two new generator observations distinct from previous executions.

Twenty-four portable source/observation/recorded-data controls preserve this
scope. Eight additional adverse controls on the actual prepared 467-file workspace
refused source, module, race/checkpoint, build-selection, trust and correlated
parent/layer drift before the ordinary component ran. Invalid recorded receipts
are rejected before large-table expansion and witness replay. These controls
preserve failures and report evidence limits; they do not authenticate a release.

## Remaining gates

These are local component observations on one host, not a production budget or
an upstream-adopted protocol. Snapshot/import and crash recovery, representative
continuous VM history, activation sequencing, production concurrency, consumer
hardware budgets and independent review remain separate acceptance work.
Race-built functional schedules retain their own scope and are not ordinary
resource samples.

M1 consumer/anchor inputs, M2 profile agreement, an authenticated accepted-header
root binding and M5 distribution are still required. Disk format marker 3 is
separate from Momentum version 3. Runtime v1/v2 boundaries and state-value
`REFUSED` results remain unchanged. These observations establish neither
canonicality, consensus finality, network activation nor production balances.
