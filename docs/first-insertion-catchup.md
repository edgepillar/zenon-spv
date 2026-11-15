# First insertion point catch-up

The owned chain-69 experiment at source `bf6ab4e43dba4fd5c2a2ca3328eba51e11f5159c`
([run 43704355778, attempt 1](https://github.com/edgepillar/zenon-spv/actions/runs/43704355778))
stopped at node readiness. All 30 recorded candidate-frontier responses were
source genesis H1. The typed consumer did not complete. One bounded pillar log
summary reported `broadcasting own momentum`; it does not establish delivery,
the header identity or ordering between the two source locations with that text.

The selected original node is
`digitalSloth/go-zenon@2835c436b197fece5c76adf4ba8dc1decca2e3ea`, tree
`f89d645c7f5be85dfe10dc7a510d80df7965d22f`. In `consensus/points.go:71`, its
synchronous insertion listener fills every completed period, followed by completed
epochs, before returning. The unchanged public genesis timestamp is `1739923200`.
At `2026-11-15T10:30:00Z`, 182,718 periods of 300 seconds have elapsed. This is a
source-supported cost hypothesis; the recorded experiment does not establish it
as the cause of the readiness deadline or unresolved ledger closes.

## Unsigned measurement

`first-insertion-catchup.yml` fetches the exact original node into a fresh hosted
workspace and verifies all original regular sources against their Git blob IDs.
It adds one test file to the original `consensus` package. Original node sources,
genesis, activation rules, slot timing and readiness limits are unchanged.

The test initializes real ledger/cache/state LevelDB managers. It inserts an
**unauthenticated, unsigned H2 test fixture directly below the verifier** into
that isolated database. It then constructs the real consensus object with a
fresh LevelDB and invokes its original point listener synchronously. No producer,
consensus event loop, RPC, peer, wallet, signing operation or live transaction is
started. This deliberate authentication bypass belongs only to the test fixture;
it creates no accepted header or runtime authority.

Three independent fresh cases use gaps of one period, one day and the fixed
experiment window. Each retains actual listener duration, database Get/Put calls,
written value bytes, completed period/epoch counts, and the closed consensus
directory's regular-file count and logical byte total. Original sources and the
added input are checked again after execution. All managers must close before
the test's disposable directory is removed.

These observations are neither peak disk/RSS measurements nor APFS physical-space
estimates. No wall-time ratio is a pass criterion. A timeout, incomplete stream,
skipped case, partial point history or failed close fails qualification; preserve
its original streams and last phase. A passing cost control does not diagnose a
live process, reproduce every production callback, authenticate execution or
qualify a devnet consumer.

## Resource and evidence limits

Admission requires a 10 GiB free-space floor plus a 3 GiB expected allocation and
1 GiB safety margin. This is admission budgeting, not an OS aggregate quota.
The hosted job is limited to 15 minutes, the native test to 180 seconds of test
execution, and its command to 600 seconds including compilation. Both command
streams are capped at 2 MiB. The final closed consensus directory must not exceed
256 MiB per case. No binary or temporary ledger is uploaded: the small artifact
retains source inputs, original source pins, toolchain context, actual command
streams/receipts and the three measurements. Source-pinned inputs reproduce the
disposable fixture; failed command output remains evidence.

Driver controls run with:

```sh
python -I -B tools/gen-state-root-vectors/qualify_first_insertion_test.py -v
```

The hosted driver uses `prepare` and `qualify` modes with explicit fresh workspace,
evidence directory and native platform arguments. Its manifest binds source and
tree, feature/checkout revisions, run/attempt, platform, actual complete command
output and each selected test. The existing closed-parent oracle retains its
separate read-only H1 scope. No signed experiment or automatic retry is authorized
by this lane; no production state-proof, canonicality or finality gate changes.
