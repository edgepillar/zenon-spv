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

The first native measurements at SPV source
`32c44aa15c54005f19d401b7cfe7a2a34f4a57a5`
([run 43708353171, attempt 1](https://github.com/edgepillar/zenon-spv/actions/runs/43708353171))
recorded:

| Platform | Listener seconds, fixed experiment window | Closed consensus logical bytes |
| --- | ---: | ---: |
| Linux amd64 | 38.778142229 | 5,047,967 |
| macOS amd64 | 52.245839178 | 5,047,787 |
| Windows amd64 | 40.2713689 | 5,044,041 |

All three native commands exited zero with complete output and all three cases
passed. Linux/macOS jobs completed successfully. Windows subsequently refused
the documentation source pin because its checkout used CRLF; that CI failure
remains recorded and is not a successful complete qualification. The document
now has an explicit LF checkout rule, which is included in the source pins.

For the fixed window, all three native observations reported 182,718 period
points, 634 epoch points, 365,945 database Gets, 183,353 Puts and 19,619,414 bytes
of Put values. These are one-run bookkeeping observations. They do not establish
the duration under four concurrent containers or identify the readiness failure
cause. Do not change the genesis, slot timing, activation or readiness limits to
convert these observations into a successful pilot.

## Unsigned measurement

`first-insertion-catchup.yml` fetches the exact original node into a fresh hosted
workspace and verifies all original regular sources against their Git blob IDs.
It adds an external-package test and a small test-only export adapter for the
original `consensus` package. Original node sources,
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

## Linux CPU comparison

The main revision `5a0d29eb3df7c4ce2f66cae7174e33dea9d8781d` completed the
unconstrained controls on all three platforms. The fixed window took 40.1 seconds
on Linux, 69.3 seconds on macOS and 33.3 seconds on Windows in that run.
[Main measurement run 43711591065](https://github.com/edgepillar/zenon-spv/actions/runs/43711591065)

The Ubuntu job now compiles the original bookkeeping test once. It runs all
three cases with one Go worker and no unit CPU quota. It then runs only the fixed
window using the same binary and a 50 ms quota per 100 ms period. Both transient
units run as the hosted runner user in a private network namespace and have a
768 MiB memory limit, no swap allocation and separate disposable databases. This
uses the per-node limits from the historical reference-gas contract and avoids
building or downloading a node container. The test reads its own kernel limits
immediately before and after the listener and retains CPU time and throttling
counter deltas. The comparison requires identical period, epoch, Get, Put and
written-value counts, and binds both runs to one test binary digest.

The 90 second comparison is against the recorded readiness deadline. It covers
one listener with an isolated disk workload. The signed fixture also includes
other nodes, networking, production callbacks and a different build environment.
A sample above 90 seconds shows that the listener can occupy that much time by
itself under the measured constraints. A shorter sample still leaves those other
costs to investigate. The comparison uses the original deadline regardless of
its result.

## Resource and evidence limits

Admission requires a 10 GiB free-space floor plus a 3 GiB expected allocation and
1 GiB safety margin. This is admission budgeting, not an OS aggregate quota.
The hosted job is limited to 15 minutes and each native test run to 180 seconds
of execution. Each Linux transient unit also has a 190 second system limit.
Compilation is capped at 480 seconds on Linux, and the portable command is
capped at 600 seconds including compilation. Both command streams are capped
at 2 MiB. The final closed consensus directory must not exceed
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
