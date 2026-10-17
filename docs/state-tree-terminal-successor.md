# Selected successor terminal-instance experiment

This separately selects node `9c71ae82fc983e16f914ae085d4034030c8ebe3b`
after the [retained-identity successor](state-tree-recovery-successor.md).
The earlier [terminal Stop experiment](state-tree-terminal-stop.md) selected
`33d7`; its observations and producer pins remain unchanged. The new complete
467-file selection, identity parent and one-file terminal proposal have distinct
source and execution records.

## Proposal and source boundary

The selected identity parent still permits `Init` after a completed `Stop`.
`stopOnce` has already been consumed, so that reopening can leave the backend
open after another `Stop`. Readiness remains observable while Stop waits for
the changes lock. Two controlled launches can also publish workers after Stop
has returned. These statements describe the finite component observations below,
not a demonstrated live RPC exploit or a complete node lifecycle guarantee.

The proposal rejects initialization and new work after terminal intent, checks
that intent in readiness, and separately serializes worker launch admission.
Stop closes the quit channel before waiting for launch admission; it joins
workers without holding the changes lock. An already admitted compute may finish
before backend close. This is not cancellation of previously admitted work.

The [descriptor](../tools/gen-state-root-vectors/node-terminal-stop-9c71-patch.json)
binds complete before/after bytes and their inverse. The original node tree is
`d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6`, the experimental identity parent is
`249f3e33e54263efc7c3cad16c02a4784df74040`, and the uninstrumented terminal tree
is `2ab95e67aa184e7faa3f080c6b08d8980a8e16f9`. This changes one file over the
two-file identity parent. It adds no migration, disk-format change, SMT encoding
change or activation policy. The parent's incompatible-format refusal remains.

`prepare_terminal_stop_successor.py` first verifies and stages that exact parent.
It checks the complete source inventory, the selected node's own module files,
the parent and layered plans, and eight explicit compiler overlays excluding the
original chain tests. Two test sources compile; the parent recovery probe is not
selected by this experiment's run expression. The preparer executes no compiler,
node or network operation and adopts no existing database.

## Executed finite schedules

The two variants are the experimental `hash-bound` identity parent and its
`monotonic-stop` successor. They are not two unmodified node releases. Each was
compiled once with Go 1.25.14, CGO and the race detector on macOS arm64, then ran
in two fresh complete processes. Both generations matched independent
expectations sealed before reference execution. See the
[observations](../tools/gen-state-root-vectors/testdata/successor-lifecycle-stop.json)
and [execution manifest](../tools/gen-state-root-vectors/testdata/successor-terminal-stop-execution.json).

The six schedules select Stop before Init, Init before Stop, Stop waiting for the
changes lock, Init waiting at its selected frontier, an already admitted compute,
and two held launch attempts. Three separately pinned test-only checkpoints
control launch entry, the previous-worker snapshot and worker admission. The
workers are held before the build loop, so no background batch is qualified.

One paired generation contains 14 initializations, 14 Stop calls, six launch
calls, 34 phase observations, 82 selected reads and 46 logical-record snapshots.
The independent Python oracle derives SMT/proof bytes and complete selected
compressed records separately from Go and LevelDB. Record bytes, readiness,
errors, callbacks, controlled launch observations and clean reopen must all match.
Six additional complete-workspace plan-drift refusals per variant include a
correlated parent/layered recursive build substitution. These local preparer
checks are separate from the recorded-data controls in hosted CI.

Verified source and dependency objects were reused without new transport. One
CAS object retains each binary; independent APFS clones served executable aliases.
The bounded compiler workspace, private module/build caches and temporary backend
files were removed after process completion. The recorded logical end size is
not peak or physical disk use, compiler RSS, a workload benchmark or a production
resource budget.

## Portable replay and limits

Run from the selected source with a trusted Python interpreter:

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_terminal_stop_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_terminal_stop_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_terminal_stop_successor.py
```

The nine preparation and 30 recorded-data controls execute no reference node,
compiler, LevelDB, scheduler or resource observer. CI is configured to replay
them on Linux, macOS Intel and Windows. Exact-source native CI and independent
artifact validation remain required before delivery. A caller-asserted source
label alone is not a source or binary attestation.

Reproducing the backend experiment additionally requires the complete pinned
node source, verified selected module inputs, a trusted Go/CGO toolchain and fresh
owned bounded workspaces. The caller supervises actual returned commands, retains
their real outcomes and checks cleanup. The preparer assumes a cooperative caller;
it is not a sandbox for an adversarial caller or compiler.

This does not execute `Chain.Start`, upstream tests, a complete node, network
chain, RPC, wallet, signing or transactions. The update/truncate terminal guards
are source/compile checked rather than directly exercised by these schedules.
Representative concurrency, background work, crash recovery, sustained retention
and target-hardware budgets remain separate. Profile agreement, authenticated
activation/provenance, an actually accepted v3-header balance flow, independent
review and authenticated distribution remain open. Production state-value
consumers remain `REFUSED`.
