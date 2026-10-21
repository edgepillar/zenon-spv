# Core-manager Stop before Start

The selected experimental Zenon core manager panicked with `close of nil
channel` when stopped after construction or successful `Init`, before `Start`.
`Zenon.Stop` reached `pillar.worker.Stop`, which closed a channel initialized
only by `worker.Start`. That panic prevented downstream subscription, event,
consensus, chain and consensus-database shutdown. In the initialized case, the
state tree remained ready immediately after the recovered public API panic.

The experimental successor creates the worker's shutdown channel in its
constructor. This preserves the stopped predicate after an early `Stop`;
skipping a nil channel would not do that. `Start` still creates a fresh channel
for its generation. This change does not make repeated `Stop` or concurrent
lifecycle calls safe.

## Exact source and finite native comparison

The [complete-file patch](../tools/gen-state-root-vectors/testdata/candidate-zenon-worker-stop-patch.json)
extends digitalSloth/go-zenon at
[9c71ae82fc983e16f914ae085d4034030c8ebe3b](https://github.com/digitalSloth/go-zenon/commit/9c71ae82fc983e16f914ae085d4034030c8ebe3b)
and experimental runtime tree `c5e413c43794b3ba32763484670db2b100295a15`.
Its successor runtime tree is `2887e4d8ee4c8c148f94c119719853c7f4a4df74`.
Only the constructor field in `pillar/worker.go` changes. The two prepared
475-file trees include identical tagged observation, caller-teardown and unit
sources. Every prior experimental change and the source module files remain
unchanged.

Two ordinary Go 1.25.14 builds and six qualified ordinary processes ran on
Darwin ARM64 with CGO enabled. Each variant selected these cases in order:

| Case | Baseline public Stop | Successor public Stop |
| --- | --- | --- |
| Construct fresh core managers, then Stop | Recovered nil-channel panic | Returns normally |
| Init fresh core managers, then Stop | Recovered nil-channel panic; tree still ready | Returns normally; tree not ready |
| Reopen initialized stores, Start, then Stop | Returns normally | Returns normally |

The probe calls `zenon.NewZenon`, never the wallet-starting `node.NewNode` or
`znnd`. No producing key, wallet manager, peer server, RPC listener or external
peer is configured. The two keyless reopen controls **do start internal
consensus, protocol and subscription services**. They do not qualify consensus
validity, a full node, networking or production behavior.

The baseline records its public Stop result and post-call queries before an
explicit tagged caller teardown closes the remaining managers. Successful
caller teardown is separate from successful public Stop. All six outer
processes returned zero because the selected baseline API panic was observed
and recovered deliberately; that exit code is not evidence that baseline
`Stop` returned successfully. The successor needs no caller teardown.

A controller interruption left one additional attempt without a recorded
actual exit or complete output. That attempt remains `UNKNOWN`, with its
original metadata and scratch preserved. Three candidate cases completed in
a fresh owned namespace using the already retained candidate binary. Neither
completed build nor the three completed baseline cases was repeated.

## Independent bytes and selected regressions

The [record](../tools/gen-state-root-vectors/testdata/native-zenon-worker-stop.json)
retains all six exact JSONL outputs, their capture pins, both binary pins and
linked module inputs. Before either variant ran, the input selected only the
source-genesis identifier, raw key and genesis patch size/digest. It supplied
no expected root, value or proof. The separate Python model rebuilds the
previously selected unsigned genesis witness and checks all twelve before/after
root/value/proof observations, including five complete successful matches and
twelve foreign-identifier refusals. It does not recompute the full genesis
projection or authenticate a network genesis.

One separate native unit invocation passed 50 root tests and 59 results with
zero skips across chain, cache, cache/storage and pillar packages. It preserves
all 41 previous roots and adds nine worker controls: pre-init shutdown,
post-init shutdown, normal start/stop, fresh channel generations, restart,
start after early Stop and waiting for registered children. No worker `Process`
or signing/broadcast path is selected. Thirty downloaded unit-cache archives
were verified; this is not coverage of every module selected by the graph.

The portable CI reader checks retained output and exact source/test inventories;
it does not execute these reference managers again or authenticate the private,
unsigned capture. State-value acceptance remains **REFUSED**. Profile agreement,
accepted-header binding, activation, full-node recovery, independent review and
authenticated distribution remain separate [roadmap gates](native-roadmap.md).

## Reproduction and resource bounds

The portable checks need no node or new dependency transport:

    python -I -B tools/gen-state-root-vectors/prepare_zenon_worker_stop_test.py -v
    python -I -B tools/gen-state-root-vectors/check_zenon_worker_stop_test.py -v
    python -I -B tools/gen-state-root-vectors/check_zenon_worker_stop.py \
      --source-revision "$SOURCE_REVISION"

For a fresh finite native comparison, use approved task-managed scratch and
the unchanged pinned node source. The source-only preparer refuses existing or
linked destinations, checks every source file and emits the exact selected
build, unit and ordered three-process recipes:

    python -I -B tools/gen-state-root-vectors/prepare_zenon_worker_stop.py prepare \
      --node-source "$PINNED_NODE_SOURCE" --workspace "$NEW_OWNED_WORKSPACE" \
      --go "$PINNED_GO" --variant candidate

Keep the 10 GiB free-space floor plus the expected 3 GiB allocation and other
reservations; the suggested task quota is 4 GiB. Reuse verified dependency
objects through a bounded local-only module catalog and reuse retained binaries
after a controller interruption. This comparison made no new external
dependency transports. Keep command exit/completeness evidence and protect
unknown attempts; close handles and processes before clearing only declared,
owned generated scratch. These allocations are admission estimates, not
measured peak memory, disk occupancy or physical APFS reclaim.
