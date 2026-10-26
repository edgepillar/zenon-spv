# Experimental core Init/Stop admission

The experimental successor refuses Init after an incomplete core Stop and
serializes Init with Stop using the existing mutex. Its one runtime change is
in zenon/zenon.go. Start remains unchanged and unqualified for concurrent use.

The preceding repeated-Stop experiment already refused another Stop after a
panic. It did not apply that guard to Init. In the selected real-manager
control, a deliberately preclosed real protocol channel makes core Stop panic
before reaching the remaining managers. The preceding Init then succeeds and
makes its state tree ready. The successor returns ErrStopIncomplete before
calling Chain.Init and keeps the tree unavailable.

This is an explicit fail-closed experimental contract, not an upstream
activation decision or a demonstrated live-network failure. The protocol close
is deliberate and local. Arbitrary manager failures, Start/Stop concurrency,
full-node restart and power loss remain unqualified. The separate
[failed-Init cleanup experiment](core-init-failure-cleanup.md) covers two selected
real-manager failure conditions on this runtime; it adds no runtime patch.

## Selected real-manager observations

All processes are keyless and use the selected source's embedded unsigned
genesis. No Node wrapper, peer server, RPC listener, wallet, signing or core
Start call is selected.

| Selected control | Preceding runtime | Experimental successor |
| --- | --- | --- |
| Init after a controlled incomplete Stop | Init returns nil; tree becomes ready | ErrStopIncomplete; tree remains unavailable |
| Stop while Init is paused after real Chain.Init | Stop completes before the pause is released | Stop does not complete before release; both calls then finish |
| Explicit teardown after each process | Tree unavailable; consensus handle closed | Tree unavailable; consensus handle closed |

The scheduling facade embeds the real Chain and forwards its methods. Only
the return from its real Init is paused; the other managers retain their real
chain. The caller waits at most two seconds for Stop before releasing Init.
This controlled observation plus the source guard checks the selected ordering.
It does not prove a particular internal database interleaving or an uncontrolled
production scheduling guarantee. The ready_after_Init observation in the
overlap case is collected after both callers join, not at an intermediate instant.

There are two ordinary builds and four ordinary fresh processes. One additional
race build executes the two successor cases with the Go race detector and a
nonzero race exit policy. The focused existing repeated-Stop suite is rerun on
the changed runtime: five roots, nine pass results and zero skips. The earlier
58-root/71-result graph is retained under its original source binding; its
results are not transferred to this successor.

The public source preparer independently stages both variants. Each complete
484-file build map matches the actual ordinary comparison inputs. All three
binaries' linked module tables match the same 30 retained, source-go.sum-bound
module inputs. Actual cache verification commands pass. This does not certify
every unused archive in the module graph.

## Source and replay

Selected node: digitalSloth/go-zenon at
9c71ae82fc983e16f914ae085d4034030c8ebe3b.

- Original node tree: d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6.
- Preceding integrated runtime: 0581880cedda66b02cbc40bd54babd19c29340ce.
- Experimental Init/Stop runtime: d0d1116e23cae298d4e8f4bd604d5894ec07bebb.
- Reference compiler: Go 1.25.14, darwin/arm64, CGO enabled.

The [patch](../tools/gen-state-root-vectors/testdata/candidate-core-init-stop-patch.json),
[preparer](../tools/gen-state-root-vectors/prepare_core_init_stop.py) and
[recorded checker](../tools/gen-state-root-vectors/check_core_init_stop.py)
bind the complete source, output framing, binary digests, actual command
completion and strict observation fields. The two probes are separate from the
runtime patch. Expected admission outcomes are checked by Python and are not
provided to the native child.

Use the finite source-only recipe with an explicitly selected original source
and a new owned workspace:

```sh
python -I -B tools/gen-state-root-vectors/prepare_core_init_stop.py plan \
  --workspace NEW_OWNED_WORKSPACE --go PINNED_GO --variant candidate
python -I -B tools/gen-state-root-vectors/check_core_init_stop_test.py -v
python -I -B tools/gen-state-root-vectors/check_core_init_stop.py
```

The plan executes nothing. Run native commands only through the approved owned
task manager with verified dependency inputs, no implicit external transport,
a 10 GiB free-space floor plus reservations, a 2 GiB expected allocation and a
4 GiB task quota. Reuse retained observations for unchanged inputs. Keep generated
sources, module/build caches and expected disposable databases separate from
protected streams, binaries and source manifests. Preserve unexpected failures
before any owned cleanup.

The completed selected tasks retain one verified CAS object per payload digest
and no scratch. No new external dependency transport or unchanged native
experiment is repeated. These are local ownership/resource bounds, not a
representative production memory or latency budget; APFS physical reclaim is
not measured.

CI runs the portable controls and checker on Linux, macOS Intel and Windows.
Its small source-bound JSON artifact reports the capture platform separately
from the reader platform. Reading retained evidence does not execute the node
on those CI platforms, authenticate distribution or establish independent
human acceptance.

R1 raw-ledger intake, M2 profile agreement and full node qualification remain
open. The accepted-v3/header-bound root gate is unchanged. Runtime state-value
acceptance remains REFUSED.
