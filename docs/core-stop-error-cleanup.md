# Core-manager cleanup after a close error

The experimental successor completes all sequential `Zenon.Stop()` cleanup calls
and returns their errors together. The preceding runtime returned immediately
when the real cache manager reported `leveldb.ErrClosed`, leaving the consensus
database open. If both owned database handles were already closed, it also lost
the final database's close error.

This is a finite keyless core-manager experiment based on
`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b` and the
[pre-start worker Stop successor](zenon-worker-prestart-stop.md). The upstream
repository is unchanged. The sole new runtime delta adds the standard-library
`errors` import and joins the existing cleanup calls in their original order:
protocol, pillar, subscriptions, event printer, consensus, chain, final database.
Protocol shutdown keeps its existing void-returning call. Returned errors remain
available through `errors.Is` and the joined error leaves.

## Observed behavior

Two ordinary comparison builds and six fresh processes ran on Darwin ARM64 with
Go 1.25.14 and CGO enabled. Each process constructed real chain, cache, consensus,
and core managers, initialized the selected unsigned source genesis, and called
public `Zenon.Stop()`. No comparison process called `Zenon.Start()`.

| Controlled case | Preceding runtime | Successor |
| --- | --- | --- |
| Healthy handles | Final database closed; no error | Same |
| Cache handle closed before Stop | Cache error returned; final database still open | Cache error returned; final database closed |
| Cache and final database handles closed before Stop | One close-error leaf returned | Both close-error leaves retained |

Tagged bridges close only handles created inside the experiment's owned case
directories. They do not replace managers or fabricate returned errors. This
models a deliberately preclosed handle, not disk failure, power loss, concurrent
shutdown, or remote activity. The preceding runtime's still-open final handle is
closed by explicit caller teardown **after** its public Stop observation. A
read-only handle query distinguishes those observations; a subsequent real open
and close verifies that the final database can be reopened after teardown.

Before and after each Stop, the existing independent source-genesis witness
checks the complete root, value, proof, readiness, and same-height foreign-hash
refusal. Six ready observations and six stopped observations match the model.
Expected roots, values, and proofs are never passed to the comparison child.
The source genesis has no signature or authenticated header-bound state root.

The source-bound native suite passed **53 root tests, 62 pass results, zero
skips** across five packages: the preceding 50 roots plus three real-manager
Stop regressions. The ordinary `./cmd/znnd` entry point also compiled, with 116
linked/downloaded module archives checked against retained inputs and unchanged
`go.mod`/`go.sum`. That binary was not executed. The whole module payload graph,
wallet startup, peer server, RPC listener, and full node are not qualified here.

## Source views and bounded output

| View | Git tree | Files |
| --- | --- | ---: |
| Preceding runtime | `2887e4d8ee4c8c148f94c119719853c7f4a4df74` | 471 |
| Successor runtime | `053c87e5bc4addd1bb70a467cb34facd439e66bc` | 471 |
| Baseline comparison | `fa3062878b04dbe233b2233f596abe46b93c46ec` | 480 |
| Successor comparison | `99db5c9f9f25360426c310bb089e1bf4be4942ea` | 480 |
| Successor native tests and ordinary entry build | `2147eba7ef3a1ae06970f2f692b16c1af98419bc` | 481 |

The first native test invocation exceeded its 8 MiB stdout cap because source
genesis construction emitted verbose account-pool information logs. Its actual
exit was -13, capture was incomplete, and it remains `FAILED_CAPTURE_LIMIT`.
Its partial output and original closed-task metadata and scratch were preserved;
no successful test outcome is inferred from that attempt.

The resumed native view adds one tagged `_test.go` file that discards only those
diagnostic handlers in the test binary. Assertions, returned errors, database
operations, and ordinary comparison sources are unchanged. The successful
invocation produced 75,351 bytes under the same 8 MiB cap. Completed comparison
builds and all six processes were reused. No external dependency transport was
repeated or newly needed. The successful resumed workspace was closed and its
declared disposable generated files removed after durable process checks.

## Reproduction and CI

`tools/gen-state-root-vectors/prepare_core_stop_errors.py` provides `plan`,
`prepare`, and `verify`. Preparation accepts the pinned original node source and
a new owned workspace; it never downloads dependencies or runs a backend.
The default view reproduces either 480-file comparison. Select
`--variant candidate --native-tests` for the separately pinned 481-file native
test view, including the test-only diagnostic handler. Baseline native-test
selection is refused. Use the approved task-storage manager to execute the
returned finite argument lists with the 10 GiB free-space floor plus expected
allocations and reservations. The ordinary node entry-point recipe is build-only.

`check_core_stop_errors.py` checks the immutable public capture and independent
model. The two portable control suites cover source views, resource policy,
capture completeness, error retention, caller teardown, source-genesis bytes,
proof refusal, module and binary pins, and false acceptance claims. Linux,
macOS, and Windows CI run these portable controls and recorded-capture checks;
they do not rerun the Darwin reference backend.

This experiment does not close M0–M5, establish profile agreement, activate a
network rule, authenticate distribution, select a canonical chain, prove
consensus finality, or enable state-value acceptance. Runtime state-value
verification and the consumer result remain `REFUSED`. The frozen review
`6ecc2310538d511e3b26bea4c658082853266a11` remains unchanged.
