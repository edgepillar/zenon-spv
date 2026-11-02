# Selected original-executor StateDiff conformance

The selected executor's actual in-memory `Store.Apply` has now been exercised
separately from the [original-node trie test](selected-original-node-conformance.md)
and the [native mathematical comparison](zeno-smt-conformance.md). The added
harness applies the supplied operations, rather than only importing the stated
post-state. This is partial D1 evidence; it does not accept an L2 transition,
select a network profile or authenticate an L1 header/root.

## Selected source and execution

| Input or result | Identity or result |
| --- | --- |
| Executor | `Zeno-L2/zeno-executor@caeaf764270b1489a53c860c6006026af208f924` |
| Executor Git tree | `e1ca785d0176d7d53c657d66ee19d9550efccf37` |
| Selected node source | `digitalSloth/go-zenon@938fca3b7787da86827a5eb63371509b36e14761` |
| Source selection | [devnet sources.txt](https://github.com/Zeno-L2/zeno-devnet/blob/04dc0797f7bcc02e48e0acba3b0ac49df2d3289d/sources.txt) |
| Normative vectors | 41,255 bytes; SHA-256 `d57aa52a683b2b768de16e6212058af9079125aca54feb2fdf007e9ba8c5568f` |
| Platform and compiler | darwin/arm64; Go 1.25.14; CGO disabled |
| Actual result | Exit 0, complete output, 24 test pass events, no fail or skip events |
| Original executor suite | 16 named cases plus its parent and the original mixed-empty/delete test |
| Added operation execution | CV-APPLY-1 and all three CV-APPLY-2 steps |
| Independent comparison | Four roots and all 15 complete generated proof byte strings matched Python |
| Execution record | SHA-256 `6b64a9ac28d573d41e35a4c280e64670c1648a3fb7080c9fd6da40b807993b82` |
| Execution gate | SHA-256 `181da97ac091295d90429f132007e8ace532c362db50843c21ae697def4102c1` |

All 302 original executor files and 484 original node files matched their
selected Git blobs and SHA-256 records before and after execution. No original
source or module file was changed.

The executor's original `go.mod` declares a historical 56ce2c3 module version
and a relative source replacement. The actual selected devnet cohort replaces
that source with 938fca3. The isolated execution made this choice explicit in a
task-owned Go workspace; it did not execute the declared historical module
instead. All 19 actually loaded external modules matched the source cohort's
`go.sum` through independent ZIP and expanded-directory h1 checks, repeated for
directories after the test. Full historical module-graph verification remains
`NOT_ESTABLISHED`.

## Actual operation coverage

The unchanged executor
[conformance test](https://github.com/Zeno-L2/zeno-executor/blob/caeaf764270b1489a53c860c6006026af208f924/internal/state/conformance_test.go)
runs 16 vector cases with a standalone expected root. It explicitly omits
CV-PATH-2, a coverage declaration, and CV-APPLY-2, a multi-step diff sequence.
Do not report its result as 18 executed original cases.

The added
[harness](../tools/gen-state-root-vectors/executor-applier_test.go.txt) exercises
the unchanged [Store.Apply](https://github.com/Zeno-L2/zeno-executor/blob/caeaf764270b1489a53c860c6006026af208f924/internal/state/store.go)
implementation:

| Case and step | Supplied diff | Observed result |
| --- | --- | --- |
| CV-APPLY-1 | Seed two leaves, then delete one and insert a present-empty leaf in one diff | Expected root, absence of the deleted key and presence of the empty value |
| CV-APPLY-2 step 1 | One insert | Expected incremental root |
| CV-APPLY-2 step 2 | Two entries in one diff | Expected incremental root |
| CV-APPLY-2 step 3 | One delete and one present-empty write in one diff | Expected incremental root and distinct presence semantics |

Each post-state also matched a fresh `RootOfLeaves` computation and the store's
current root. The harness checked generated inclusion/absence proofs for every
selected path at each step. Independently, Python rebuilt each full tree and
serialized every proof byte. L2 paths were supplied directly: they were not
hashed again as raw L1 keys. Nil is delete; a non-nil zero-length value is a
present-empty write.

The [recorded facts](../internal/testdata/conformance/executor-statediff.json)
preserve those roots, states and proofs. The native SPV regression compares them
with its candidate checker and a separate full-tree/serialization oracle.
It also refuses a proof under a different step's root, a double-hashed path or
flipped presence. Hosted replay of these facts does not reexecute the executor.

## Resource outcome and preserved preflight

The cold local operation took 36.834 seconds. Its largest workspace observation
taken after a command was 244,661,609 bytes, about 233.3 MiB. This is not a
continuous peak, representative production measurement or hardware budget.

The first dependency preflight stopped before any selected test because one
293-byte Wazero module-metadata file was absent from the local file proxy. That
failed attempt remains retained. Only the required metadata was fetched and
independently checked against the selected `go.sum` h1; no completed native
test was repeated. The actual successful run loaded its dependencies offline,
removed 28,103,067 bytes of its own verified fresh module ZIP copies before
compilation and removed its temporary caches on completion. Physical reclaim
was not measured. Protected sources, outputs and failure evidence remain.

## Reproduction and remaining gates

Use fresh isolated, verified checkouts of the two selected source revisions
with verified dependencies and an explicit workspace selecting that node source.
Keep the original module files unchanged. Add the published harness only at
`internal/state/spv_selected_applier_test.go`, refusing an existing destination.
From the selected executor checkout:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
  go test -mod=readonly -p 1 -json -count=1 -timeout=60s \
  -run '^(TestSMTConformanceVectors|TestApplyMixedPresentEmptyAndDelete|TestSPVSelectedExecutorApplier)$' \
  ./internal/state
```

`GOWORK` must point to the explicit workspace; clear unrelated Go flags.
The harness locates the selected node's vector file through `go list -m`.
Concatenate output events before reading the JSON after `SPV_EXECUTOR_APPLIER`;
long log lines can be split. Preserve actual exit/completeness, source, workspace,
toolchain and dependency identities.

The [D0-D3 contract](batch-entry-query-contract.md) still needs selected trust
inputs, actual network activation/profile, owned accepted v3 headers and one
typed consumer. Node height/hash recovery, representative R1 data, production
limits and independent review remain separate gates. No live chain, service,
wallet, signing operation or deployment was started by this execution.
