# Recorded chain-69 Settlement history replay

The native SPV test replays original-node Settlement proofs from an isolated
chain-69 database. The fixture stores the three selected ABI values at H5,
deletes the batch at H6, reopens the database, and checks the older root again.
A further reopen of the pruned fixture demonstrates the H5 pruning boundary.

Source is the pinned node `938fca3b7787da86827a5eb63371509b36e14761`.
The proof and pruned RPC bytes matched across Linux, macOS and Windows in
[the first-insertion run](https://github.com/edgepillar/zenon-spv/actions/runs/44882528531/attempts/1).
The original archive IDs are `14698214783`, `14698846187` and `14697938817`,
respectively. The [existing stored ABI fixture](../internal/testdata/conformance/batch-context-node-witness.json)
supplies the selected value bytes without a duplicate copy.

The proof-only collector requests the three full keys at H5. The native
checker reconstructs the unsigned H5 header root, recovers the same value
bytes and decodes BatchEntry, domain record and domain config. The same H5
proofs fail under the H6 root. A pruned H5 response fails on the first read
without a bundle or a later-height fallback. At H6, the original batch
proof establishes mathematical absence under the H6 fixture root.

```sh
go test -run '^TestExperimentalV3RecordedChain69TypedHistory$' ./internal/verify
```

The headers come from unsigned, disposable fixture inserts. Replay qualifies
the selected proof and ABI paths. Owned header acceptance and actual chain-69
consumer completion remain separate gates.

## Signed height-two frontier replay

A separate native test consumes the original signed v1 frontier from
[run 43653383092, attempt 1](https://github.com/edgepillar/zenon-spv/actions/runs/43653383092/attempts/1),
artifact `14136634774`, request 32. The 697-byte response has SHA-256
`931a991acef939bd4d9c0f55e293c64402189940b406b612a0e8bed9668acbc4`.
That run ended with a startup refusal even though its post-sync diagnostic
observed H2.

The replay passes the response through `FetchFrontier` and the native
`VerifiedState` entry point. Its configured inputs are the source genesis H1,
a v1 profile ending at H2, and the exact H2 producer slot corroborated by the
original-node check in [run 44882528531](https://github.com/edgepillar/zenon-spv/actions/runs/44882528531/attempts/1).
A wrong slot timestamp or a profile activating v2 at H2 rejects the same
signed header and leaves the retained window empty.

```sh
go test -run '^TestRecordedChain69V1FrontierEntersNativeState$' ./internal/verify
```

Acceptance covers header linkage, signature authenticity and producer
authorization under the configured inputs. Canonicality, a signed v3
successor and a proven BatchEntry query remain outside this result.
