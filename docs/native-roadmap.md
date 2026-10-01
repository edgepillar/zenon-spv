# Native verifier roadmap

The initial product verifies Zenon headers and identified account-block
inclusion under explicitly sourced trust inputs, with bounded resources and
explicit unproven properties. It does not authorize irreversible asset release,
claim balances, or provide consensus finality. Reuse the current implementation;
Bitcoin SPV and Portal remain separate future decisions.

The operator workflow from [PR #62](https://github.com/edgepillar/zenon-spv/pull/62)
already supplies configuration inspection/pinning and synthetic native-platform
evidence. Those completed pieces are the baseline, not new roadmap work.

| Stage | Delivery and remaining acceptance gate |
| --- | --- |
| Verification contract | [Current contract](verification-contract.md) resolves header/PoW, flat content, identity and operator-schedule semantics. Historical review/vault wording does not add guarantees. |
| Retained availability | [K/W separation](retention-policy.md) supplies explicit bounded capacity, versioned context/state, migration and delayed-query tests. [Node-derived mixed-height fixtures](delayed-inclusion.md) cover delayed user/embedded segments across v1/v2 and compiled watch/restart/query flows. |
| Trust lifecycle | [Controlled renewal](trust-input-lifecycle.md) records origins, required pins, coverage and restart boundaries. Runtime never authenticates those origins or automatically renews them. |
| Compatibility and resource evidence | Independent byte-level v1/v2 and mixed-height checks run in CI. [Populated capacity workloads](retained-capacity-benchmarks.md) exercise K=16/256/4096 with allocations, state size and operation latency. [Bounded state reads](state-read-allocations.md) reduce input-buffer allocation while preserving full validation. [Flat-content scaling](flat-content-resources.md) adds node-derived stress roots, repeated-list costs and compiled Linux/macOS process memory observations. Consumer-specific distributions, target hardware, Windows peak memory and real-network bandwidth/latency remain open; synthetic evidence is bounded. |
| Controlled network pilot | Select a real consumer and exact account-block targets, authenticate network inputs, then record read-only restart, disconnect, stale peers, expiry and delayed queries. Keep actual observations and all failures separate from synthetic artifacts. No live pilot is claimed by this change. |
| Reviewed release and integration | Obtain independent review of an exact candidate, test a real report consumer, choose the smallest public API, verify source/binary provenance and document upgrades/support limits. CI does not substitute for independent review. |

## Separate consensus research

Before implementation, specify which authenticated history/commitments bind
election inputs, slot authorization, producer transitions and activation.
Define conflict resolution, long-offline recovery, weak-subjectivity/checkpoint
and freshness assumptions, and storage/bandwidth costs. Matching RPC responses
or an operator schedule cannot complete this track.

## Separate state-root research

The candidate [digitalSloth revision](https://github.com/digitalSloth/go-zenon/tree/56ce2c384966f2f1940967257a0788d3998a5eef)
introduces a v3 `StateRoot` hash field and a `StateRootSpork`-gated verification
path. The header appends the root to its hash preimage; the transaction verifier
compares it with a computed root. These are source observations from
[`chain/nom/momentum.go`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/chain/nom/momentum.go)
and [`verifier/momentum.go`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/verifier/momentum.go),
not a security audit, deployment/activation claim or production endorsement.

Review node changes and base compatibility independently; specify root binding,
key/path encoding, absent versus present-empty values, deletion, membership and
absence proofs, activation and migration. Then require controlled testnet
node/client conformance under an explicit profile before any accepting
`STATE_VALUE_INCLUSION` implementation. A state root alone does not identify a
canonical chain. The current client continues refusing v3 and state-value proofs.
Older "no state tree" audits apply to their pinned v1/v2 baseline, not every fork.

## Reuse and later tracks

`edgepillar/zenon-spv` remains the implementation. Upstream SPV/vault history
informs compatibility; pinned `zenon-network/go-zenon` behavior supplies the
reference. Use SDK RPC/model adapters selectively, without importing a whole
wallet/runtime into the verifier. Treat TminusZ Commons as selected threat-model
and test input, the digitalSloth branch as protocol research, the browser light
client as a later comparison, and Trevor's SPV/pyznn as historical prototypes.

Bitcoin work starts only with a concrete use case and its own Bitcoin Core
header/retarget conformance, transaction-to-Merkle binding, reorg and freshness
model. Portal/custody integration needs a further review; neither prototype nor
Commons text is a ready implementation or a replacement for those gates.
