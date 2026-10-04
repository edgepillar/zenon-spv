# Five-block live observer findings

On 2026-10-04, the [block observer](block-observer.md) consumed five distinct real
signed testnet account blocks as one complete read-only batch. Two recorded live
observer runs and one direct native run matched all five exact target bindings.
Wrong target bindings and incomplete evidence produced the expected refusals.
This is fixed-history compatibility with one gateway; network qualification
remains open.

The observed source is
[`ca24277f2af297f171eacaffcc80eeac8c6b8694`](https://github.com/edgepillar/zenon-spv/commit/ca24277f2af297f171eacaffcc80eeac8c6b8694).
Four ordinary Darwin/arm64 executables, built with Go 1.25.14, came from
tested-candidate artifact 11302757698 of
[main CI run 37199981173](https://github.com/edgepillar/zenon-spv/actions/runs/37199981173).
Their archive digest is
`sha256:22f9b01fe1ac8dd934c2871a4e6c08484aee1e10acb40cb064130e585e22489c`;
source-input SHA-256 is
`57b930258cce1346430ac4e44ad0a5df111e4ee384d59400d30e2f413e19a077`.
Archive, manifest and executable pins were checked before execution. Later
documentation commits do not retarget these observations.

## Selection and read-only boundary

All five exact account-header identities were selected from an immutable earlier
momentum-content capture before new account-envelope or candidate-proof
collection. A separate raw account range query then bound all five returned
identities to that selection. Standard-library projections, proof byte oracles,
consumer expectations and controlled variants were sealed before candidate
execution. Selection was separate from the new proof; the original gateway and
research workflow still supplied it, so it was not independent consumer selection.

The segment contained account heights 1..5, all committed at momentum 6026.
Both existing states retained tip 6144, with depth W=6 and capacity K=256/4096.
The states, explicit anchor, experimental activation profile, observed producer
schedule and context pins stayed unchanged. No frontier query, trust renewal,
state advancement, wallet, signing, transaction or deployment was involved.
Each target required `CONTENT_INCLUSION` and `SIGNATURE_AUTHENTICITY` under the
existing explicit trust allowances.

## Recorded outcomes

| Operation | Actual result |
|---|---|
| Separate raw account-envelope capture | Five exact preselected identities matched before candidate execution. |
| Direct native collection at K=256 and K=4096 | Both 9,514-byte proof-only outputs exactly matched preexecution byte oracles. |
| Direct retained queries and consumers at both capacities | Both queries and both consumers matched all five targets. |
| Recorded live observer at both capacities | Collector, verifier and consumer exited 0; each complete batch matched. |
| Direct native live observer at K=4096 | All three children exited 0; the complete batch matched. |
| Wrong block index, swapped position bindings, omitted target, wrong target hash | Four consumers exited 2 with `target_mismatch` and zero checked targets. |
| Reversed expectations array with unchanged exact references | All five targets matched; array order itself is not a position-binding error. |
| Sealed offline bundle missing the middle block's commitment | Verifier exited 2; observer refused before starting the consumer. |

Account blocks in the segment still require ordered, contiguous linkage.
Reordering the expectations array preserves its explicit `index`, `block_index`
and account-header references; swapping identities between positions does not.
Count zero means a failed match, not absence of an account or block. The missing
commitment case changed a private offline candidate and is not a network absence
proof.

All 15 outer candidate statuses and 10 started observer child statuses were
retained. One separate envelope-capture status and six forwarding-process
statuses bring the total to 32 actual process statuses. Six deliberate nonzero
statuses were expected refusals. Every actual outcome matched the sealed plan;
all 63 raw run files were preserved and no candidate phase was repeated.

Each recorded observer forwarded three exact historical queries: the checkpoint
at `tip-K`, confirming momentum 6026 and the five-block account range. Each
recorded 13,224 response-body bytes; the separate account-envelope capture
received 11,219 bytes. These exclude HTTP framing. The proxy forwarded validated
request bytes and returned unmodified response bodies and statuses. It checks
server query compatibility under that forwarding boundary, not equivalence to
native TLS transport or timing. Nine direct native RPC requests are predicted
from the pinned source and selections; those requests were not independently
counted.

## Byte checks and evidence limits

A standard-library raw-record checker recalculated 25 account-block SHA3-256
preimages, 15 public-key/address projections and seven momentum/content
preimages across sealed history, collected bundles and recorded replies. It
performed no independent Ed25519 execution; actual Go verifier processes checked
signatures. The checker belongs to the same development workflow and does not
constitute independent security review.

The original auditor stopped on its own schema assertion: it expected reserved
`STATE_VALUE_INCLUSION` in segment `not_proven` lists. The pinned segment schema
enumerates header integrity, producer authorization, canonicality and state
transition there. The original auditor and failure were preserved. A separately
sealed read-only reconciliation checked that exact source enumeration and kept
state value inclusion absent from `proven`. It reran no candidate or network
request and changed no selected identity, process expectation or trust input.

The private unsigned evidence package has 111 members and SHA-256
`8ed1b5e674c879f97f95e3d7f4a0a0b369a229b28fb05782acc7dc73af51e215`.
Raw identities, replies and trust inputs remain private; the endpoint
configuration is excluded. This aggregate report is not a publicly reproducible
corpus or a signed release attestation.

Process time and Darwin outer high-water records are diagnostics only. They do
not define latency, throughput or hardware-memory qualification; earlier
[fixed-capture resource observations](selected-observer-resources.md) remain
bound to their own source and workload. All scratch directories, loopback
listeners and handlers were cleaned.

Independent operator corroboration, consumer selection, authenticated
anchor/profile/schedule inputs, exact-candidate review and reviewed binary
distribution remain qualification gates. These observations establish no network
freshness, activation, canonicality, consensus finality, balances or state-value
proofs.
