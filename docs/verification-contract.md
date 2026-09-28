# Native light-client verification contract

This document defines the current bounded verification scope and the gates
for the next native light-client milestone. It describes existing behavior
and integration requirements; it does not add a new enforced runtime profile.

## Trust inputs

An integration must record these inputs alongside its verification result:

| Input | Required interpretation |
| --- | --- |
| Network and anchor | Pin chain ID, anchor height/hash, and their provenance. A matching chain ID is not remote identity authentication. A hash fetched from the same untrusted peer is not an independent trust root. |
| Header layout and activation | Only v1 serialization is implemented. Versions 0, 2, 3, and unknown versions are refused. v1 support does not prove v1 is permitted at a particular network height. Network activation rules remain a separate gate. |
| Producer policy | Without an authorizer, signatures bind the claimed key only. With an operator schedule, authorization is relative to that schedule and inherits its external trust. Elected-producer derivation from authenticated chain data is not implemented. |
| Checkpoints and retained state | Treat configured checkpoints and the persisted retained window as trusted local inputs. Protect their provenance and integrity. State-file parsing and version checks do not re-prove their history or authenticate a substituted file. |
| Resource and depth policy | Choose explicit `Policy` limits and `W` appropriate to the experiment. `W` is a strict-past depth requirement for commitments, not a consensus finality certificate. Header-chain ACCEPT alone does not establish that depth for a selected target. |
| Peer observations | k-of-n RPC agreement detects disagreement. It cannot establish elected-producer quorum or canonical history. Record peer assumptions separately from cryptographic evidence. |

`HeaderState` is currently caller-constructible. Functions consuming it assume
that its headers came from successful verification under the intended trust
inputs. Loading JSON, calling `Append`, or supplying `HeaderState` fields does
not create that provenance. Validated handles and stronger resume validation
remain implementation work; even complete signature revalidation would not
authenticate an attacker-chosen trust root.

## Result interpretation

Consumers must inspect the outcome, required `Proven` guarantees, and the
external assumptions they accept. The absence of a guarantee from `NotProven`
does not mean that it is proven. Existing assumption tags are not a complete
record of every integration input, especially custom anchors and local state.

| Path | Bounded meaning of ACCEPT |
| --- | --- |
| Header verification | Implemented layout hashes, signatures, chain identity, links, height progression, configured checkpoint matches, and the retained-window requirement pass relative to the supplied state. |
| Required operator schedule | In addition, retained or newly verified headers match the configured schedule. This does not prove that the network elected that schedule. |
| Content commitment | A target account-header triple belongs to the content bound by a retained header, with the required strict-past depth, assuming retained-state provenance. |
| Account segment | The implemented account-block checks and commitment checks pass. This does not prove state-transition execution or a balance. |
| State value | No accepting implementation exists. RPC balances and `ChangesHash` are not authenticated state-value proofs. |

REJECT means supplied evidence fails an implemented validity check. REFUSED
means the supported verifier cannot establish the requested result, for
example because evidence, producer coverage, depth, or a supported header
layout is unavailable. Neither permits treating an unproven value as zero.
Header verification must retain the original state on REJECT or REFUSED.

Persistence success precedes accepted watch progress. A save failure leaves
the prior in-memory tip in use and is retried within the configured limit.
A failure after rename can leave new bytes visible with durability uncertain;
see [watch persistence](watch-persistence.md) for the platform boundary.

## Source-pinned compatibility evidence

The [node-derived corpus](../internal/testdata/conformance/README.md) pins
go-zenon commit `3a4131e63881058b6ce2ee81d3a41d0033fafc99`. Its v1 expected
hashes are computed by the node implementation, not by this verifier. Real
v2 preimages are included as refusal cases. A separate Python checker
reconstructs the hashes and wire encodings independently.

The node's [momentum serializer](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/chain/nom/momentum.go)
includes both price fields for v2. Its [version checks](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/verifier/momentum.go)
depend on Dynamic Plasma activation. A source branch or synthetic fixture
does not establish activation on any public network.

## Next acceptance gates

1. Add v2 serialization as a separate change: preserve both prices through
   RPC, proof bundles, persistence, and hash computation; test each field's
   tampering and zero/nonzero/max values against this corpus.
2. Specify and enforce network-specific activation profiles with trusted
   provenance and tests before, at, and after the transition. Refuse unknown
   profiles instead of inferring activation from an untrusted RPC response.
3. Strengthen retained-state provenance and resume validation before an
   application pilot. Define which guarantees the application actually needs.
4. Run a controlled read-only pilot with restart, stale/forked/malformed
   peers, producer-coverage gaps, resource limits, and persistence failures.
   Record the exact source, binary, trust inputs, and bounded outcomes.

Chain-derived election inputs, fork selection/finality, and authenticated
state-value proofs are separate research milestones. Bitcoin SPV and Portal
are outside this native-client milestone. Passing the corpus or CI alone does
not qualify this implementation to authorize irreversible settlement.
