# Native light-client verification contract

This document defines the current bounded verification scope and the gates
for the next native light-client milestone. It describes existing behavior
and integration requirements, including the explicit runtime activation profile.

## Trust inputs

An integration must record these inputs alongside its verification result:

| Input | Required interpretation |
| --- | --- |
| Network and anchor | Pin chain ID, anchor height/hash, and their provenance. A matching chain ID is not remote identity authentication. A hash fetched from the same untrusted peer is not an independent trust root. |
| Header layout and activation | Layouts v1 and v2 are implemented. Without a profile, verification accepts only v1 and makes no activation claim. An explicit anchor-bound profile enforces the first v2 height and a coverage limit under external operator trust. Unsupported versions still refuse. |
| Producer policy | Without an authorizer, signatures bind the claimed key only. With an operator schedule, authorization is relative to that schedule and inherits its external trust. Elected-producer derivation from authenticated chain data is not implemented. |
| Checkpoints and retained state | Treat configured checkpoints and the persisted retained window as trusted local inputs. Save/load recheck hashes, signatures, identity, links, profiles, and applicable checkpoints within resource limits. Protect provenance: these checks do not re-prove evicted history or authenticate a substituted, internally valid file. |
| Resource and depth policy | Choose explicit `Policy` limits and `W` appropriate to the experiment. `W` is a strict-past depth requirement for commitments, not a consensus finality certificate. Header-chain ACCEPT alone does not establish that depth for a selected target. |
| Peer observations | k-of-n RPC agreement detects disagreement. It cannot establish elected-producer quorum or canonical history. Record peer assumptions separately from cryptographic evidence. |

The CLI and watch use the [verified state API](verified-state-api.md), which
owns its headers and captures verification policy. Callers cannot inject raw
state or mutate accepted evidence through input or snapshot aliases. The
lower-level `HeaderState` remains caller-constructible and requires its callers
to maintain provenance. `LoadTrustedState` explicitly relies on protected local
file provenance; signature revalidation does not authenticate a substituted
window or an attacker-chosen trust root.

## Result interpretation

Consumers must inspect the outcome, required `Proven` guarantees, and the
external assumptions they accept. The absence of a guarantee from `NotProven`
does not mean that it is proven. Existing assumption tags are not a complete
record of every integration input. The verified state API reports configured
anchor and persisted-state trust explicitly; legacy free functions retain
their earlier assumption reporting.

Use the optional [verification context](verification-context.md) diagnostic
to record captured settings and compare their fingerprints. It intentionally
omits private audit metadata and is not a complete provenance record, a proof
receipt, or a substitute for the result's guarantees and trust assumptions.

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
v2 preimages and a v1-to-v2 transition are covered. Missing profiles refuse,
and configured profiles enforce activation and coverage. A separate Python checker
reconstructs the hashes and wire encodings independently.

The node's [momentum serializer](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/chain/nom/momentum.go)
includes both price fields for v2. Its [version checks](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/verifier/momentum.go)
depend on Dynamic Plasma activation. A source branch or synthetic fixture
does not establish activation on any public network.

## Next acceptance gates

1. Independently authenticate network-specific activation information. The
   current profile is an operator attestation, not a chain-derived proof.
2. Review v2 application behavior against additional independently sourced
   network evidence. Local vectors establish serialization compatibility;
   they do not re-execute Dynamic Plasma price transitions.
3. Use the validated application API and establish external provenance for
   anchors and persisted state before a deployment pilot. Define which
   guarantees the application actually needs.
4. Run a controlled read-only pilot with restart, stale/forked/malformed
   peers, producer-coverage gaps, resource limits, and persistence failures.
   Record the exact source, binary, trust inputs, and bounded outcomes.

Chain-derived election inputs, fork selection/finality, and authenticated
state-value proofs are separate research milestones. Bitcoin SPV and Portal
are outside this native-client milestone. Passing the corpus or CI alone does
not qualify this implementation to authorize irreversible settlement.
