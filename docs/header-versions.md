# Supported momentum versions

The verifier implements the **version-1 momentum serialization only**.
It refuses version 0 (including an omitted RPC `version`), version 2,
version 3, and every other unsupported value. A matching hash and valid
signature over the version-1 layout do not make another version supported.

This is a serialization boundary, not proof that version 1 is valid at
every height on a selected network. Network activation rules, producer
selection, and canonicality remain separate requirements. See
[`trust-model.md`](trust-model.md) for the existing trust boundaries.

## Source basis

These are pinned source observations, not live-network activation claims:

- In go-zenon commit
  [`667a69d`](https://github.com/zenon-network/go-zenon/blob/667a69d9e9a418edf7580b08492ba5dcb9efd63a/verifier/momentum.go),
  `rawMomentumVerifier.version` permits only version 1.
- In go-zenon commit
  [`3a4131e`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/chain/nom/momentum.go),
  `Momentum.ComputeHash` appends `NextFusionPrice` and `NextWorkPrice`
  when `Version >= DynamicPlasmaMomentumVersion` (2). The
  [version rule at that same commit](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/verifier/momentum.go)
  requires version 2 when Dynamic Plasma is active and version 1 otherwise.

The SPV header type does not carry those price fields. Applying its existing
preimage to a claimed version 2 would omit signed data. Future versions
must not silently inherit the version-1 layout either.

## Enforcement and errors

`chain.ValidateHeaderVersion` is the shared support check. The low-level
`Header.ComputeHash` still computes the version-1 preimage; it does not
validate protocol support by itself.

| Boundary | Behavior |
|---|---|
| Header-chain verifier | Checks each incoming version before hashing and all retained versions before extending the window; unsupported input returns `REFUSED / ReasonUnsupportedHeaderVersion` with the original state. |
| Commitment verification | Checks the entire retained window, including the target, intermediate headers, and tip. Segment verification inherits this check through its commitment verification. |
| State-value verification | Refuses unsupported retained versions without claiming a trusted depth or any proven guarantee. State-value inclusion remains unsupported. |
| Retained-window authorization | Checks versions even with producer authorization disabled. A producer schedule cannot enable an unsupported serialization. |
| RPC conversion | Returns an error wrapping `chain.ErrUnsupportedHeaderVersion`; no header or partial batch is returned. A multi-peer caller may report insufficient healthy peers or quorum. |
| State load | Checks every stored header before policy-driven truncation. A smaller window cannot discard an unsupported version to make the state usable. |
| State save | Checks before creating or replacing files. An unsupported state cannot overwrite an existing valid state. |

The momentum version is distinct from both the bundle wire version and the
state-file schema version. Those formats and their existing version numbers
are unchanged.

For `verify-headers`, an unsupported incoming header produces exit code 2
and is not persisted. Loading an unsupported saved state remains a setup
error (CLI exit code 70), following the existing state-load error convention.
`watch` refuses such a saved state at startup. RPC errors during a running
watch remain unsuccessful ticks under the existing retry behavior.

## Validation and further work

Regression tests construct deliberately invalid version-2/3 envelopes with
valid Ed25519 signatures over the old preimage. These are adversarial
fixtures, **not reference vectors for actual version-2/3 serialization**.
They cover incoming headers, retained anchors and depth evidence, RPC
conversion, persistence, and CLI refusal. Existing version-1 acceptance
tests remain in place. All test traffic uses local fixtures or local HTTP
servers; this does not establish live-node compatibility.

Adding version-2 support requires carrying both price fields through RPC,
bundles, retained state, and hashing, with independent reference vectors
and explicit activation/trust rules. Merely adding `2` to the accepted
version list is insufficient. Changes to account-block versions, state-root
proof support, or network activation discovery are outside this change.
