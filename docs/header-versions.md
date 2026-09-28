# Momentum versions and activation profiles

The client implements v1 and v2 signed momentum layouts. Versions 0, 3,
and all other unknown values are refused before hashing or trusting a
retained header. `Header.ComputeHash` is a low-level primitive; callers must
check layout support and activation policy separately.

V2 appends `NextFusionPrice` and `NextWorkPrice` as big-endian uint64 values.
Both fields are preserved through RPC conversion, bundles, retained state,
and hashing. Missing or null v2 JSON prices fail decoding. The verifier
requires zero prices in v1 and prices at least 1000 in v2. It does not
re-execute the dynamic pricing state transition.

## Explicit operator policy

`verify-*` and `watch` accept `--protocol-profile <path>`. The profile is a
trusted local input, never supplied implicitly by a bundle or an RPC peer.
Without it, verification remains v1-only and makes no claim that v1 is
permitted at every height. Fetch tools can decode and hash both layouts;
fetching a v2 header does not authorize its acceptance.

A profile JSON object has these fields:

| Field | Meaning |
| --- | --- |
| `version` | Profile schema; must be `1`. |
| `anchor` | The exact configured trust root: `chain_id`, `height`, and `header_hash`. The hash uses 64 hexadecimal characters. |
| `valid_through` | Last covered momentum height, strictly greater than the anchor height. Coverage begins immediately after the anchor. |
| `v2_from_height` | First momentum height required to use v2. Before it, v1 is required. Zero explicitly selects v1 throughout coverage. |
| `source` | Nonempty provenance description, at most 1024 bytes. Recording it does not authenticate it. |

The profile loader accepts one JSON object of at most 16 KiB and rejects
unknown, duplicate, or differently cased field names and trailing JSON. All
five fields and all three fields inside `anchor` must be explicit and non-null;
this includes an explicit zero for `v2_from_height` or a custom `chain_id`.
The nested anchor follows the [anchor configuration](anchor-configuration.md)
schema. Profile objects embedded in retained state obey the same field rules
and 16 KiB limit. Failed decoding leaves an existing profile unchanged and
does not echo private field names or values in profile parser diagnostics.
The profile schema and anchor are checked again in the verifier, including
for callers that construct policy directly.
ACCEPT under a profile includes `TRUST_EXTERNAL_PROTOCOL_PROFILE`. This trust
assumption is separate from an operator-attested producer schedule.

No mainnet or testnet activation height is hard-coded here. A profile must
be established by the operator using evidence they explicitly trust. The
synthetic transition in the conformance corpus is not a network configuration.

## Source basis and height semantics

The implementation and corpus pin go-zenon commit
[`3a4131e63881058b6ce2ee81d3a41d0033fafc99`](https://github.com/zenon-network/go-zenon/tree/3a4131e63881058b6ce2ee81d3a41d0033fafc99):

- [`Momentum.ComputeHash`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/chain/nom/momentum.go)
  adds both prices starting at version 2.
- [`rawMomentumVerifier`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/verifier/momentum.go)
  requires v2 when Dynamic Plasma is active and v1 otherwise, and checks
  basic price limits. [`dp.MinResourcePrice`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/dp/dp.go)
  is 1000 at this pin.
- [`momentumStore.IsSporkActive`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/chain/momentum/embedded.go)
  evaluates the stored frontier and has a genesis-frontier exception.
  **Do not copy a spork enforcement height directly into `v2_from_height`.**
  This profile names the first incoming momentum that must use v2; deriving
  it requires the spork state and the relevant preceding frontier context.

These are source observations, not assertions of public-network activation.

## Persistence and failures

Profile-bound state uses schema **2**, including the full profile. Older
clients refuse that schema instead of ignoring activation constraints.
Legacy v1-only state without a profile keeps schema 1. The bundle envelope
remains at version 1; new clients require the price fields for v2 headers.

Resume requires an exact match of the configured profile and anchor,
including anchor height. Removing, changing, or extending a profile fails
rather than silently changing trust policy. To adopt a different profile,
verify the required history into a new state file from an independently
trusted anchor. Automatic migration or profile renewal is not implemented.
All retained headers are checked before a smaller window can discard any.

Normal profile and state serialization is unchanged. Older manually authored
files that relied on duplicate fields, case-insensitive names, or an omitted
custom chain ID must be corrected before use. Oversized embedded profile
objects are rejected even when the surrounding state file is within its own
byte limit. These checks remove parsing ambiguity; they do not authenticate
the profile's activation claims or renew expired coverage.

| Condition | Verifier outcome |
| --- | --- |
| Unknown momentum layout | REFUSED / `ReasonUnsupportedHeaderVersion` |
| V2 without a profile | REFUSED / `ReasonProtocolProfileRequired` |
| Invalid profile or profile/state mismatch | REFUSED / `ReasonInvalidProtocolProfile` or `ReasonProtocolProfileMismatch` |
| Header outside profile coverage | REFUSED / `ReasonProtocolProfileCoverage` |
| Supported version conflicts with activation policy | REJECT / `ReasonHeaderVersionInactive` |
| Basic resource-price bound fails | REJECT / `ReasonInvalidResourcePrice` |
| Signed price changed without a matching hash/signature | REJECT through existing hash/signature checks |

Failure does not advance header state or report proven guarantees. Bad
configuration or saved state is a CLI setup error (exit 70); incoming
REJECT and REFUSED retain exit codes 1 and 2. Decode errors, including missing
v2 price fields in a bundle, follow the existing setup-error convention.
RPC conversion errors return no partial batch.

The [independent corpus](../internal/testdata/conformance/README.md) covers
both layouts, activation boundaries, price tampering, CLI use, persistence,
and a local HTTP watch/resume experiment. State provenance, producer election,
canonicality, finality, balances, and Dynamic Plasma price-transition
correctness remain outside these guarantees.
