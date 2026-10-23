# Candidate v3 header encoding

The native `chain.CandidateV3Header` codec reconstructs one selected research
layout. It returns untrusted encoding data. The production verifier still
supports only v1/v2, and state-value verification remains refused.

## Source and recorded bytes

The selected format is
[`digitalSloth/go-zenon@9c71ae82`](https://github.com/digitalSloth/go-zenon/blob/9c71ae82fc983e16f914ae085d4034030c8ebe3b/chain/nom/momentum.go).
Its `ComputeHash` body is byte-identical to the body at
`56ce2c384966f2f1940967257a0788d3998a5eef`; this comparison does not establish
whole-node equivalence. The selected source explicitly identifies versions 2
and 3 and uses SHA3-256 through `types.NewHash`.

The existing
[`candidate-v3-balances.json`](../tools/gen-state-root-vectors/testdata/candidate-v3-balances.json)
remains bound to its original execution at `56ce2c38`, with SHA-256
`8b69cdaf78ae4eeaad79cdfa493ed9633a1202e09819178da83e17be385f00d3`.
All ten recorded header cases remain inputs: four v1/v2 regressions and six v3
preimage/hash cases. These vectors are synthetic and unsigned, with profile
agreement and runtime state-proof acceptance explicitly false. Reusing their
bytes is not a new node execution or evidence of network activation.

The [candidate contract](state-root-candidate-contract.md#header-and-activation-binding)
lists all offsets in the 208-byte preimage. The final 32 raw bytes are the state
root, after both uint64 big-endian prices. The projected header carries the
already computed data and content hashes.

## API and input limits

| Entry point | Behavior |
| --- | --- |
| `Preimage` | Reconstruct exactly version 3 into a fixed 208-byte array; return zero bytes and an error for every other version. |
| `ComputeHash` | Apply SHA3-256 to those bytes. It does not authenticate a header or provide a trusted expected root. |
| `DecodeCandidateV3Header` | Bound the complete JSON document before scanning, including surrounding whitespace; return a zero value on failure. |
| JSON marshal/unmarshal | Require the complete projected envelope and a self-consistent claimed hash. Publish a decoded value only after every check succeeds. |

The JSON representation is a flat fourteen-field envelope: the existing
projected `Header` fields plus `stateRoot`. Each exact field name must occur
once; unknown, duplicate, missing, null and trailing fields/input are refused. Hashes use
exactly 64 hexadecimal characters without a prefix. Public key and signature
fields use canonical padded Base64 for 32 and 64 bytes. Integers must fit uint64.

The complete-document limit is 8 KiB. This is a local codec budget, not an agreed
network or proof-service limit. Call `DecodeCandidateV3Header` to enforce it:
`encoding/json` removes surrounding whitespace before invoking a type's
`UnmarshalJSON` callback. The callback also bounds the object bytes it receives.

Width-correct key and signature bytes do not establish signature validity.
This type has no constructor for accepted verification state. Existing
`Header` v1/v2 serialization, protocol profiles, context pins, saved-state
schemas and `ValidateHeaderVersion` remain unchanged.

## Verification and next gate

Run the focused native controls with:

```sh
go test -race -count=1 -json -run '^TestCandidateV3Header' ./internal/chain
```

Eight top-level tests and 141 named subtests compare the recorded preimages
and hashes, exercise complete-field and representation failures, enforce the
byte limit and check failure atomicity. Dummy key/signature bytes exercise
encoding without signing or authenticating the recorded headers. The ordinary
chain/verifier regressions continue to cover v1/v2 and default refusal.

This is M3 format preparation. The
[native roadmap](native-roadmap.md) still requires an agreed profile and an owned
accepted v3 header/context, whose root must bind the locally derived
address/token key, bounded proof, persisted context and strict typed consumer
result. This codec does not close those gates.
