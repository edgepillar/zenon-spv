# Recorded account PoW runtime and RPC boundaries

The existing [finite node PoW corpus](../tools/gen-node-account-basic-vectors/README.md#separate-finite-account-pow-mode)
records 32 fixed difficulty/nonce probes and 64 actual account-method calls at
`zenon-network/go-zenon@c64ed6279ff1d07335dab0ac36156dec8b5b71e9`.
Its SHA-256 is
`560ff77f5fe092e99222399309da164c0539dec749e95b0e1788cd52fe30716f`.
The independent Python oracle continues checking all PoW preimages, unsigned
thresholds, complete store maps and ordered reads. No recording is regenerated.

The native follow-up sends those same immutable observations through the real
segment verifier and production RPC fetch client, using loopback JSON-RPC
responses. Original signed account blocks, trust inputs, retained headers and
commitments are selected before peer data or method outcomes. The test selects
the complete eight-difficulty, four-nonce and two-method inventory explicitly;
a node `MATCH` never selects an expected acceptance.

Six native test roots exercise 324 controls:

| Boundary | Controls | Required result |
| --- | ---: | --- |
| Original runtime inputs | 64 | Only the two original signed inputs accept inclusion/signatures; 62 changed inputs reject at the claimed hash |
| Coherent changed runtime hash | 62 | Recomputing the claimed hash cannot supply the unchanged original signature; all reject |
| Original RPC inputs | 64 | Two original blocks convert and verify; 62 changed inputs return hash errors without partial blocks |
| Coherent changed RPC hash | 62 | All convert with exact nonce/difficulty/signature bytes, then reject at signature validation |
| Complete send/receive RPC ranges | 64 | Two original ranges verify; 62 failed first sends cannot return the valid following receive |
| Missing commitment inputs | 8 | Both original method observations, through both layers, refuse absent retained headers and absent supplied proofs |

The coherent-hash RPC controls replace only the `hash` member using
`json.RawMessage`. This preserves the exact unsigned JSON integers, including
both sides of `2^63` and the maximum `uint64`, without a float conversion. Every
projected block differs from the original signed block only in the selected
difficulty and nonce. The original claimed hash and signature remain unchanged
until that control explicitly replaces the claimed hash. No key, signature,
nonce search, new account history or new commitment is generated.

Each query preserves its selected verified-state snapshot. Every rejection and
refusal carries no proven guarantees. Positive results retain inclusion and
signature authenticity with state transition unproven; synthetic method/store
outcomes do not authenticate execution eligibility, account PoW or difficulty
policy, plasma accounting, canonicality, finality, freshness, activation or
state values. A coherent hash is a transport/byte check, not signed history.

Run the finite native controls with:

```sh
go test -v -count=1 -run '^TestNodeAccountPoW' ./internal/conformance
```

Linux, macOS and Windows CI run this selection alongside the unchanged Python
oracle, complete existing tests and 59 offline pilot scenarios. The new controls
build no CLI, execute no reference node and perform no new resource sampling.
Exact published source, native CI and artifact qualification are required before
delivery. Independent consumer/network trust, real authenticated histories,
human review and authenticated release remain separate acceptance gates.
