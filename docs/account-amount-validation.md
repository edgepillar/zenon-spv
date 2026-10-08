# Account amount validation

RPC account-block conversion and offline segment verification both reject
negative amounts and values requiring more than 255 bits. The core verifier
returns `REJECT / ReasonInvalidAmount` before hashing or looking up inclusion
evidence. A following block receives `ReasonParentNotAccepted`; a failed parent
cannot advance account-chain linkage.

The bound follows the send-amount rule in the pinned node's
[`accountBlockVerifier.amounts`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/verifier/account_block.go#L209-L217).
Receive amounts are zero in the node. This change checks the common scalar
domain; it does not add complete send/receive validation, token validation,
balance execution, or state-transition proofs. Nil proof amounts retain their
existing numeric-zero interpretation.

## Signed-value ambiguity

Previously, the SPV reduced amounts wider than 32 bytes to their low 32 bytes.
An offline bundle could therefore replace a signed amount `a` with `a + 2^256`
while preserving the claimed hash, signature, and inclusion evidence. Negative
values also have the same magnitude bytes as their positive counterparts, and
the previous negative check existed only in RPC parsing. Both substitutions
were reproduced as `ACCEPT` through the offline bundle/segment path before the
fix, without changing the original signature or commitments.

The low-level hash encoder now matches the node's
[`common.BigIntToBytes`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/common/bytes.go#L33-L39):
left-pad short magnitude bytes to 32 bytes and preserve all longer values.
The node's pinned
[`LeftPadBytes`](https://github.com/ethereum/go-ethereum/blob/v1.10.22/common/bytes.go#L117-L129)
does not truncate. Raw hashing still supports invalid inputs for serialization
parity; callers must use the scalar validator or the full segment verifier
before interpreting an amount as evidence.

RPC parsing bounds significant decimal input before `big.Int` conversion and
then checks the exact bit limit. Empty input still means zero; leading zeroes
and an optional leading plus sign remain supported. Minus-prefixed input,
including `-0`, is refused. Errors do not echo the supplied amount.

## Offline parsing resource guard

The CLI caps each known account `amount` JSON token at 4 KiB before invoking
the arbitrary-precision decoder. Oversized tokens return
`REFUSED / ReasonOversizedSegment` (exit 2) during bundle loading, before state
loading or verification. Each occurrence is checked, including a token later
overwritten by another `amount`, a case or escaped-key alias, or null. The
outer JSON decoder still checks complete syntax and its usual nesting limit.

This fixed parser guard is separate from the 255-bit scalar-validity check;
under-cap invalid magnitudes still decode for node parity and then receive
`REJECT / ReasonInvalidAmount` during segment verification. All seven pinned
node vectors retain their decoded values and classifications. Verification
policies, context fingerprints, and persisted-state schemas are unchanged.
Library callers may set `DecodeLimits.MaxAccountAmountBytes`; zero preserves
legacy unbounded scalar conversion. Direct account-block decoding is unchanged.

`BenchmarkProofAccountAmountDecode` compares full synthetic bundle parsing with
legacy conversion and early bounded refusal at 32 KiB, 256 KiB, and 1 MiB.
The large decimals are invalid proof amounts; legacy decoding alone does not
mean proof acceptance. CI records three iterations per mode on Linux, macOS,
and Windows. Allocation bytes and timing are observations, not peak RSS,
network measurements, or fixed performance gates. The file, row, and token
limits do not constitute a total process-memory bound.

## Independent regression evidence

`internal/testdata/conformance/account-amounts.json` contains seven deterministic
vectors produced directly by the pinned go-zenon module: zero, ordinary and
maximum 255-bit amounts, the first 256-bit value, a 257-bit overflow alias,
a 1025-bit value, and a negative alias. The generator imports no SPV code and
verifies the node module version, checksum, and lack of replacements.

Go tests compare the node hashes against the SPV encoder, verify the synthetic
signatures, exercise local RPC acceptance/refusal, and enforce offline scalar
rejection. A Python standard-library checker reconstructs the magnitude bytes
and complete account-block hash preimages independently. Separate signed-chain
tests cover scalar boundaries and rejection propagation after bundle decoding.

The all-zero test seed is public synthetic material. No wallet, live endpoint,
private key from an operator, or captured user data is involved. These vectors
exercise serialization, not full node acceptance or a live-chain incident.
Checkpoint provenance, canonicality, finality, and state-value authentication
remain separate requirements.
