# Anchor configuration

Every `verify-*` command and `watch` selects its starting trust root in this order:

1. An explicit `--genesis-config <path>` overrides the environment completely.
   An unreadable or invalid file fails startup; it never falls back to the
   environment or the embedded mainnet anchor.
2. Without that flag, setting any of `ZENON_SPV_GENESIS_HASH`,
   `ZENON_SPV_CHAIN_ID`, or `ZENON_SPV_GENESIS_HEIGHT` selects an environment
   override. All three must be present and nonempty after trimming surrounding
   whitespace. A variable set to an empty string still selects this mode.
3. Only when no anchor file is selected and all three variables are unset does
   the CLI use the embedded mainnet anchor.

## File format

```json
{
  "chain_id": 3,
  "height": 100,
  "header_hash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
}
```

This example is synthetic and is not a network checkpoint.

`LoadGenesisFromConfig` accepts at most 16 KiB, including whitespace. Both
the initial file-size check and the bounded read enforce the cap; a file that
grows after the size check cannot cause an unbounded read. The input must be
one JSON object with exactly the three fields shown. Field names are case
sensitive. Missing, null, duplicate, unknown, or trailing fields/data fail.
Escaped JSON spellings that decode to the same name count as duplicates.

`chain_id` and `height` must be unsigned 64-bit JSON integers; strings,
fractional numbers, exponents, negative values, and overflow fail. Height must
be positive. Explicit chain ID zero remains supported for custom networks.
`header_hash` must be a 64-character hexadecimal string encoding a nonzero
32-byte hash, optionally preceded by `0x`. Uppercase hexadecimal digits work.
The all-zero hash fails. Configured anchors are not restricted to height one.

## Environment format and migration

The same anchor requirements apply to environment overrides. Chain ID and
height use unsigned decimal integers; signs, prefixes, fractions, exponents,
trailing text, and overflow fail. Hash syntax matches the file format.
Leading and trailing whitespace is trimmed from all three values.

Earlier CLI versions silently chose mainnet if either hash or chain ID was
missing, parsed only the numeric prefix of some values, and defaulted a
missing height to zero. Partial overrides now fail. Configure all three
values explicitly, or unset all three to select the mainnet default. There
is no implicit height for a custom anchor.

Invalid anchor configuration exits with the existing startup-error code 70,
before reading proof evidence, loading or saving retained state, emitting a
verification context, or making watch RPC requests. This is a configuration
failure, not an evidence REJECT verdict. Invalid field values and unknown
field names are not echoed by the parser; ordinary file-access errors can
still include local paths.

## Trust boundary

These checks establish a bounded, unambiguous configuration, not the origin
or correctness of the selected anchor. Independently establish the network,
anchor height/hash, and provenance before using the result. A matching chain
ID or a hash supplied by an untrusted RPC peer is not network authentication.
`GenesisTrustRoot.Validate` checks only the nonzero hash and positive height;
it cannot determine whether struct fields were explicit in some prior input.
Generic JSON decoding of other schemas retains its existing behavior.
See the [verification contract](verification-contract.md) for the meaning of
ACCEPT and the remaining trust assumptions.
