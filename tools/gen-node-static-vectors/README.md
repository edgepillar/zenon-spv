# Actual node static momentum observations

This separate reference module executes the official node's exported
[`verifier.MomentumStatic`](https://github.com/zenon-network/go-zenon/blob/c64ed6279ff1d07335dab0ac36156dec8b5b71e9/verifier/momentum.go)
at commit `c64ed6279ff1d07335dab0ac36156dec8b5b71e9`. It verifies the selected
module version and checksum in its build information and refuses replacements.
The local source qualification compared all 375 Go/module files with the exact
Git tree. Header/content encoding, hash construction, and signature verification
are unchanged from the historical `3a4131e63881058b6ce2ee81d3a41d0033fafc99` pin.
Historical generators, corpora, and the frozen review candidate retain their
existing pins.

The [recorded corpus](../../internal/testdata/conformance/node-static-v1-v2.json)
has SHA-256 `1873c677ea64936cea90262dbe70a5a76e497a8c6d7736394dd4eaee7da766c3`.
It retains every selected result: 21 existing signed synthetic momentums, one
nil input, one unsigned historical genesis, and 16 mutations each of a v1
momentum and a v2 momentum with nonzero prices. The actual node function returns
22 matches and 33 rejections across these 55 calls. The driver creates no private
keys or signatures and starts no chain or network service.

The node checks the claimed hash before the signature and public-key presence.
Malformed nonempty key widths produce an internal signature-format error.
Recorded results preserve this precedence, including multiple simultaneous
faults. Every non-nil observation includes the complete projected header and
computed hash.

## Reproduction

Run the reference module with its two exact, SHA-selected historical inputs:

```sh
cd tools/gen-node-static-vectors
go run -mod=readonly . ../../internal/testdata/conformance/momentum-v1-v2.json ../../internal/testdata/conformance/historical-testnet-genesis.json
```

The recorded node execution used Go 1.25.14 with the local macOS ARM64 CGO
toolchain. Its build and source evidence are separate from native CI. CI performs
offline checks of the recorded corpus rather than rebuilding or starting a node.

From the repository root, select an OpenSSL 3 executable explicitly:

```sh
python -I -B tools/gen-node-static-vectors/check_test.py -v
python -I -B tools/gen-node-static-vectors/check.py --openssl openssl --source-revision COMMIT
go test ./internal/conformance -run TestNodeStatic -count=1
```

Replace `COMMIT` with the exact 40-character source revision. This value is a
caller assertion, not authenticated source provenance. On macOS, use the
OpenSSL 3 executable rather than the system LibreSSL binary.

The Python checker first verifies both historical input pins, all 55 selected
wire records, exact types, and source/scope metadata. It independently
reconstructs all 54 non-nil byte projections before selecting the signature
backend. It then runs 26 OpenSSL Ed25519 checks over independently recomputed
messages: 22 positive and four negative results. Eighteen control tests cover
input/source substitution, reordered or missing cases, numeric and boolean
aliases, coherent wire forgeries, byte corruption, preflight refusal, and
retained process outcomes on a backend deadline.

The existing backend uses an empty OpenSSL configuration and the default
provider. Reports retain the selected executable hash and actual process
outcomes. Loaded libraries and the executable's publisher remain unauthenticated.
Each native signature artifact contains the original `node-signatures.json`
and the separate `node-static-signatures.json`; the original report contract is
unchanged.

## Runtime and trust boundaries

The 55 matching runtime selections yield 19 `ACCEPT`, 34 `REJECT`, and two
`REFUSED` outcomes. Tests keep their original synthetic anchor/profile inputs;
mutations cannot supply replacement trust. Three node-static matches fail the
runtime's resource-price rules. Nil input remains refused, and a v2 chain
mutation remains refused by its explicit profile. Unsigned historical genesis
is tested as an attempted extension of its selected anchor. The runtime keeps
its existing public-key-first presence rule when both fields are empty.
Rejected/refused selections preserve the caller and returned trusted state.

A static match checks only hash/signature behavior. It supplies no activation
profile or authorized producer: additional runtime controls refuse otherwise
valid v1/v2 inputs without the required producer information and refuse v2
without its profile. These tests do not establish full-node validation,
network activation, election, canonicality, consensus finality, freshness, or
state-value acceptance. Human review, authenticated distribution, and network
pilot trust inputs remain separate acceptance gates.
