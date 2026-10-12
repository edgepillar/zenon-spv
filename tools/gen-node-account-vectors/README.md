# Actual node account transaction observations

This isolated research module calls the exported
`verifier.NewAccountBlockVerifier(recordingChain, nil).AccountBlockTransaction`
at official node commit
[`c64ed6279ff1d07335dab0ac36156dec8b5b71e9`](https://github.com/zenon-network/go-zenon/blob/c64ed6279ff1d07335dab0ac36156dec8b5b71e9/verifier/account_block.go).
The module version and checksum are checked in the executable's build information;
replacements refuse. The GPL node dependency stays outside the MIT runtime module.
No SPV implementation is imported by this generator.

The two selected historical corpora remain byte-for-byte unchanged:

| Input | SHA-256 |
| --- | --- |
| `account-segments.json` | `1faca6715c3865bae726a7a07f56ef2c43bd8a5a5c9816f618373312de43b048` |
| `account-amounts.json` | `55e6d89f2ad3a25f7f7a6232fe99a5a572e2937d844fc9a3828d9e4cdad4a6aa` |
| Recorded `node-account-transactions.json` | `8f3858bf3cb0d77ded8ae4d12b500a3d21c54492f1f5f4dc5014da531f23df32` |

All 58 selections are retained: 11 original blocks, 29 user-send mutations,
one user-receive nil amount, 12 coherently rehashed unsigned embedded receives,
three embedded key/signature presence changes, and two programmatic nil inputs.
The existing keys and signatures are reused. Rehashing unsigned embedded claims
creates no signature. The generator performs no key creation, signing, chain
startup, database access or network request.

The recording chain returns opaque non-nil account/momentum interfaces. It
records each lookup and its exact arguments; other methods have no implementation
and fail generation if unexpectedly reached. These stubs authenticate nothing.
The selected seven amount vectors already contain a descendant on a user send.
Their original bytes and descendant hash are preserved: after successful hash,
signature and producer checks, the transaction method rejects those descendants.
The node's `Previous()` derives the lookup identifier from the first descendant,
including its zero-height unsigned wrap. This is recorded synthetic behavior,
not a claim about a reachable live-chain state.

| Recorded method result | Count | Meaning |
| --- | ---: | --- |
| `MATCH` | 20 | This exported method returned nil under the recording stubs. |
| `REJECT` | 36 | A selected context-shape, hash, signature or descendant error occurred. |
| `PANIC` | 2 | Direct nil transaction/block calls dereferenced nil before any lookup. |

Only the two selected programmatic nil cases may record the specific runtime
nil-pointer panic. Every other panic or unselected error fails generation. This
does not establish remotely reachable nil input or a full-node vulnerability.

`AccountBlock` and `AccountBlockTransaction` are separate node entry points.
The latter checks context shape, hash, signature, producer binding and descendants.
Its success is not full protocol validation: coherently rehashed unsigned
embedded version/type/chain/receive-field changes can still match this method.
`AccountBlock` is not executed in this experiment, including recursively: the
user-send descendants are rejected before recursion. Missing-state fallback,
consensus, PoW, account execution and a real store are not exercised.

Programmatic nil amounts are explicitly flagged. The node JSON display emits
`"<nil>"`, while the SPV projection contains null and the hash uses zero bytes.
This is not a valid nil RPC round trip. The established SPV scalar API also
treats programmatic nil as zero; the committed user receive retains that behavior.
Signed negative amount aliases match the transaction hash/signature but remain
rejected by the SPV scalar bound.

The independent Python checker reconstructs the exact finite mutation inventory,
complete projections, descendant/data hashes, Bech32 mutations, context calls,
nil flags and 56 preimages using SHA3-256. Source, input, inventory and byte checks
finish before the OpenSSL backend is constructed. Sixteen fresh OpenSSL checks
verify 14 existing signatures and reject two corrupted signatures. A descendant
rejection does not change its independently verified signature to a failure.
Malformed-width and missing-field diagnostics remain separate method observations.
Failure reports retain completed process outcomes.

Runtime tests reuse only the original selected anchor, nine signed momentums and
four commitments. Across all 58 rows, the SPV produces eight bounded inclusion
acceptances, 35 rejections and 15 refusals. In particular, a standalone embedded
send is rejected by the node transaction method but can have committed inclusion;
a coherently changed embedded claim lacks its original commitment and refuses;
unsupported layouts/types refuse. Method matches do not supply missing retained
momentums, activation profiles, producer authority, canonicality, consensus
finality, account execution or state-value proofs. Runtime validation is unchanged.

From this module directory, with the selected dependency available:

```sh
GOWORK=off go build -mod=readonly -trimpath -o node-account-reference .
./node-account-reference ../../internal/testdata/conformance/account-segments.json \
  ../../internal/testdata/conformance/account-amounts.json > observations.json
```

The offline consumer commands, from the repository root, are:

```sh
python -I -B tools/gen-node-account-vectors/check_test.py -v
python -I -B tools/gen-node-account-vectors/check.py --openssl openssl
go test -v -count=1 -run '^TestNodeAccountTransaction' ./internal/conformance
```

Use an OpenSSL 3 executable on macOS. Native Linux, macOS Intel and Windows CI
consume the recorded corpus and export `node-account-signatures.json` alongside
the preserved signature reports. CI does not rerun the reference node, generate
signatures, authenticate network context or enable state-value verification.
