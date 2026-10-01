# Delayed inclusion across momentum heights

The [delayed corpus](../internal/testdata/conformance/delayed-inclusion.json)
contains six account blocks and nineteen linked momentums. Expected hashes,
flat-content ordering and RPC encodings come from `zenon-network/go-zenon`
at `3a4131e63881058b6ce2ee81d3a41d0033fafc99`, through the separate pinned
generator module. No SPV implementation is imported by that generator.

These are deterministic synthetic serialization fixtures. They are not
captured network traffic, VM execution, a node-accepted ledger or independent
producer-election evidence. The all-zero Ed25519 seed is public test data.

## Workload

| Item | Fixture selection |
| --- | --- |
| Anchor | Synthetic chain 99, height 5000. |
| Momentums | 5001..5019; v1 through 5008, v2 from 5009. |
| Accounts | One signed user-send chain and one unsigned embedded-receive chain, three linked blocks each. |
| Confirming heights | Each account's blocks 1, 2 and 3 are included at 5003, 5007 and 5011 respectively. |
| Acknowledgements | Each pair references the preceding momentum's exact hash and height. This is separate from its confirming momentum. |
| Retention/depth | Explicit K=16, W=6, an anchor-bound activation profile and a fixture-attested producer schedule. |

At tip 5016, the first two account blocks have enough subsequent headers and
the third returns `REFUSED/ReasonInsufficientFinality`. At 5017 all six pass.
At 5018 the window is 5003..5018, its depth-eligible range is 5003..5012, and
all targets remain available. At 5019 height 5003 is evicted: a complete segment
refuses its first block and propagates `ReasonParentNotAccepted` to children.
A partial segment starting at block 2 can still prove its own inclusion.
The same tip under legacy K=W+1 has discarded every target in this workload.

The core test checks these boundaries through RPC conversion, bundle encoding,
the owned state API, schema-3 save/resume and context pinning. A changed v2 price
cannot advance state; valid flat evidence moved to another confirming height
cannot prove membership there. User signatures and embedded-account omissions
retain their distinct guarantee sets. No accepted result proves execution,
balances or canonicality.

## Compiled workflow and independent checks

`TestCompiledDelayedInclusionWorkflow` builds the actual verifier and collector.
It seeds sixteen headers, queries the shallow target, advances and restarts
watch using two separate processes, collects proof-only evidence across all
three confirming heights, and queries commitments and both segments offline.
Every frontier, target and range response is an unmodified node-derived
envelope. The local server's credentials are public synthetic test strings;
reports must exclude them and temporary paths. Read-only queries preserve the
saved file's bytes, identity, permissions and modification time and make no RPC.

Reproduce the corpus from the repository root:

```sh
(cd tools/gen-node-momentum-vectors && go run -mod=readonly . --delayed-inclusion) > /tmp/delayed-inclusion.json
cmp internal/testdata/conformance/delayed-inclusion.json /tmp/delayed-inclusion.json
python3 tools/gen-node-momentum-vectors/check-delayed-inclusion.py /tmp/delayed-inclusion.json
go test -count=1 -run '^(TestNodeDelayedInclusionAcrossVersionsAndResume|TestCompiledDelayedInclusionWorkflow)$' ./internal/conformance
```

The standard-library Python checker independently reconstructs every hash
preimage, Bech32 projection, account/momentum link, acknowledgement, content
membership, activation boundary and query interval. Go checks signatures.
Linux CI executes this checker alongside the existing corpora and context
vectors. Native Linux/macOS/Windows pilot artifacts include the core and
compiled workflows. This adds independent byte-level compatibility evidence;
authenticated network provenance and a real-consumer pilot remain separate.
