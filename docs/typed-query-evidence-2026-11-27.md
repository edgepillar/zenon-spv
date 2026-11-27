# Chain-69 opening evidence on 27 November 2026

The selected query uses domain 1 and batch 0 on chain 69. Both runs below
selected the reference-gas renewal contract with SHA-256
`7af671795d7a9a97d57432ce1b38d490580340e7b844a083298dbcaf8a5c4fe0`.
The retained opening proof tests the selected BatchEntry key at H3, before
fixture configuration. See the [readiness ledger](typed-query-readiness.md)
for earlier executions and the remaining acceptance gates.

## Opening and terminal outcomes

| Run and exact runner revision | Opening versions | Actual terminal record |
| --- | --- | --- |
| [44961621978](https://github.com/edgepillar/zenon-spv/actions/runs/44961621978), `740518e172614f5a01da18917599c4bedc924566` | H1 v1, H2 v1, H3 v3 | `UNKNOWN` during fixture deposit. Timeout, exit 143, incomplete output. |
| [45905746425](https://github.com/edgepillar/zenon-spv/actions/runs/45905746425), `f058474d5f35cfa08cdccbf153d6fb9fbf9ab649` | H1 v1, H2 v1, H3 v3 | `UNKNOWN` during fixture configuration. Timeout, exit 143, incomplete output. |

Both archives record closure of the owned runtime. GitHub reports failure for
each workflow. The original archives and their SHA-256 digests follow.

| Archive | SHA-256 |
| --- | --- |
| [14730556980](https://github.com/edgepillar/zenon-spv/actions/runs/44961621978/artifacts/14730556980) | `737f2603f1136541c635e5552df4d6352a53d58e69088229a08bcb4275920a4c` |
| [15158177983](https://github.com/edgepillar/zenon-spv/actions/runs/45905746425/artifacts/15158177983) | `78495041b77c89845f20c5f4b1939e5bd95ae0e1303216e3f72ae4b3230276a3` |

The offline replay checked the indexed opening requests and responses. It
recomputed all six header hashes from their wire fields using 160-byte v1
preimages and 208-byte v3 preimages. OpenSSL 3.6.5 verified both original H2
and H3 signatures in each capture. The public keys derived the recorded
producer addresses. Four negative controls rejected H3 signatures over
messages with the StateRoot omitted or changed.

The captures share the selected H1 hash
`fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`.
The linked H2 and H3 identities differ between runs.

| Run | H2 hash | H3 hash |
| --- | --- | --- |
| 44961621978 | `62674faa490bea69fc92f562abcf1bb9a91da05af7b6a7117384f18c43e7be45` | `a4ac633fd459766c579326f2a1728ca5d64c9da8e10b1755d80504cd3c31053f` |
| 45905746425 | `bc5fe74547ed874e14d8a98580e6f52aaa8f64e2e7480d1b9eb14bc30c473876` | `78e7fd4a5bfe0db1efd311646051e9cc971c79ecf99963b8e033a82daeac3354` |

Both H3 roots are
`36fd7a907707f00939bb4741da5d8f3dd4fdf4200581ebe869b934a8f1981287`.
Both responses carry the same 259-byte absence proof with five siblings.
Its SHA-256 is
`5dc5adc0b21bee3b5fa405fe4c2c07e431a6bff36ce73a688f16f67e6796e37e`.
The replay derived the key from the selected Settlement address, domain and
batch. It checked the zero leaf and folded the five siblings along the local
path to each H3 root. Changing the last proof byte changed the folded root.
The replay read the retained archives in place.

## Original-node replay of the recorded openings

The selected reference-gas node
[`2835c436b197fece5c76adf4ba8dc1decca2e3ea`](https://github.com/digitalSloth/go-zenon/tree/2835c436b197fece5c76adf4ba8dc1decca2e3ea)
replayed both original signed openings in separate test ledgers built from the
pinned genesis. Both H2/H3 pairs have empty account-block content and empty
patches. The original `ApplyMomentum` path checked the signatures, producer
slots, patch hash and version selected by the parent. At H3 it also checked
the signed StateRoot against the root computed by the node. The state-root
rule was inactive at H1 and active at H2 in both replays.

The test derived the Settlement key from domain 1 and batch 0. The node
regenerated the original H3 root and all 259 proof bytes in each ledger. The
returned value was absent in both cases. The existing
[closed-ledger oracle](../tools/gen-state-root-vectors/closed-devnet-parent-oracle.go.txt)
then reopened each reconstructed ledger read-only and checked both producer
slots. Each lookup used the corresponding H1 or H2 parent. All four election
lookups used H1 as their proof block.

| Run | H2 and H3 timestamps (Unix seconds) | Tick | Producer at both slots |
| --- | --- | --- | --- |
| `44961621978` | `1795303590`, `1795303680` | `184601` | `z1qzedcjmds6cwuqu7wkrvl0dadwwauzaana6g8e` |
| `45905746425` | `1795732640`, `1795732730` | `186031` | `z1qq9n7fpaqd8lpcljandzmx4xtku9w4ftwyg0mq` |

Each oracle also refused the other run's H2 target and H3 frontier. The five
raw-ledger files in each test copy matched their pre-read SHA-256 inventory.
The test used Go 1.25.14 on macOS arm64 with CGO and the `devnet` build tag.
It verified 484 original node files against Git tree
`f89d645c7f5be85dfe10dc7a510d80df7965d22f` and checked the ZIP and expanded
file checksums for 25 Go modules. The source archive SHA-256 is
`76d974ab3588518dddf9ea5eb4032b43228f9a732d14006330477037a905884a`.

The completed tagged run reused the original archives and local module
inputs. Its worker took 20.70 seconds and recorded 292,573,185 logical bytes
in the temporary workspace before cleanup. This sample measures workspace
size after the command. The retained record includes the exact test inputs,
native output and separate controller status for an earlier untagged run.

This check uses reconstructed test ledgers and the original recorded signed
bytes. The original fixture outcomes remain `UNKNOWN`. The first accepted
typed consumer still requires the selected run's closed-ledger schedule and
three present proofs under one accepted header root.

## Retained H4 and the native CLI at depth one

The second archive also retains the completed `ledger.getFrontierMomentum`
response for request 30. Its signed v3 H4 has hash
`168e78a461a62a8dd3298fed62118a6c56aba25dc27c2bc89084cda3fc7bf0b2`
and directly links to that run's H3. The 703-byte response has SHA-256
`01ef2c931f8cf3da3913003aa3941ddbbc5db02075389ad89b8c170dcad80446`.

The original-node test replayed the three signed successors of genesis and
closed the reconstructed ledger at H4. The read-only oracle checked all three
producer slots, including H4 at Unix time `1795732740`, and left the five
raw-ledger files byte-identical. A read of H3 after H4 reproduced the archived
BatchEntry absence and yielded two more absence witnesses. All three were
checked independently against the same H3 root and their locally derived keys.

| H3 witness | Proof bytes | SHA-256 |
| --- | ---: | --- |
| BatchEntry, recorded RPC | 259 | `5dc5adc0b21bee3b5fa405fe4c2c07e431a6bff36ce73a688f16f67e6796e37e` |
| Domain record, reconstructed ledger | 323 | `941ace369adada3cd6356d98e768d82180b997b8898fedbc7027c2e784a396b5` |
| Domain config, reconstructed ledger | 291 | `7703b4eff18d1ec51d3e4f913b459924dbb0a87959652951eb903cb129de30f4` |

The compiled `c64f545` CLI used the recorded H2 anchor, explicit v3 coverage
at H3–H4, the reconstructed producer slots, and required depth `W=1`. Its
header and query context pins matched independent byte calculations. It
accepted both headers under those configured inputs. The three canonical
proofs passed verification against H3's owned root, and the command returned
exit 2, `query/required_row_absent`, with a null typed result.

| Control | Native result |
| --- | --- |
| H3 as tip | Exit 2, `query/outside_owned_scope` |
| H2 anchor from the other run | Exit 1, `ReasonBrokenLinkage` |
| Changed configured H4 slot time | Exit 1, `ReasonUnauthorizedProducer` |
| Changed domain-config sibling | Exit 1, `query/invalid_witness` |
| Substituted provider root | Exit 1, `query/invalid_witness` |

The node replay took 17.78 seconds and the single CLI build with seven
invocations took 8.22 seconds. Both used retained archive and module inputs,
and their temporary workspaces were removed after recording the evidence.
This is a configured-header and proof-refusal replay for the archived inputs.
The original fixture outcome remains `UNKNOWN`. The selected live target
still requires three present proofs and completed typed consumption.

## Restoring the H3 and H4 checkpoints

A local Go 1.25.14 test on Darwin arm64 reused the same recorded headers,
schedule and witnesses with SPV source `c64f545`. The test wrote the version-4
checkpoint through the existing Go encoder and passed the saved file and its
SHA-256 pin to the existing CLI handler. It restored H3, appended the original
H4, and obtained the same H3 root and identical final checkpoint bytes as the
continuous replay. The byte check independently matched both retained
checkpoints to the original headers and selected context. The six CLI calls
left the files' identities and bytes intact.

| Query form | Provider headers | Provider JSON bytes | Local checkpoint bytes |
| --- | ---: | ---: | ---: |
| Anchor replay | 2 | 2,892 | 0 |
| H3 checkpoint with H4 | 1 | 2,224 | 1,642 |
| H4 checkpoint with proofs only | 0 | 1,557 | 2,514 |

All three forms returned exit 2 and `query/required_row_absent` at the same
H3 root. Reusing H3 without a successor returned exit 2 and
`query/outside_owned_scope`. Supplying the H3 digest for the H4 checkpoint
returned exit 1 and `state_input/digest_mismatch`. The export command returned
exit 2 for the absence and emitted zero checkpoint bytes.

The H3 and H4 checkpoint SHA-256 values are
`02c047d01123595d966f41b95edeee743a59bd42a93a889a0dd4a7c58670a270` and
`d6856d1a309c257f3b65b477aff6c9dcb29b36fc4972bdc98db48c06fcb59b44`.
For this two-header sample, proof-only reuse saves 1,335 provider bytes and
reads 2,514 local bytes. The byte counts cover the provider document and
checkpoint. The configuration and request are common to the three forms.
This sample measures document size. The test used one build and existing
module inputs, took 9.63 seconds, and observed 156,457,595 bytes of temporary
workspace data after execution and before cleanup.

## Remaining acceptance evidence

The captures provide two observed opening transitions and independently
rechecked candidate-root absence proofs. The next execution must derive its
own anchor from its opening response. D2 still requires finite producer
authorization from the selected closed-ledger range. D3 and the native host
exit require three present canonical proofs under the same header-derived
StateRoot, a completed typed BatchEntry result and all 17 stored gateway
fields matching.

The next prepared main runner is
`c64f5453521f4f334bcb6205bbe00d9adfed3980`. Its exact-source qualification
covered 44 original archives and 21 binaries. It gives the reference-gas
configuration command 660 seconds and retains selected progress on timeout.
A fresh dispatch requires its own approval. [General CI](https://github.com/edgepillar/zenon-spv/actions/runs/45911169119),
[preparation CI](https://github.com/edgepillar/zenon-spv/actions/runs/45911169178).

The consumer and parent-oracle archives use source
`58e03fa9ff58a752cfd1718245b31cba73dde473`. The 27 November metadata check
reported both archives unexpired. The earlier listed expiry is 11 December 2026
at 15:36 UTC, so the next dispatch must repeat the availability check.
[Consumer artifact](https://github.com/edgepillar/zenon-spv/actions/runs/44764773500/artifacts/14645836816),
[parent-oracle artifact](https://github.com/edgepillar/zenon-spv/actions/runs/44764773665/artifacts/14644100853).
