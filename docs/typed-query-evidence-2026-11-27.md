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

## Closed-fixture snapshot transport and header comparison

For run `45905746425`, the pinned reference-gas node reconstructed two
closed LevelDB ledgers from the recorded headers, one ending at H3 and one at
H4. The read-only producer oracle checked each frontier after the corresponding
manager stopped. The exporter read the selected effective raw ledger of each
copy. The two exports retain distinct height, full hash and payload digests.

| Closed fixture frontier | Put records | Put bytes | Chunks at 1 KiB | Balance/storage leaves |
| --- | ---: | ---: | ---: | ---: |
| Recorded H3 | 99 | 14,896 | 15 | 32 |
| Recorded H4 | 101 | 15,213 | 15 | 32 |

The completion, inventory and transport checks read the retained streams
through EOF. A separate check recomputed every chunk SHA-256 from the original
put bytes. Both framed reads produced the same balance/storage mapping digest
`71898584c1d9d4175e3ebd6c85c9d9dafbeb3f1c6afe3ee2b14f35536c90c90e`
and the recorded StateRoot. Each framed result reported `MATH_ONLY`.

The compiled verifier first selected H3 with the configured H2 anchor, explicit
H3–H4 schedule and `W=1`. It matched the H3 report to the selected header and
its StateRoot. The same comparison refused the H4 report with exit 1 and
`projection/frontier_mismatch` even though the roots matched. Selecting H4
itself returned exit 2 and `selection/insufficient_depth`. The verifier used
`c64f5453521f4f334bcb6205bbe00d9adfed3980`. The exporter and framed
projection used `265531259b4734b384cbc2b063cffb6b47307225`. The macOS
executables came from retained CI archives. [Verifier archive](https://github.com/edgepillar/zenon-spv/actions/runs/45911169119/artifacts/15161063070) · [Exporter archive](https://github.com/edgepillar/zenon-spv/actions/runs/45938634780/artifacts/15171727047)

The native replays reused 21 read-only module directories after checking their
expanded contents and cached ZIPs against the recorded Go module digests.
That avoided staging 92,977,144 bytes of module inputs per replay. The
completed node commands reported 406,769,897 and 404,452,373 bytes as their
largest sampled build-workspace sizes. The framed reads and verifier checks
took 3.40 seconds on macOS arm64 with the retained amd64 executables running
through Rosetta. The controller reused the completed H3 export after an
orchestration error and retained interrupted runs with their failure status.

The original fixture outcome remains `UNKNOWN`. This completes a bounded
transport and header-root comparison for reconstructed fixtures.
Representative capture, excluded-state provenance, import and restart, and
successful live typed consumption remain open.

## Restore the closed H3 ledger and rebuild derived stores

A new probe used the same archived opening and reference-gas node
`2835c436b197fece5c76adf4ba8dc1decca2e3ea`. After the seed process closed its
managers, it selected the five regular files of the H3 LevelDB ledger. The
restore copied those files into a fresh private directory and checked their
sizes and SHA-256 values before opening it. The source and copy had distinct
file identities. The selected file manifest has SHA-256
`8461056ed1c5177e50874f4d45f9571f4d94fb0e88005b64f7fe5f871f5db47b`.

| Fresh process | Frontier before and after | Observed result |
| --- | --- | --- |
| Import and advance | H3 to H4 | `Chain.Init` rebuilt the cache and StateTree from the three stored patches. The original verifier applied the recorded H4 successor. |
| Reopen and roll back | H4 to H3 | The ledger and cache reopened at H4. A rollback request with the wrong hash at height 3 was refused. The exact H3 rollback then updated the ledger, cache and StateTree. |
| Reopen after rollback | H3 to H3 | The reopened node was ready for state-root reads. The old H4 state version was unavailable. |

At each stage the H3 StateRoot and all three absence proofs matched the
prior recorded replay. The procedures used `Chain.Init` and `Chain.Stop`
for lifecycle control and checked the recorded signatures. No network
runtime or new signing was needed.

A separate fresh database reconstructed the 99 records of the 14,896-byte
effective-frontier stream. The read-only node manager recovered the exact H3
identifier from that database and found no patch at heights 1, 2 or 3.
The fuller ledger transfer supplied the history that the observed
`Chain.Init` used for reconstruction. The balance/storage StateRoot
comparison and the provenance of the complete closed ledger are separate
checks.

The complete ledger transfer used 34,582 logical bytes. Rebuilding the
derived stores omitted 3,739 cache bytes and 16,425 StateTree bytes from the
input transfer. The one copy took 2.4 ms and the qualification took 34.20
seconds, including one Go build. All archived inputs were reused. These are
single-host fixture measurements. The original runner outcome remains
`UNKNOWN`. A representative capture, longer recovery and retention,
excluded-state provenance and production import acceptance remain open.

## Cross the v3 activation boundary and reopen a replacement branch

The same reference-gas node revision, at tree
`f89d645c7f5be85dfe10dc7a510d80df7965d22f`, replayed two archived chain-69
branches on an isolated ledger. The five steps each used a fresh node process
and verified the full height/hash frontier of the ledger and cache after
`Chain.Init`. All five processes closed their managers successfully.
[Starting branch archive](https://github.com/edgepillar/zenon-spv/actions/runs/45905746425/artifacts/15158177983) ·
[Replacement branch archive](https://github.com/edgepillar/zenon-spv/actions/runs/44961621978/artifacts/14730556980)

| Process | Transition | Observed control |
| --- | --- | --- |
| Seed | Common genesis → starting v3 H4 | The recorded successors applied through the original verifier. The replay harness checked the full ledger identifier before reading the H3 proofs. |
| Roll back | Starting H4 → starting v1 H2 | The other branch's H2 hash was refused and the frontier stayed at H4. The exact H2 then rolled back successfully. The discarded H3 and H4 state versions became unavailable. |
| Reopen legacy and rewind | Starting H2 → common genesis | H2 reopened with its v1 header and zero StateRoot field. The stored H2 state enabled v3 for its next block. At the rewound genesis the spork was inactive. |
| Replace branch | Common genesis → replacement v3 H3 | The recorded replacement H2 and H3 applied. The ledger identity check rejected the old H3. The node refused the unavailable H4 state version. |
| Reopen replacement | Replacement H3 → replacement H3 | The exact replacement frontier, guard outcomes and proof bytes persisted across another process restart. |

The starting H3 hash is
`78e7fd4a5bfe0db1efd311646051e9cc971c79ecf99963b8e033a82daeac3354`.
The replacement H3 hash is
`a4ac633fd459766c579326f2a1728ca5d64c9da8e10b1755d80504cd3c31053f`.
Both headers carry the same StateRoot,
`36fd7a907707f00939bb4741da5d8f3dd4fdf4200581ebe869b934a8f1981287`.
Nine independent sparse-proof checks confirmed that the three absence proofs
were byte-identical at the starting, replacement and reopened H3. The proofs
were 259 bytes for `BatchEntry`, 323 for `DomainRecord` and 291 for
`DomainConfig`.

The first probe stopped when the internal StateTree returned a root and proof
for a different hash at a retained height. Its lookup is height-indexed.
The successful replay kept that first outcome and checked the full ledger
identifier before each root or proof read in the harness. The live-node
recovery path still needs its own qualification.

The compiled macOS verifier then ran six controls against the same recorded
branches at `W=1`. It used each branch's H2 anchor and producer slots
reconstructed by the pinned node oracle. The context fingerprints were
computed independently. The binary came from CI checkout
`fbd550b75edd7b2733f9edaacb01cef0895f447e` for feature
`3a5e1c9dad20d48499573015f32451618e11f7bb`.
[Verifier archive](https://github.com/edgepillar/zenon-spv/actions/runs/46142293662/artifacts/15262893512)

| CLI control | Exit | Result |
| --- | ---: | --- |
| Export starting checkpoint with H3–H4 | 0 | Version 4 checkpoint and exact H3 header selection |
| Reopen the pinned checkpoint in its own context | 0 | Same H3 header and StateRoot |
| Reopen that checkpoint in the replacement context | 70 | `state_input/invalid_checkpoint` |
| Select the replacement H3 hash from the starting checkpoint | 1 | `selection/header_hash_mismatch` |
| Select replacement H3 from its recorded header alone | 2 | The header checks passed, then selection returned `selection/insufficient_depth` |
| Supply replacement H3 under the starting anchor and schedule | 1 | `headers/not_accepted` with `ReasonUnauthorizedProducer` |

The node harness SHA-256 is
`898d10c92a98556f3c109e3dc84850fe9eda18145810a4dcd292918642a0a352`.
The exported checkpoint SHA-256 is
`d6856d1a309c257f3b65b477aff6c9dcb29b36fc4972bdc98db48c06fcb59b44`.
The node build checked 25 modules and reused 21 validated module expansions
and their ZIPs, avoiding 92,977,144 bytes of input staging. The build took
35.34 seconds and the five node processes took 3.07 seconds in total. The
largest sampled build workspace was 474,226,546 logical bytes. The closed
ledger, cache and StateTree contained 44,888 logical bytes. Streaming the
retained verifier and running the six controls took 2.22 seconds. The original
archives were reused throughout.

This evidence covers reconstructed fixtures and a configured CLI context.
Both original runner outcomes remain `UNKNOWN`. A depth-one successor for
the replacement branch, a present typed `BatchEntry` consumed end to end, and
production recovery and fork-choice acceptance remain open.

## Replay with experimentally hash-bound node storage

The two full input files of the [existing recovery patch](../tools/gen-state-root-vectors/node-recovery-9c71-patch.json)
matched the chain-69 node revision `2835c436b197fece5c76adf4ba8dc1decca2e3ea`
byte for byte. Both replacements were checked against their before and after
file lengths, Git blobs and SHA-256 values. The derived node tree before
adding the replay harness is `79140277a54a167be84d79366eb51b0f0fc7a95a`.

The patched build repeated the same five processes on a separate fresh ledger.
All five succeeded and reproduced the full frontier identities, root values,
removed-height refusals and three proof byte strings of the original replay.
Five additional cases also called the node's state-tree methods directly.

| Stage | Input refused by both native read methods |
| --- | --- |
| Starting H4 | Replacement H3 identifier |
| Before rewinding to v1 H2 | Replacement H2 identifier |
| After applying replacement H3 | Starting H3 identifier |
| After reopening replacement H3 | Starting H3 identifier |
| After reopening replacement H3 | Height 3 with the hash omitted |

In each case `StateRoot` and `GetProof` returned
`ErrVersionIdentityMismatch` without producing a usable root, value or proof.
The replay continued to check the full identity of valid reads against the
ledger. The five phases and nine independent proof checks matched the
original replay results.

The patched harness SHA-256 is
`f91629e76077cc0bdf8ac8c717c406bc888225ef101d78c98b6f294a7f3a013e`.
The same 25 module pins and both original archives were reused. The build took
37.31 seconds and the five process runs took 3.25 seconds in total. The
largest sampled build workspace was 441,970,081 logical bytes. The closed
ledger, cache and StateTree contained 34,705 logical bytes.

This comparison qualifies the two-file patch for the selected offline replay
on fresh research data. The patch changes the StateTree disk format. Existing
database migration, live reorg, broader retention and recovery qualification,
and production state-proof acceptance remain open.
