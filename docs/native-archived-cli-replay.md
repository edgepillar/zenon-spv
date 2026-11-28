# Native CLI replay with five historical testnet targets

On 28 November 2026, the native CLI and its report consumers matched five
preselected signed testnet account-block identities using the retained October
capture. The replay used the normal `observe-block` local-file mode, with
`verify-segment --retained-only` behind it. The exact same proof and saved state
also produced the expected refusal when the archived control changed the fifth
target hash. The original gateway observation and the offline replay each retain
their own source and results. [Original observation](live-signed-batch-observation.md)

## Candidate and input selection

- Runtime source `c64f5453521f4f334bcb6205bbe00d9adfed3980` and tree
  `d55cd7cbe3dae4847e080605ee1f6bd797dac416`. Source-input SHA-256
  `5cc18c33b68755244acb4253f0eb3ea64a97eaad693da456ea8906d650959f23`.
  The three executables came from artifact `15161063070`, attempt 1. The
  replay ran their Darwin amd64 build on an Apple Silicon Mac using Rosetta.
  [Exact-source main CI](https://github.com/edgepillar/zenon-spv/actions/runs/45911169119)
- The original 20,478,824-byte candidate ZIP matched SHA-256
  `05dbfbc71f228f116b7a5272157542f5b63f16e491289e8c65ad3f437c22673b`. Its
  candidate manifest matched the selected clean revision, source inputs,
  architecture and passing test status. Each executable matched its manifest
  size and digest.
- The 111-member historical ZIP matched the digest in the original observation,
  and the selected entries matched its manifest. Its preexecution seal matched
  the preselected identities. The recorded collector output matched the stored
  9,514-byte proof oracle exactly. The five identities had already been chosen
  before the original proof was collected. The same original gateway and
  research workflow supplied that selection. [Original selection](live-signed-batch-observation.md#selection-and-read-only-boundary)
- Testnet chain identifier `73404`, confirming momentum 6026, retained tip
  6144, K=256 and W=6. Every retained header in this replay used v2. The
  expected tip matched the saved frontier. The inputs included the original
  anchor, finite protocol profile, producer schedule, saved state and context
  pin. The historical selection's Bech32 addresses decoded to the exact address
  bytes in the expectations. Both expectation files required
  `CONTENT_INCLUSION` and `SIGNATURE_AUTHENTICITY` under their explicit trust
  allowances.

| Command | Bytes | SHA-256 |
| --- | ---: | --- |
| `zenon-spv` | 10,420,432 | `8bd2547abbdf7e21e2cbf1d4a14fd71cf5e0e026ac3678b9dc27ebafb9976ee0` |
| `observe-block` | 5,843,040 | `1c398294ef40a370593f035cea7f262715c20e07d73aa601ca793cbe3ab2d21f` |
| `consume-query-report` | 3,303,504 | `85cdc1f2233238b8561c4c05299481ae9c735135ba1a50cb40734f23494ebff3` |

## Actual local-file results

The [local-file procedure](block-observer.md#select-inputs-before-checking) pins the
verifier and strict consumer hashes and selects every trust input explicitly.
The outer reader ran from the same source and received the complete observer
stdout and its actual process exit. The checked count is a count of matched
expectations.

| Selected expectations | Verifier | Strict consumer | Observer | Outer reader | Checked targets |
| --- | ---: | ---: | ---: | ---: | ---: |
| All five preselected identities | 0 | 0 | 0 | 0 | 5 |
| Archived wrong hash for target five | 0 | 2 | 2 | 2 | 0 |

The second observer reported `target_mismatch`. The outer reader reported
`process_failure` from the actual nonzero observer exit. The saved state and all
selected input files still matched their original bytes after both executions.
The protected record retains the actual exits and complete outputs.

The replay made zero RPC calls and reused both original archives with zero
network transfers and zero builds. It staged 19,566,976 executable bytes and
1,070,612 input and reader bytes. After opening the verified candidate store, the timed
fixture verification, staging and checks took about 3.48 seconds. Owned scratch
was cleaned up. This single observation measures elapsed time and
materialized file sizes. It leaves peak memory, throughput and target hardware
acceptance open.

## Scope for review

The operational choice is a read-only native CLI observation against a retained
testnet segment. The protected inputs are needed to reproduce this exact sample.
An operator selecting another sample uses their own exact targets, tip and
context, along with the anchor, profile, schedule and documented trust
assumptions. This run establishes compatibility with the selected v2 history on
one local host. Evaluating a v1 sample with this workflow, acquiring fresh peer
data, authenticating the trust inputs independently and accepting the workflow
on target hardware require separate evidence. Independent consumer selection
remains open. Network activation, canonicality, consensus finality and
state-value proofs remain unestablished. [Operator procedure](operator-pilot.md)

The frozen `6ecc2310538d511e3b26bea4c658082853266a11` review candidate keeps
its original review scope. The runtime source in this replay has its own CI
and retained evidence. Scoped distribution still needs independent review,
source and dependency license notices for the selected deliverable and
authenticated distribution of its exact bytes. [Native roadmap](native-roadmap.md)
