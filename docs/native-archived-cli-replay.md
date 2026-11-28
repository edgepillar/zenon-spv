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

## Private installation rehearsal

The private manifest SHA-256 is
`688f13c358498f889133ea2ba5ab642b21aa10501ce2b929c85b3e4ac547d261`.
It selects three commands per platform and the source-pinned Python outer
reader. All nine binaries matched the original CI payload sizes, SHA-256
digests, native image formats and embedded clean VCS revision
`c64f5453521f4f334bcb6205bbe00d9adfed3980`. Their embedded Go version was
`go1.25.14`. [Original candidate CI](https://github.com/edgepillar/zenon-spv/actions/runs/45911169119/attempts/1)

| Candidate platform | Exact artifact ID | Local installation evidence |
| --- | ---: | --- |
| Linux amd64 | 15160289032 | Staged ELF64 executables and verified build information and notice files. |
| macOS amd64 | 15161063070 | Staged Mach-O executables and ran the installed read-only workflow on Apple Silicon using Rosetta. |
| Windows amd64 | 15161241296 | Staged PE32+ executables and verified build information and notice files. |

The inspection checked the selected commands' package closure against the
pinned source, toolchain and local checksum-verified Go modules. The
installation manifest binds 16 license and notice paths to four distinct
protected payloads. The reviewed inputs include the project license, the
Go distribution and its used vendored packages, and the pinned
`golang.org/x/crypto` and `golang.org/x/sys` modules. Retaining notice
bytes and build information leaves the independent distribution review open.

Install a version in its own private directory. Verify the selected
platform, executables, outer reader and notices from one manifest before
using the explicit command paths. Store the saved state, expectations and
trust settings outside that directory. To roll back after selecting an
independently accepted version, reverify its directory and select its
explicit paths with its paired anchor, profile, schedule and context.
Preserve the saved inputs and evidence outside both versions.
[Operator procedure](operator-pilot.md)

The macOS rehearsal refused an inconsistent executable digest during
installation preflight. The verified manifest still matched the installed files.
The installed observer and outer reader matched all five preselected
targets and refused the archived wrong target. The timed inspection and
rehearsal phase took 6.54 seconds and materialized at most 19,832,673
install-file bytes for one platform at a time. It reused the original
archives with zero downloads, builds or RPC calls. Target-host install
execution on Linux and Windows and independent consumer acceptance remain
open.

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
and retained evidence. Independent review of the selected installation and
authenticated distribution of its exact bytes remain release exits.
[Native roadmap](native-roadmap.md)
