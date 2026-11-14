# Typed-query source and execution evidence: 15 November 2026

This supplements the [dated acceptance ledger](typed-query-readiness.md) and
[D0-D6 plan](typed-state-roadmap.md). It records already qualified sources and
one retained non-accepting execution. It introduces no new runtime build,
selected-network acceptance, independent review or release. Historical records
retain their original revisions and outcomes.

## Source roles

| Role | Exact identity | Scope |
| --- | --- | --- |
| Qualified runner/diagnostic main | `7cb3fdda54a7febd11ed6c8e2901d3a5d066cd53`, tree `c3922b4babbc312cbb99bce50a89ca61eb143f02` | Local `edgepillar` author/committer merge of [PR #396](https://github.com/edgepillar/zenon-spv/pull/396), followed by its own main CI and artifact checks. |
| Reviewed PR source and test checkout | Feature `bc84ff8c086e647da8219be2d8939c9204e7532b`; test merge `846216b61245ba069e2003a9cba5c65e2019aaf7` | Separate PR qualification. The reviewed tree matches the local main merge; each revision keeps its own evidence. |
| Latest executed owned diagnostic in this record | Main `4f0b9f738041c368477c365e1b65fb01f71a2c1c`; run `43640873250`, attempt 1 | Readiness refused at H1. Its single-dispatch authorization is consumed. |
| Selected consumer/oracle binaries | `7493c5929c7dbcfb29f94be521f7533d90a1a687` | Existing independently pinned input artifacts from the [reference-gas contract](reference-gas-owned-contract.md); not binaries relabeled as the later runner. |
| Frozen human-review candidate | `6ecc2310538d511e3b26bea4c658082853266a11` | Its original scope remains fixed. New source qualification does not transfer independent human acceptance. |

The selected contract remains v2, SHA-256
`6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31`.
Its [source cohort](reference-gas-source-cohort.md), chain-69 genesis,
Settlement/domain 1/batch 0, profile and finite-authorization requirements
remain explicit. No alternate query is selected after an unavailable result.

## Completed source qualification

- [PR general CI](https://github.com/edgepillar/zenon-spv/actions/runs/43646371575)
  and [main general CI](https://github.com/edgepillar/zenon-spv/actions/runs/43648974548)
  each passed all seven jobs on attempt 1.
- [PR preparation](https://github.com/edgepillar/zenon-spv/actions/runs/43646371394)
  and [main preparation](https://github.com/edgepillar/zenon-spv/actions/runs/43648974591)
  each report 330 roots on Linux, macOS and Windows. Windows has exactly 49
  recorded POSIX skips; Linux and macOS have none. The experiment job is skipped
  for these test-only events.
- Each context has 44 checked original archives: 18 primary, one scope,
  21 supplemental and four preparation archives. The three seven-binary
  candidate packages supply 21 source/byte bindings per context. Supplemental
  checks cover archive digest/size, CRC, JSON framing and source/platform labels;
  they do not independently requalify their diagnostic or resource semantics.
- Independent Git-blob framing matches 747 Go/module/JSON inputs, 36,055,705
  content bytes and fingerprint
  `074fa8d0cdb5c0dddd7d5fcb0c5945998d8ff400c67f56d7ca8da270fce24672`.
  This input fingerprint is distinct from the complete repository tree.
- The focused local selection passed 239 roots, including 24 new roots, with
  no failures, errors or skips. Re-reading the retained H1 archive with the new
  reader produced its original report unchanged, without another transport.

Source CI, archive integrity and mathematical/recorded controls supply no
accepted-header authority or selected-network state-value result.

## What the latest executed diagnostic established

The [source-4f0b9f7 attempt](https://github.com/edgepillar/zenon-spv/actions/runs/43640873250)
ended `REFUSED` at `nodes`, reason `owned_rpc_readiness_deadline`. Its original
338,548-byte ZIP has SHA-256
`4020bdba1a525ad275362b3cfe3d8bb87e5454c6eda594c5674a2ef1372ee976`.
The hosted reader checked 689 indexed files and exited 1 with
`HOSTED_RECORDED_NON_ACCEPTING_OUTCOME`.

The later sync read reported `SyncDone` at height one; the next frontier again
returned v1 H1, hash
`fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`.
All four pre-cleanup node inspections reported running and `OOMKilled: false`.
Producer stdout summaries counted 5/4/1 production-start lines. The excluded
raw streams cannot be replayed independently, so these summaries remain
sequential diagnostic assertions. A production-start line precedes the worker
call and does not prove successful block production or an absence of errors.

No selected H2/H3 range, finite schedule capture, signed fixture setup, deposit,
proof or completed native consumer was reached. This outcome remains refused.

## Prepared observation, not an executed repair

The [file-log change](owned-startup-file-logs.md) addresses a source-derived
visibility gap: the pinned node writes generation errors and recovered VM
panic records to file handlers rather than Docker stdout. It does not claim
to fix the underlying H1 production problem.

After the original refusal, at most eight additional reads select two fixed
files from previously inspected owned containers. Each has a five-second
deadline, 64 KiB TAR stdout, 4 KiB stderr and 32 KiB decoded-content bounds.
The in-memory reader admits one exact regular entry and exports only a content
pin, bounded classifications and allowlisted source locations. Unknown or
incomplete data cannot become an empty successful log or application absence.

The actual Python command-recorder/finalizer control is exercised; the new
Docker file-log capture has not executed in an owned fixture at this cut.
Another signed fixture requires new source-specific approval and fresh host,
artifact-availability and source/ref checks. Existing readiness, RPC, cleanup,
anchor/profile/schedule and context-pin boundaries remain intact.

## Acceptance exits remain explicit

| Delivery / cases | Current evidence | Still required |
| --- | --- | --- |
| D0-D1; C01/C03/C04 | Exact source/contract inputs, earlier conformance and retained H1 observations. | Actual selected H2/H3 transition, anchor/range and finite-authorization provenance. Genesis and source-conditioned H3 expectations do not establish activation. |
| D2-D3-D5; C01/C05/C11 | Owned-header and typed-query implementations, strict local keys/proofs/ABI and controlled CLI workflows. | One actual selected accepted-header/root/context capture and completed three-row CLI consumer. |
| C09/C12/C14 | Bounded channels, actual exit/completeness, source-bound reports and new regular-file/in-memory controls. | Actual file-log observation in the separately authorized attempt; failures remain non-accepting. These controls do not close G2. |
| N1/S1; G4 | Inventory, transport/import preparation and declared resource controls. | An owner-selected consistent representative dataset and actual identity-bound measurements. No representative R1 result is introduced here. |
| D4 | Existing separate candidate proof primitives. | One demanded L2 path after the first selected consumer, with its own contract and acceptance. |
| D6; G3/G5/G6/G7 | Source/binary/report bindings for the stated scope. | Applicable integrated-node/profile, exact-network, independent-review, authenticated-distribution and future hash/profile decisions. |

Native v1/v2 inclusion and historical/read-only x402 observation remain
independent. A second operator is not required for an explicitly operator-trusted
development experiment. Such an experiment does not establish public-network
canonicality, consensus finality, transition correctness or recipient receive.
G7 applies to the corresponding future hash/network activation, not the narrow
existing-SHA3 owned experiment.
Production state proofs and irreversible settlement remain **NO-GO**.
