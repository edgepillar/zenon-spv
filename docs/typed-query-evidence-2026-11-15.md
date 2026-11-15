# Typed-query source and execution evidence: 15 November 2026

This supplements the [dated acceptance ledger](typed-query-readiness.md) and
[D0-D6 plan](typed-state-roadmap.md). It records already qualified sources and
two retained non-accepting executions and the qualified tail runner. It introduces no new runtime build,
selected-network acceptance, independent review or release. Historical records
retain their original revisions and outcomes.

## Source roles

| Role | Exact identity | Scope |
| --- | --- | --- |
| Earlier qualified runner/diagnostic main | `7cb3fdda54a7febd11ed6c8e2901d3a5d066cd53`, tree `c3922b4babbc312cbb99bce50a89ca61eb143f02` | Local `edgepillar` author/committer merge of [PR #396](https://github.com/edgepillar/zenon-spv/pull/396), followed by its own main CI and artifact checks. |
| Earlier reviewed PR source and test checkout | Feature `bc84ff8c086e647da8219be2d8939c9204e7532b`; test merge `846216b61245ba069e2003a9cba5c65e2019aaf7` | Separate PR qualification. The reviewed tree matches the local main merge; each revision keeps its own evidence. |
| Qualified bounded-tail runner main | Main `57929f01faa75ea3a4b9942d38889b0c7947d4f7`, tree `d58e43420a130dd272d824c64e59f9befe3d6518` | Local `edgepillar` merge of [PR #397](https://github.com/edgepillar/zenon-spv/pull/397); feature `c12dba4e9ed1a721256d92c5b695f004320dff14`, PR test merge `df72d66cc71a9522f3771875f54dd2c5763046cf`. PR and main have their own completed source/platform CI and artifact qualification. |
| Retained H1 execution | Main `4f0b9f738041c368477c365e1b65fb01f71a2c1c`; run `43640873250`, attempt 1 | Readiness refused at H1. Its single-dispatch authorization is consumed. |
| Latest executed owned diagnostic | Main `7cb3fdda54a7febd11ed6c8e2901d3a5d066cd53`; run `43653383092`, attempt 1 | Readiness refused; a later unauthenticated frontier observation returned candidate v1 H2. No accepted H3 or consumer result. Its single-dispatch authorization is consumed. |
| Selected consumer/oracle binaries | `7493c5929c7dbcfb29f94be521f7533d90a1a687` | Existing independently pinned input artifacts from the [reference-gas contract](reference-gas-owned-contract.md); not binaries relabeled as the later runner. |
| Frozen human-review candidate | `6ecc2310538d511e3b26bea4c658082853266a11` | Its original scope remains fixed. New source qualification does not transfer independent human acceptance. |

The selected contract remains v2, SHA-256
`6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31`.
Its [source cohort](reference-gas-source-cohort.md), chain-69 genesis,
Settlement/domain 1/batch 0, profile and finite-authorization requirements
remain explicit. No alternate query is selected after an unavailable result.

## Completed source qualification at 7cb3fdd

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

## Completed runner source follow-up

The [PR #397 general CI](https://github.com/edgepillar/zenon-spv/actions/runs/43656311153)
passed all seven jobs. Its [preparation](https://github.com/edgepillar/zenon-spv/actions/runs/43656311116)
reports 350 roots on each platform, with exactly 49 expected POSIX skips on
Windows and none on Linux/macOS. Its 44 original archives and 21 candidate-binary
bindings have been checked with the same explicit supplemental-integrity scope.

The focused local selection passed 259 roots in 8.066 seconds, including 20
additional tail/reader cases, with no failures, errors or skips. Both retained
execution ZIPs were reread in place and produced their original report structures;
no artifact transport was repeated.

The new main's [preparation](https://github.com/edgepillar/zenon-spv/actions/runs/43658957995)
and its four artifacts are qualified with the same 350-root/49-skip accounting.
Its [general CI](https://github.com/edgepillar/zenon-spv/actions/runs/43658957937)
passed all seven jobs. Main's independent artifact checks complete the same
44-archive and 21-binary-binding accounting. The identical reviewed tree did not
replace main's own qualification. Both contexts keep their original source/run
identities and integrity-only supplemental scope. No signed fixture has run on
this source; its tail command and selected-network consumer remain unexecuted.

## Retained H1 diagnostic

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

## Later H2 diagnostic

The [source-7cb3fdd attempt](https://github.com/edgepillar/zenon-spv/actions/runs/43653383092)
also ended `REFUSED` at `nodes`, reason `owned_rpc_readiness_deadline`. Its original
351,317-byte ZIP has SHA-256
`79bba4eed277ea9328cba856c28304cc4aecc8e2f44332870d4c7a49119b9b80`.
The hosted reader checked 714 indexed files, materialized zero bytes and exited
1 with `HOSTED_RECORDED_NON_ACCEPTING_OUTCOME`.

The later sync read reported `SyncDone` at current/target height two. The following
frontier read returned candidate v1 H2, hash
`6203eed405db9b47b93628ed4178740150d35dbb3353bcee75fd622133c9798e`.
These sequential diagnostics do not select an accepted anchor or establish the
first incoming v3 boundary. No fixture setup/deposit, proof or native consumer
was reached. The original refusal is preserved.

The v1 file-log capture executed. It observed two fixed late-broadcast messages
in one producer's error file, while two run-log reads remained incomplete/refused.
The [execution and byte-tail record](owned-startup-log-tails.md) preserves their
bounds and the distinction between a recorded source branch and its unknown cause.
Cleanup stop-state records report RPC exit 137, third-producer exit 2 and exits
0 for the other two producers, all with `OOMKilled: false` and `Running: false`.
The cause of the nonzero exits is not established; complete owned-runtime closure
remains unqualified.

## Bounded-tail candidate

The [v2 follow-up](owned-startup-log-tails.md) reads at most the last 32 KiB from
the same two fixed files in each previously inspected owned node. At most eight
additional commands retain the five-second deadline and 4 KiB stderr bound.
Possible leading fragments and unfinished final lines are excluded. The complete
stdout pin binds the captured window; fixed classifications and byte accounting
describe only complete inner records. Raw text remains outside the public index.
Zero classified records are not proof that a file is empty or an error absent.

The v1 TAR reader retains its original schema, 64 KiB transport limit and report
shape. Historical failures are not repaired or relabeled. Recorder/finalizer,
reader and command-construction controls passed; the node tail command has not
executed in an owned fixture. Actual applet availability remains a runtime check.
Another signed fixture needs
source-specific authorization and fresh source/ref, input and host checks.
Readiness, producer timing, RPC, cleanup, anchor/profile/schedule and context-pin
boundaries remain intact.

## Acceptance exits remain explicit

| Delivery / cases | Current evidence | Still required |
| --- | --- | --- |
| D0-D1; C01/C03/C04 | Exact source/contract inputs, earlier conformance and retained H1/H2 diagnostics. | Actual selected H2/H3 transition, accepted anchor/range and finite-authorization provenance. The unauthenticated H2 observation and source-conditioned H3 expectation do not establish activation. |
| D2-D3-D5; C01/C05/C11 | Owned-header and typed-query implementations, strict local keys/proofs/ABI and controlled CLI workflows. | One actual selected accepted-header/root/context capture and completed three-row CLI consumer. |
| C09/C12/C14 | Partial v1 file-log observations, actual exit/completeness and stop states, bounded v2 controls and source-bound reports. | Actual v2 window observation and diagnosis of production delay/nonzero shutdowns; failures remain non-accepting. These controls do not close G2. |
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
