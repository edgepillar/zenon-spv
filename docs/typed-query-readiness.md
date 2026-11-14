# Typed-query readiness and acceptance ledger

Evidence cut: **14 November 2026**, ledger-selected native runtime source
[`e143ade8507a45a1f125de7bc15b92541036ef85`](https://github.com/edgepillar/zenon-spv/tree/e143ade8507a45a1f125de7bc15b92541036ef85).
This reconciles the [D0-D6 plan](typed-state-roadmap.md) with implemented controls
and the remaining execution and external gates. The planning document retains
its dated pins and original delivery states. A documentation-only head does
not advance runtime qualification.

The first product remains one actual query:

```text
owned accepted H/hash/context -> header-derived StateRoot
  -> local Settlement/domain/batch key -> bounded canonical proof
  -> strict BatchEntry ABI -> completed native CLI consumer
```

The controller requests three present proofs at the same H/root: BatchEntry,
domainRecord and domainConfig. The last two constrain the selected current-H
domain interpretation. They do not prove the runtime or configuration used by
an older batch. Native v1/v2 inclusion remains an independent delivery track.

## Keep these source identities separate

| Role | Pinned source or input | Meaning |
| --- | --- | --- |
| Frozen human-review candidate | `6ecc2310538d511e3b26bea4c658082853266a11` | Its original review/handoff scope remains fixed. Later source and CI do not inherit human acceptance. |
| Current ledger-selected runtime | `e143ade8507a45a1f125de7bc15b92541036ef85`, tree `0cfe07a72796b985e4d51483807c7a168d16c2e3` | Own-main Linux/macOS/Windows CI and archive qualification; see the [runtime ledger](review-candidate-changes.md#current-qualified-runtime-baseline). |
| Executed owned-runner ref | `codex/owned-devnet-query-runner` at `747fcf0293a7a341fed34393cac5afa0a96e5f1e` | The separately authorized third attempt recovered from the initial transport failure, then refused at the readiness deadline. Its authorization is consumed. The second source is preserved at `codex/owned-devnet-query-second-attempt-834d551`; the first remains fixed in its original record. |
| Qualified startup repair | `747fcf0293a7a341fed34393cac5afa0a96e5f1e` | Merged bounded empty-response readiness repair with its own main CI and artifact qualification. The third fixture executed this source without reaching the selected height or consumer. Later diagnostic changes need their own source qualification and execution permission. |
| Selected Linux consumer/oracle inputs | `7493c5929c7dbcfb29f94be521f7533d90a1a687` | The [reference-gas contract](reference-gas-owned-contract.md) pins their own qualified runs, artifact IDs, archive and binary hashes. They are not binaries built from the later runner or documentation head. |
| Original experiment contract | `owned-devnet-batch-query-contract/v1`, SHA-256 `1178cb1161d8e21a3f6e657aa2519900c8a0d4dbe6d207ecb667edf473cfe93e` | Original cohort and prepared metadata keep their byte identity. |
| Prepared reference-gas contract | `owned-devnet-batch-query-contract/v2`, SHA-256 `6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31` | Explicit separate source selection; a matching digest supplies no execution permission or network authority. |

The reference-gas sources select devnet `cf1c9c0`, node `2835c43`, executor
`a14bf0e` and the unchanged contract SDK `bc1548d`. Their full revisions,
prepared descriptor/profile hashes and qualified input runs are listed in the
[contract record](reference-gas-owned-contract.md). The
[source-cohort record](reference-gas-source-cohort.md) distinguishes actual
new-source conformance from unchanged source bytes and old-source executions.

The selected host is the existing read-only native CLI. Browser, WASI and a
public-library product are not selected by this experiment. A module rename
does not supply a public API or host integration.

## Delivery exits at this evidence cut

| Delivery | Existing implementation/evidence | Remaining acceptance exit |
| --- | --- | --- |
| D0 | Two exact contract selections; fixed chain 69, Settlement/domain 1/batch 0 selectors; prepared profile and independent context framing; [source and input pins](reference-gas-owned-contract.md); three separately authorized exact-source attempts recorded as non-accepting. | A new fixture attempt needs a new reviewed source and approval. Actual H2 hash, captured range and finite schedule remain unobserved; retain their provenance when available. No alternative batch is selected after absence. |
| D1 | Original-node 18-case root/proof/path controls and executor applier comparisons; [reference-gas conformance](reference-gas-source-cohort.md), [H1 and manager reopen](reference-gas-genesis.md), earlier isolated [first-v3 boundary](first-v3-node-boundary.md). | Observe the actual selected chain-69 H2/H3 transition and qualify its finite authorization. H1 execution and chain-100 fixtures do not establish that observation. |
| D2 | [Owned v3 headers](experimental-v3-owned-state.md), explicit source/profile/context, producer authorization, immutable views and trusted-local checkpoint controls. | Accept the actual captured range under the selected experiment contract. The one-run anchor replay has no checkpoint input/output; broader node recovery and supported migration retain separate gates. |
| D3 | [Three-row query](experimental-batch-context-query.md), header-derived root, local keys, bounded proofs, strict ABI and all 17 stored gateway fields; [owned controller and evidence reviewer](../tools/owned-devnet-query/README.md). | One actual selected BatchEntry must reach the native CLI and retained successful completion. The [first dispatch](owned-devnet-attempt-2026-11-13.md) refused at builder closure; the [second](owned-devnet-startup-attempt-2026-11-13.md) failed at the first node RPC read; the [third](owned-devnet-readiness-attempt-2026-11-14.md) recovered transport but refused at the selected-height deadline. Selected-network consumer acceptance remains open. |
| D4 | Separate [candidate proof primitives](candidate-smt-proof.md) and path/absence controls exist. | Choose one actual L2 read after D3 and demand; receipts, outbox, DA and processed/release/receive policy need their own contracts and consumers. |
| D5 | Existing native CLI and compiled recorded/synthetic workflows; source-selected context/checkpoint controls. | The chosen host must consume the actual selected query. Compilation and controlled replay do not complete this exit. Browser/WASI acceptance is outside the selected scope. |
| D6 | Source/run/platform and binary/report bindings for the selected runtime; separate fixed human-review candidate and historical SHA mapping. | Applicable independent review, update/rollback and authenticated distribution. Native inclusion, experimental preview and production state proofs retain different eligibility rules. No release is created by this ledger. |

The [first authorized owned experiment](owned-devnet-attempt-2026-11-13.md)
remains `REFUSED` at image-builder closure. The separately authorized
[`834d551` attempt](owned-devnet-startup-attempt-2026-11-13.md) completed both
image builds and the [builder-only compatibility handoff](owned-builder-shutdown.md),
then failed on the first loopback RPC command with exit 56 and zero response
bytes. Both original non-accepting archives remain intact. The second run
retained four runtime containers observed closed with exit 0; it produced no
opening-header capture, closed-ledger oracle or native consumer result. Its
budget observed about 2.81 GiB peak new disk use, without establishing an OS
aggregate quota or the cause of the RPC failure.

The separately authorized [third attempt](owned-devnet-readiness-attempt-2026-11-14.md)
at `747fcf0` retained the initial curl exit 56 and 29 subsequent completed
frontier commands, then recorded `REFUSED` at `owned_rpc_readiness_deadline`.
Its 591 indexed files and original 277,053-byte ZIP were verified in place.
No signed fixture step or consumer result was reached. The original response
bodies were not selected for upload, so their pins do not establish the exact
stalled height. All four runtime containers were observed closed.

All three one-attempt authorizations are consumed. The bounded startup repair
does not reclassify any prior run or authorize a replacement. Its own main
CI and artifact qualification are complete. Selecting the native
runtime `e143ade` does not replace this runner selection or the contract's
`7493c59` consumer/oracle inputs. A new signed fixture needs a reviewed exact
source and explicit approval; a matching contract digest supplies no permission.
The current execution ref remains at the already executed `747fcf0` source;
the previous `834d551` ref and evidence are preserved separately.

For `747fcf0`, [main general CI](https://github.com/edgepillar/zenon-spv/actions/runs/43529102244)
passed all seven jobs. [Main preparation CI](https://github.com/edgepillar/zenon-spv/actions/runs/43529102221)
reported 226 controls on each platform, with 44 platform skips on Windows and
none on Linux or macOS. Each context of [PR #389](https://github.com/edgepillar/zenon-spv/pull/389)
and its main push has 44 retained, source/run/platform-bound archives: 23 primary
archives and 21 supplemental integrity/readback archives. The latter do not
independently requalify their diagnostic or resource semantics. Independent Git
blob framing also matched the Go/module/JSON input fingerprint in each context;
it creates no new native execution or selected-network acceptance. These source
and archive controls do not execute another signed fixture or replace the fixed
consumer/oracle inputs.

The selected flow uses public fixture accounts for domain configuration, vault
setup and one test-ZNN deposit before read-only capture and offline consumption.
None of the three attempts reached those signed fixture steps. The selected
deposit flow does not select a withdrawal or release operation.

The bounded plan allows one fresh GitHub-hosted Linux attempt: 50-minute
workflow timeout, 2,700-second controller budget with a 300-second closure
reserve, at most 8 GiB new disk, and at least 19 GiB initial free space. The
experiment repeats admission and artifact-availability checks on its own host.
These are configured/sampled bounds, not an OS aggregate disk quota.
Preparation admission samples do not prove runtime enforcement. A failed or
incomplete attempt remains FAILURE/UNKNOWN; there is no automatic retry.

## C01-C15 acceptance coverage

These rows map the plan's minimum matrix to available controls. A local
control is not a passed selected-network acceptance case. D4-specific clauses
remain deferred when their path is not part of the selected query.

| Case | Current control scope | Selected experiment / later gate |
| --- | --- | --- |
| C01: valid exact query | Recorded/synthetic owned-header and compiled CLI composition. | **OPEN:** actual selected H/hash/context, three proofs and completed consumer result. |
| C02: wrong identity/profile/version | [Owned v3 configuration](experimental-v3-owned-state.md), source-cohort and CLI context refusals. | Retain the actual experiment's independent expectations; never replace them from a provider reply. |
| C03: genesis/first-v3/expiry | [Reference-gas H1](reference-gas-genesis.md), source rules, isolated boundary and finite-profile controls. | Actual chain-69 H2/H3 observation remains open; no v3-from-genesis inference. |
| C04: signature/producer/schedule | Native signature, finite authorization, unknown-producer and coverage-gap controls; [closed-parent oracle](closed-devnet-parent-oracle.md). | Actual closed-ledger parent/slot provenance remains open. This is not authenticated election, fork choice or canonicality. |
| C05: provider-selected root/header | Opaque accepted state and [header-bound query](experimental-batch-context-query.md) prevent replacement by self-consistent candidate data. | Use the captured owned H/root/context; a provider boolean cannot supply authority. |
| C06: key/path/domain/adapter | [Typed keys](candidate-batch-entry-key.md), single-hash paths and independent source-byte vectors. | Preserve the independently selected Settlement/domain/batch; L2 path-native rules stay separate. |
| C07: absence/zero/empty/delete/excluded | [SMT policy](candidate-smt-proof.md), original-node proof/applier controls and typed-absence refusal. | No absent or unavailable BatchEntry becomes a zero row. Plasma/frontier/mailbox remain excluded from the current L1 projection. |
| C08: canonical proof/ABI/schema | [Strict ABI](candidate-batch-entry-codec.md), canonical-proof and source-field rules, malformed/trailing/unknown-schema refusals. | Compare actual authenticated bytes under the exact selected schema. |
| C09: exact/one-short limits | Value, node, proof, aggregate-work/input caps and bounded collector/consumer controls. | Local policy caps and codec observations do not establish production hardware/resource budgets. |
| C10: mixed root/time/processed facts | Same-H/root three-row composition and [current-H domain semantics](batch-entry-domain-context.md). | H<finalizeAtHeight<=T does not establish finality at H. Processed/withdrawal claims require separately selected D4 policy. |
| C11: gateway/nested identity | All 17 stored BatchEntry fields are compared by the [strict consumer](../tools/owned-devnet-query/query_checks.py). | Actual selected DTO comparison remains open; unrelated nested L2 input/message proof cases belong to D4. |
| C12: unavailable/pruned/incomplete | Bounded acquisition, command completion, partial-output and missing-witness refusal controls. | Preserve actual failure/unknown; DA retrieval and liveness are not established by an L1 membership result. |
| C13: state/context/restart | v1/v2 regression, immutable ownership, source-separated checkpoints and explicit provenance controls. | No implicit trust renewal. The narrow owned anchor replay does not qualify general node recovery or a live checkpoint workflow. |
| C14: process/output/channel | Actual exit/completeness capture, owned closure and [retained-result review](../tools/owned-devnet-query/review.py). | An ACCEPT-bearing payload cannot promote a failed/incomplete process into successful consumption. |
| C15: browser/WASI parity | Not selected for this native CLI experiment. | Require an actual named host and full-width identity/ownership/cap/context parity before supporting it. |

## G0-G7 and the remaining external inputs

| Gate | State / concrete remaining evidence |
| --- | --- |
| G0: scope/source/query | Three separately authorized exact-source executions are retained as non-accepting: builder closure, first node RPC read, then selected-height readiness deadline. All three authorizations are consumed; a new fixture run needs a new explicit approval. Actual run-derived anchor/range remain open. |
| G1: conformance/profile | New-source bounded conformance and H1 lifecycle are recorded; actual first-v3 range/authorization and applicable profile review remain open. |
| G2: actual typed consumer | **OPEN:** the real selected three-row capture and completed native consumer. Green CI and retained-result mathematics do not close it. |
| G3: integrated node/profile | General identity/recovery and agreed supported profile behavior remain open; a narrow owned devnet success would not close every node lifecycle path. |
| G4: representative budgets | **OPEN:** an authorized consistent raw-ledger dataset, capture owner/method and full identity/size/frontier metadata; see [#270](https://github.com/edgepillar/zenon-spv/issues/270). Source-genesis and synthetic workloads are not representative R1 data. |
| G5: exact-network activation/pilot | **OPEN:** authenticated intended-network inputs and an actual scoped pilot. Native v1/v2 inclusion remains independent of Zeno v3 activation. |
| G6: independent review/release | **OPEN:** exact-candidate independent acceptance and authenticated distribution; the frozen review candidate is unchanged. |
| G7: applicable hash/profile decision | Required for the corresponding future mainnet activation; not a prerequisite for the narrow existing-SHA3 devnet experiment. |

The maintainer's [contract/source feedback](https://github.com/Zeno-L2/zeno-devnet/issues/1#issuecomment-6612559092)
applies to `702180a` / node `938fca3`. It supplies no public RPC endpoint;
the devnet is local-only. Its source review is not silently transferred to
node `2835c43` or a later SPV revision. One operator is sufficient for an
explicitly operator-trusted experiment; a second operator is not the missing
execution prerequisite here.

The [R1 intake](state-root-r1-intake.md) and snapshot transport/import
preparation can proceed independently. A ZIP directory/WAL observation does
not establish capture consistency, network/frontier identity or representative
resource results. No large archive acquisition is selected by this update.

Production state proofs and irreversible settlement remain NO-GO. W depth,
Settlement delay, consensus finality, transition correctness and fund
release/receive remain separate claims.
