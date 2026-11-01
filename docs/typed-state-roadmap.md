# Typed-state delivery plan

Selected planning baseline: **1 November 2026**.

Tracking: [#293](https://github.com/edgepillar/zenon-spv/issues/293).

This is the current D0-D6 plan linked by the [native roadmap](native-roadmap.md).
Delivery and gate states below are planning states. This documentation change
does not execute a devnet, enable runtime v3/state-value acceptance, authenticate
network activation or publish a release. Historical source/report identities remain fixed.

## First consumer and independent native track

Deliver a reusable resource-bounded native verifier, first consumed through one header-bound Zeno BatchEntry query on an explicitly selected experimental devnet profile, while retaining an independent native inclusion consumer and coordinating measured node/snapshot work.

First query:

```text
owned accepted header H/hash/context
  -> StateRoot extracted from that header
  -> locally derived Settlement / domain / batch storage key
  -> bounded canonical proof
  -> strict BatchEntry ABI decoding
  -> one actual read-only consumer result
```

One Settlement BatchEntry on the selected devnet. This intentionally updates the earlier balance-first M3 wording to typed-state-first while preserving accepted-header authority, local key derivation and strict results. A balance reference can reuse the same core after its amount profile is agreed; it is not another mandatory first-month product.

Native v1/v2 inclusion and the read-only x402 observation lane remain independent
of this Zeno delivery. Their scoped release does not wait for D3 or Zeno activation.

## Scope decisions

| Scope | Decision | Required condition |
| --- | --- | --- |
| Extend the existing verifier | GO | Reuse current implementation and primitives; do not rewrite. |
| Narrow Zeno devnet integration | GO_WITH_EXPLICIT_EXPERIMENTAL_SCOPE | Choose one query/profile and preserve all inherited trust. A mathematical demo cannot emit an authenticated-state guarantee. |
| Native inclusion/x402 observation | GO_READ_ONLY | Start with historical/read-only witnesses and explicit payment identity; inclusion is not settlement authorization. |
| General production v3/state proofs | NO_GO_UNTIL_GATES | Agreed network profile, integrated node behavior, measured workload, exact-network activation, independent review and authenticated distribution remain required. |
| Zeno Phase1 on mainnet or irreversible settlement | NO_GO | Current Zeno Phase1 is executor-attested and testnet-only. L1 membership does not prove execution correctness, consensus finality, receive or spendability. |

## Source and qualification identities

These are selected planning pins, not a claim of new execution or maintainer agreement.
Recheck source/profile changes before running the selected experiment.

| Identity | Selected revision |
| --- | --- |
| spv_main | `df1cc52af3ae132a33bf3c41541fcb214eccc0d6` |
| spv_main_tree | `00b7972b2099c8cb35d09459608b79426c7ba4ea` |
| qualified_runtime_baseline | `1b8a33fd351ee5b7c697aac21940323ee1f81c74` |
| qualified_runtime_tree | `38d9c0b37554622454452c149d251dad99204978` |
| frozen_human_review_candidate | `6ecc2310538d511e3b26bea4c658082853266a11` |
| zeno_docs | `d74ba1fc4b01583af0daf33a2dedfc84ea2b9419` |
| zeno_devnet | `04dc0797f7bcc02e48e0acba3b0ac49df2d3289d` |
| devnet_node | `938fca3b7787da86827a5eb63371509b36e14761` |
| devnet_executor | `caeaf764270b1489a53c860c6006026af208f924` |
| devnet_console | `b4726037e01e5e2c2a37f3f7a234cc29daee6cc2` |
| devnet_contract_sdk_rs | `bc1548d75473797f24bb3eb79f5594969c596e39` |
| historical_root_node | `9c71ae82fc983e16f914ae085d4034030c8ebe3b` |
| historical_corpus_node | `56ce2c384966f2f1940967257a0788d3998a5eef` |

The own-fork main pin is documentation-only. The ledger-selected runtime baseline
and original frozen human-review candidate retain their own evidence and scope.
Open [PR #292](https://github.com/edgepillar/zenon-spv/pull/292) is separate
qualification work; this plan does not merge it or transfer its CI to another source.
The [review change ledger](review-candidate-changes.md) retains the old-to-new SHA
mapping. An equal tree or identity-normalized commit does not inherit old CI or review.

## Authority and required invariants

- The original owner memo is a dated architectural input; Zeno research/state-root.md is a separate informative file. Neither overrides the selected normative contract or actual source behavior.
- Agreed normative rules and selected implementation must match before supported acceptance. Resolve known doc/code discrepancies explicitly rather than treating a prose note as executable consensus.
- Zeno Phase2 remains an outline. R9, future validity proofs, hash migration and governance dates remain conditional decisions.
- One active source/profile manifest may mirror the selected devnet sources.txt; historical corpus/execution manifests retain their original independent pins.
- Current source, selected runtime CI, frozen human-review evidence, new local results and actual activation/distribution remain distinct.

- Default refusal remains for unsupported, inactive, unknown or incomplete profiles and commitment domains.
- A provider root, self-consistent candidate hash or experimental flag cannot create accepted header/state authority.
- Bind network/genesis, selected anchor, producer schedule provenance/coverage, version/profile and immutable verification context explicitly; chain ID alone is insufficient.
- Genesis is v1. Derive and qualify the actual first incoming v3 boundary; do not assume it equals genesis or enforcement height.
- Use the full 18-case suite obligations: roots, leaves, serialized inclusion/absence, path-native/double-hash and L2 applier behavior. Cases and assertion counts are distinct.
- Partial L1 projection covers balance/storage. Plasma, frontier and mailbox remain excluded; unknown/excluded raw absence is not application absence.
- L1 raw-key hashing and already-derived L2 paths are separate adapters. Preserve L1 empty-to-delete versus L2 present-empty and absent versus stored-zero.
- Approve canonical encoding and schema-aware value/proof/cumulative-work limits. Local research caps are not protocol limits.
- Missing, pruned, unavailable, corrupt or incomplete witnesses remain refusal/error; never turn them into an absent/zero application value.
- Keep all actual failures, skips, incomplete output and historical source identities. CI, replay, tags, attestations and source equivalence do not prove independent acceptance or network activation.

## Completion labels

| State | Meaning |
| --- | --- |
| MATH_ONLY | Source-pinned byte/root conformance or standalone comparison. Header/root inputs remain untrusted; no STATE_VALUE_INCLUSION. |
| DEVNET_PROFILE_SELECTED | The experiment owner explicitly selects and reviews a narrow source/network/profile/schedule/ABI/cap contract. Any external maintainer agreement not obtained is recorded as open. This does not register a general production profile. |
| DEVNET_CONSUMER_ACCEPTED | The owned accepted-header pipeline and actual typed consumer pass the scoped experiment under explicit assumptions and declared lifecycle limits. Broader M2 node/recovery, independent-network and production gates remain open. |
| REVIEWED_DISTRIBUTION | The actual selected release scope has completed applicable profile/node/workload/consumer/independent-review and authenticated-distribution gates. Devnet and production labels remain separate. |

## Deliveries

All listed owners are proposed accountable roles; no external person's availability
or commitment is assumed. Select actual owners before the corresponding execution.

### D0: One consumer contract and source baseline

**State:** PLANNED. **Priority:** NOW.
**Proposed owner:** SPV maintainer + selected consumer owner.
**Depends on:** explicit scope selection.

Select one read-only Settlement BatchEntry query, one devnet profile and one existing client integration seam. Record exact source/build/profile identities; preserve historical pins, SHA mappings, failures and evidence.

Work:

- Pin the four devnet component revisions plus spec, vector and build/configuration identities. Add any client/library pin when that host is actually selected.
- Select network/genesis/anchor, Settlement contract, domain, batch and required guarantees independently of gateway replies. The proven value is a query output; it need not be predetermined or copied from the gateway.
- Capture node recovery/profile questions for maintainers and prepare a concise English agreement/proposal draft early.
- Repair the broken README table, missing-tool reference and stale current-baseline entrypoints as small follow-up changes. Decide CLI-preview versus public-library scope before module publication.

Acceptance exits:

- One bounded consumer contract lists request identity, authoritative header source, trust, limits, expected failure behavior and unresolved decisions.
- Every active source cohort and current/frozen qualification identity remains distinguishable; no archive or module rename is needed to start.

### D1: Devnet conformance and profile

**State:** PLANNED; PRIMITIVES_REUSED. **Priority:** NOW.
**Proposed owner:** SPV maintainer + protocol/profile reviewer.
**Depends on:** D0.

Establish exact format and activation behavior for the chosen experimental profile.

Work:

- Check narrow9c71→938 subtree equivalence and retain old execution labels; do not regenerate every old experiment.
- Inventory and qualify all declared 18-case root/proof/path/applier obligations, plus targeted malformed/flag/length/cap/canonical/presence controls.
- Derive first incoming v3 from v1 genesis and predecessor-frontier spork logic; test the actual boundary, inactive/unknown versions and coverage expiry.
- Select producer schedule from independently chosen devnet inputs, its coverage and provenance. Require StateRoot availability no later than Offchain under the chosen network rule.
- Pin partial-tree/hash/canonical/ABI/value limits, query-key derivation and L1/L2 adapter semantics. Keep mainnet and unsupported profiles refused.

Acceptance exits:

- Conformance report lists actual selected source, assertions, attempts and outcomes; root-only18/18 is insufficient.
- The selected profile has explicit genesis/first-v3/schedule/key/value/proof/context rules and honest open agreement/lifecycle limits.

### D2: Owned accepted-v3 header path

**State:** PLANNED. **Priority:** NEXT.
**Proposed owner:** SPV maintainer.
**Depends on:** D1.

Connect existing candidate format code to strict RPC, header authentication and immutable state only under the selected profile.

Work:

- Propagate v3/root through strict bounded RPC decoding, hash/signature/linkage checks, schedule authorization and selected activation rules.
- Extend owned state, context/profile identity and persistence schemas coherently; preserve v1/v2 behavior and fail closed on ambiguous/unsupported migration.
- Keep provider/caller-built raw roots outside accepted-state constructors; detached views must not mutate accepted evidence.
- Use existing CLI/result/ownership machinery. Expose only the minimal reusable Go facade needed by the selected consumer; decide module/import identity in the same coherent publication change.

Acceptance exits:

- A real selected v3 chain is accepted only under its explicit scoped profile; altered signature/root/header/profile/context and wrong genesis refuse/reject appropriately.
- Restart, saved-state/context migration and v1/v2 regression controls preserve prior guarantees and actual failure boundaries.
- Without a selected supported experiment contract, the tool remains MATH_ONLY and production STATE_VALUE_INCLUSION remains refused.

### D3: One typed BatchEntry vertical slice

**State:** PLANNED. **Priority:** PRIMARY_FIRST_PRODUCT.
**Proposed owner:** SPV maintainer + Zeno consumer integrator.
**Depends on:** D2.

Deliver one authenticated storage query and one actual consumer result before expanding to all Settlement records.

Work:

- Extract expected StateRoot from the owned accepted header H/hash/context.
- Derive the full storage key locally from fixed Settlement address, domain and batch. Pin L1 Settlement ABI/schema as well as relevant domain/runtime profile; prove a minimal DomainRecord/config dependency only if required.
- Verify bounded canonical proof, then strictly decode authenticated bytes and compare every selected gateway batch commitment field with this proven row.
- Bind H to retained state and verified tip T under selected W; enforce finalization delay at H only if that claim is requested.
- Integrate one existing client seam or CLI consumer. Bind result caches to source header/context and invalidate when fork/anchor/profile interpretation changes.

Acceptance exits:

- One actual selected batch flows through accepted header → header-derived root → local typed key → bounded proof → exact ABI → strict completed consumer.
- The negative matrix passes and all actual attempts, exits, skipped/incomplete evidence and progress boundaries are retained.
- Result names L1 membership and executor/domain assumptions precisely; it does not claim state-transition correctness, consensus finality or spendability.

### D4: Add L2 read paths incrementally

**State:** PLANNED; NOT_FIRST_MONTH_REQUIRED. **Priority:** AFTER_D3.
**Proposed owner:** Zeno adapter maintainer.
**Depends on:** D3.

Add one selected L2 state proof, then receipt and outbox only when consumed.

Work:

- L2 state: derive contract/local-key path with the agreed path-native convention; do not hash the path again; preserve present-empty.
- Receipt: bind domain/batch, source input/send, contract, status, return data and related event/outbox commitments.
- Outbox: use exact canonical typed message encoding, indices and specified binary-Merkle construction; do not reuse native flat content or SMT formats as binary-Merkle formats.
- Prove any processed/domain/pause facts needed by the requested policy at the same H/root; keep registration, release and receive separate.
- Define bounded witness/DA acquisition and unavailable/pruned/timeout refusal. A matching DAHash does not guarantee retrieval.

Acceptance exits:

- Each added path has one consumer use and its own positive/negative identity, temporal, byte/work and missing-data acceptance cases.
- L2_COMMITMENT_INCLUSION or any new guarantee is versioned and interpreted by the strict consumer; executor attestation remains explicit and STATE_TRANSITION stays unproven.

### D5: Functional host integration

**State:** PLANNED; DEMAND_SELECTED. **Priority:** AFTER_D3.
**Proposed owner:** Selected client maintainer + SPV integrator.
**Depends on:** D3.

Choose a native Go/CLI adapter first; add browser WASM or a bounded local sidecar only for an actual host need.

Work:

- Use the smallest public owned-state/result facade and an external-module example; a namespace rename alone is not an API.
- For browser support run native-equivalent corpus in a real browser using js/wasm, preserve full-width uint64/BigInt identity, bounds, byte ownership, cancellation and context/result parity.
- If a WASI consumer exists, qualify wasip1/wasm on its actual host separately; compilation alone is preparation.
- Keep filesystem persistence, watch/network policy and endpoint serving outside the pure verifier. If sidecar is selected, define local access, request/work limits and lifecycle before claiming support.

Acceptance exits:

- The named host actually consumes the selected query with the same guarantees, refusals and identity/cap semantics as the native core.
- Caches and report delivery cannot promote a provider boolean, stale context or unrelated summary into authority.

### D6: Scoped reviewed distribution

**State:** OPEN; NO_FIXED_DATE. **Priority:** AFTER_APPLICABLE_GATES.
**Proposed owner:** Release maintainer + independent scope reviewers.
**Depends on:** D0.

Release native inclusion and experimental devnet/state-proof scopes separately; production requires all additional node/network/workload gates.

Work:

- Select actual candidate/platform/source/tree, native binary hashes, reports/skips and update/rollback policy. Equal historical trees do not transfer qualification.
- Make CLI-only preview versus library preview explicit; experimental publication is not production support or completion of independent review.
- Use exact build provenance, checksum and attestation verification. They authenticate origin/build relationships, not semantic correctness.
- For a supported production state-proof release close agreed profile, integrated node behavior, representative budgets, exact-network activation, real consumer and independent review gates.
- Follow repository-local author/committer identity, protected pre-push guard and authorized local merge policy; preserve identity mapping and old reports.

Acceptance exits:

- The chosen release's claims are supported by its own review and source/binary/report/platform evidence and authenticated distribution.
- No Phase1 attestation-based Zeno mainnet claim or irreversible-settlement authorization is inferred from a tag, CI or devnet demo.

| Release scope | Candidate prerequisites |
| --- | --- |
| Native v1/v2 inclusion | X1 or the selected existing native consumer, applicable exact-network profile/anchor and scoped candidate evidence. Independent review and authenticated distribution complete this release; no D3 or Zeno activation dependency. |
| Experimental Zeno devnet preview | D3/G2 scoped typed consumer and explicit experimental profile/limits. Public preview is not production review or public-network support. |
| Production state proofs | Actual selected typed consumer, applicable G3-G5 node/profile/workload/activation and hash decision. G6 independent review/authenticated distribution completes release. Zeno Phase1 remains testnet-only. |

## Parallel lanes

### N1: SPV-R1 inventory and node/snapshot measurements

**Proposed owner:** Node/snapshot operator + SPV/protocol reviewer.
**Start:** Start intake at D0; acquire/measure when a consistent authorized dataset and budgets are selected.

Scope: Measure balance/storage and excluded plasma/frontier/mailbox key counts, encoded sizes, churn/patch distribution, build/catch-up, proof service, retained/archive disk and actual import/reopen costs on declared hardware.

Dependency boundary: No full representative inventory is required for a narrow existing-domain devnet prototype. Representative results are required before production domain expansion, activation/import/resource commitments.

Acceptance exits:

- Source-bound consistent dataset with full frontier identity and completeness/accounting scope.
- Declared time/memory/disk/network budgets and actual outcomes; source-genesis records are supporting controls, not representative network data.
- Current projection and candidate extensions compared before a versioned scope decision. Mailbox completeness needs an authenticated collection invariant; adding a prefix alone does not prove no pending items.

### N2: Node identity, recovery and activation agreement

**Proposed owner:** Node maintainer + protocol reviewer + SPV maintainer.
**Start:** Open bounded decision/defect intake at D0; integrate and qualify with the selected node owner.

Scope: Adopt one reviewable node revision for full height/hash root provenance through startup, matching/foreign ahead/behind state, cache, retention/prune, reorg, import, interruption and migration/downgrade.

Dependency boundary: Broader supported/prod state proofs depend on this exit. A fresh controlled devnet observation records its narrower lifecycle assumptions without claiming this gate closed.

Acceptance exits:

- Existing proposed patches, recorded observations, adopted commit and fresh qualification remain separate.
- Missing/foreign/corrupt histories fail closed without implicit destructive reset or relabeling.
- Prebuild/no-prebuild, background readiness, after-activation join, snapshot-start and reorg-across-activation paths meet agreed liveness and correctness criteria. Never solve readiness by silently accepting unverified v3 roots.

### S1: Snapshot transport/import in parallel

**Proposed owner:** Snapshot/node maintainer.
**Start:** Preparation can proceed alongside D0-D3 and N1; root activation is not a prerequisite for transport engineering.

Scope: Reuse current tools; keep chunk integrity, committed-state reconstruction and excluded-state trust separate.

Dependency boundary: Production header-bound import depends on agreed profile/root semantics and qualified node/import behavior.

Acceptance exits:

- Transport digests authenticate selected chunk bytes; reconstruct the agreed typed SMT and compare its root with an accepted H header root.
- Excluded state carries explicit trust or a qualified reconstruction/completeness rule; partial-root match never authenticates a full node snapshot.
- Import tree/frontier identities match and restart/reorg/retention/readiness behavior is qualified on the selected node. Do not promise one-field-only implementation effort.

### X1: Historical/read-only native inclusion adapter for x402

**Proposed owner:** Native consumer/facilitator owner + SPV integrator.
**Start:** Small parallel item when it does not delay D1-D3.

Scope: Use existing CLI/strict JSON before broader public API. Select the exact original transaction/request and verify native inclusion under declared anchor/profile/schedule/depth assumptions.

Dependency boundary: Independent of v3 and Zeno. Any live payment/irreversible fulfillment is a separate explicitly selected acceptance and execution scope.

Acceptance exits:

- Bind network/genesis, asset/amount/recipient, payer/request authorization, invoice/challenge and original hash; preserve replay and unknown-payment reconciliation.
- Expose inclusion_only or equivalent precise claim. Do not infer execution, consensus finality, recipient receive, spendability or settlement completion.
- Count as a working integration; independent consumer acceptance needs an actual consumer owner's acceptance.

### ZK-R3: Zeno hash decision inputs

**Proposed owner:** Zeno proving owner + SPV client-performance contributor.
**Start:** Coordinate early; run measurements when actual guest design/hash or selected client budget needs the data.

Scope: Actual R3 is zkVM-guest depth256 updates/multiproofs and read/write/batch cycle share. Go/browser/mobile proof costs are a separate client-budget input.

Dependency boundary: Guest/zkVM selection belongs to Zeno's own research. Keep its R1 naming separate from SPV-R1 inventory.

Acceptance exits:

- R3 decision uses the actual question's data; no browser benchmark is substituted for guest cycles.
- Any hash change has explicit root/proof/vector/profile/persisted-state/snapshot compatibility and activation/migration decisions; a hash interface is code organization only.
- R9 remains conditional. R6 stays optional and later; Phase2 mainnet validity claims require its eventual normative design and independent acceptance.

## Request and result contract

| Part | Contract |
| --- | --- |
| request | Select network/genesis/profile, anchor/context, H/hash, Settlement address, domain and batch independently. A provider cannot choose those expected identities. |
| value | Read and verify the actual value under the accepted header root, then decode it. Do not require a gateway-supplied value/root as the authority or pretend query outputs were independently predetermined. |
| temporal | Bind relevant L1 records to one H/hash/root; retain verified tip T and selected depth T-H>=W. Evaluate finalizeAtHeight<=H for delay claims. If proofs use different heights, report separate facts or reacquire a coherent snapshot. |

Allowed claims, only when their corresponding path has been implemented and qualified:

- L1 typed storage membership at H under selected external trust
- L2 commitment membership under the proven BatchEntry root when that path is implemented
- Settlement delay elapsed at H when requested and proved
- Outbox registration or non-registration at H when that marker is proved

Inferences the result must not make:

- W-depth is consensus finality
- Signed header or RPC quorum proves elected canonical history
- Attested BatchEntry proves STF execution correctness
- processedOutbox means funds released or recipient received
- An old absence proves current unregistered/withdrawable state
- DAHash guarantees availability
- An excluded/missing witness proves zero or account absence

Example precise labels: `settlement_delay_elapsed_at_H`, `outbox_unregistered_at_H`, `execution_attested`, `l1_canonicality_unproven`.

## Minimum acceptance matrix

Cases are obligations, not executed outcomes. Apply each case to the selected
delivery and record the actual source, attempts, exit, completeness and skips.
C15 applies only when its actual host is selected; compilation alone is not acceptance.

| Case | Input or condition | Required result |
| --- | --- | --- |
| C01 | Valid exact selected devnet query | Owned accepted header and actual consumer complete; result cites H/hash/context and typed query. |
| C02 | Wrong chain/genesis/anchor/context/profile or unsupported version | Refuse/reject without accepting state or replacing trusted inputs. |
| C03 | Actual genesis, predecessor-frontier and first-v3 boundaries; inactive and expired coverage | Enforce selected source-derived rules; no v3-from-genesis assumption. |
| C04 | Invalid signature, unknown/unauthorized producer or schedule gap | Reject/refuse; claimed key possession is not elected-producer authority. |
| C05 | Coherent mathematical proof under provider-selected replacement root/header | Cannot replace the owned accepted root/context. |
| C06 | Wrong Settlement address, family, domain, batch, key/path or L1/L2 adapter | Local typed derivation prevents substitution and double hashing. |
| C07 | Absent, stored-zero, present-empty, explicit-delete and excluded domain | Retain the selected adapter/domain distinctions; missing data is never zero. |
| C08 | Noncanonical, malformed/truncated/trailing proof or ABI; unknown schema | Apply explicit canonical policy and strict schema/length rules. |
| C09 | Exact/one-short value/proof/node/work/input limits | Bound before allocation/hash work; no unbounded batch amplification. |
| C10 | Mixed H/root records, H<finalizeAtHeight<=T, stale processed marker | No manufactured current/finality/withdrawal claim. |
| C11 | Wrong gateway commitment fields or valid nested proof for another domain/input/message | Bind all selected row/root/identity relationships, not just one hash. |
| C12 | Pruned/unavailable/timeout/incomplete witness or DA data | Preserve refusal/unknown and actual completion; no absent/zero interpretation. |
| C13 | Saved-state/profile/context migration, restart and downstream failure | Preserve v1/v2 compatibility, immutable ownership, selected provenance and saved progress; no implicit trust renewal. |
| C14 | Wrong process exit, incomplete output or unrelated report channel | Strict consumer refuses; evidence acceptance is not successful process completion. |
| C15 | Browser/WASI uint64, ownership, cap and context parity when supported | Actual selected host matches native semantics; compile-only is not a pass. |

## Gates

| Gate | Needed for | Exit; current state is OPEN |
| --- | --- | --- |
| G0: Scope/source/query selected | D1 | D0 consumer contract and exact source/profile decision pack exist. |
| G1: Conformance and experimental profile | D2 | D1 root/proof/path/applier obligations, actual activation boundary and explicit experimental trust/caps are reviewed and selected. |
| G2: One actual header-bound typed consumer | D4, D5, devnet consumer claim | D2-D3 flow completes with C01-C14 as applicable and actual consumer use; any incomplete agreement/lifecycle limit is explicit. MATH_ONLY remains a useful fallback. |
| G3: Agreed integrated node/profile behavior | supported state-proof profile, production state proofs | N2 integrated identity/recovery and shared protocol/profile rules close for the intended scope; scoped devnet success does not close broader recovery. |
| G4: Representative resource/import/activation budgets | production node/import/resource claims | N1/S1 actual declared workload and liveness/import/retention/activation paths meet budgets; excluded state trust/completeness is explicit. |
| G5: Exact-network activation and real pilot | public-network support | Authenticated network-specific genesis/anchor/profile/activation evidence and one actual qualified consumer pilot. The StateRoot-no-later-than-Offchain rule applies only to the corresponding Zeno state-proof network, not native v1/v2 inclusion. No scheduled mainnet date or upstream merge alone closes this gate. |
| G6: Independent review and authenticated release | production distribution | D6 exact-candidate review and source/binary/report/update/rollback authentication. State-proof production additionally closes G3-G5 and applicable hash decision. |
| G7: Applicable hash/profile decision | corresponding mainnet SMT activation | ZK-R3 inputs and explicit selected hash/format/migration policy; not a blocker for a narrow current-SHA3 devnet experiment. |

## Mapping from the native milestones

M3 now means the first typed accepted-header state query. BatchEntry is the
selected first use; historical balance experiments retain their original labels.

| Milestone | Meaning | New delivery | Status |
| --- | --- | --- | --- |
| M0 | Exact source/candidate and preserved evidence | D0 + D6; G0 and release source bindings | Mechanics have prior scoped evidence; independent acceptance remains open. |
| M1 | Real native v1/v2 consumer | X1 and its actual owner acceptance | Existing operator observations remain supporting evidence; independent pilot open. |
| M2 | Agreement and node identity/recovery | D1 scoped profile + N2/G3, with N1 decision inputs | Scoped devnet selection and broader supported-node qualification are separate. |
| M3 | Accepted-header typed state flow | D2-D3 first BatchEntry; D4 later; optional balance reference | Preparation primitives exist; accepting integration planned. |
| M4 | Representative workload/import | N1 + S1 + G4 | Existing components reusable; representative production exits open. |
| M5 | Scoped reviewed distribution | D6 + G5/G6 and applicable G7 | Separate for native inclusion, devnet preview and production state proof. |

## Estimated first-month windows

| Estimated window | Work | Exit |
| --- | --- | --- |
| 2-8 November 2026 | D0 and D1 scope/conformance/profile intake; early maintainer agreement draft; identify R1 dataset owner and existing CI/evidence dependencies. | One query and exact profile/source decision pack; no mass archive; actual first-v3 boundary is an explicit obligation. |
| 9-15 November 2026 | D2 minimum owned-v3 path and facade/context/persistence compatibility work; keep all native legacy refusals and regression semantics. | Source-bound implementation and actual qualification for selected scope, or clearly labeled incomplete/MATH_ONLY result. |
| 16-22 November 2026 | D3 typed BatchEntry and exact gateway-field comparison; complete targeted identity/proof/ABI/temporal/failure controls. | One selected query under G1/G2, or an honest list of unmet acceptance conditions; no promotion by experimental flag. |
| 23 November-1 December 2026 | One actual consumer adapter/pilot record; review handoff and English upstream proposal draft. Finish bounded X1 work only if it does not delay the main slice. | One demonstrated integration and remaining-gates record. A release, second adopted consumer, public issue or upstream approval is not a calendar requirement. |

The first-month windows are estimates from the 1 November baseline. Carry unmet exits forward; do not manufacture a release, approval or activation to meet a date.

Recommended maximum two active implementation items: one primary Zeno integration item and one small native-consumer, compatibility or coordination item. Node/snapshot/proving work proceeds with its actual owner; this plan does not assume extra staff.

## Engineering and evidence policy

- **CI:** Preserve existing fail-closed source/change scope. Define a fast required lane and source-selected platform/regression/release lanes. Measure wall time, runner-minutes and cache conditions separately; 15 minutes / 80 named steps is not a hard reason to remove guarantees.
- **Evidence:** Reuse completed source-pinned inputs and existing tools. Add qualification work only to close a named defect/gate; never rerun unchanged native tests/transports solely to relabel evidence after local bookkeeping or identity-only history changes.
- **Archive:** No blanket move/delete. Inventory active callers, dependencies and source cohorts first. Any later separately authorized move preserves original records, manifests, hashes, old-to-new mapping, failures and reproducibility references; update callers coherently.
- **Metrics:** Track completed consumer workflows, gate closure, actual defect regression, end-to-end budgets and review findings. Drop product-LOC/commit-touch quotas, unconditional fixture 256 KB and docs 30-line mandates. Use justified size/documentation budgets.
- **Identity and publication:** Future implementation respects repository-local author/committer identity and the pre-push guard; authorized merges are local with the same identity. Public issues/messages, tags/releases and repository migration require their own explicit authorization; this roadmap does not execute them.
- **Storage:** Future downloads, extraction and qualification scratch use the approved owned-task manager with mount identity, explicit quotas and the production free-space floor. Serialize shared-root metadata work; preserve FAILURE/UNKNOWN and original evidence, do not adopt historical data or alter automations.
- **Schedule:** Keep one primary integration item and one small parallel item. Advance a blocked item only when its actual missing input arrives; work on independent conformance/native/data-intake tasks meanwhile. Reassess estimates at each gate rather than promising external approval dates.

This change adopts the planning text only. It does not change repository
instructions, hooks, storage-tool code, module identity, release tags or historical evidence.

## Deferred scope

- Receipt, event, outbox, every Settlement record and all host adapters in the first month.
- Broad WASI support or a long-running sidecar without an actual selected consumer.
- Blanket historical research extraction, cleanup or a new evidence framework before the first typed integration.
- Commitment-domain expansion to mailbox/plasma/frontier without representative measurement, collection semantics, vectors and protocol/version decision.
- R9 schema redesign before its decision; R6 consensus/ETH bridge research on the first-product critical path.
- Public production state proofs, Phase1 Zeno mainnet, trustless full wallet or irreversible settlement claims before their separate gates.

## Owner state-root memo alignment

| Principle | Delivery consequence |
| --- | --- |
| Measure before commitment-domain and production budget decisions | N1 intake starts now; representative counts/churn/build/import/resource results precede domain expansion and production commitments. Existing partial-domain devnet work proceeds without pretending representative data exists. |
| Snapshot and state-root work in parallel | S1 transport/import preparation proceeds beside D1-D3 and N1. Header-bound import acceptance waits for agreed reconstruction/root and node behavior; transport need not await activation. |
| Partial commitment | Balances/storage only remain the selected L1 projection. Plasma/frontier/mailbox and snapshot remainder carry explicit exclusion/trust/completeness rules. Correct frontier namespace and collection semantics are protocol inputs, not a quick predicate change. |
| Activation liveness and recovery | N2/G3/G4 include prebuild/no-prebuild, readiness, snapshot-start, after-activation join, restart and reorg across activation. Production is not enabled by a client-side proof match alone. |
| Digest versus state root | S1 verifies chunk bytes separately and reconstructs the exact agreed typed SMT before comparison with StateRoot from an owned accepted header. |
| Estimates are hypotheses | No 4-7 engineer-month, 2027-Q3 or two-week-build estimate is adopted as a measured commitment. First-month dates are scope estimates and external approvals remain explicit gates. |

## Reviewed correction traceability

The F01-F18 identifiers preserve the proposal review's correction mapping.
Linking an obligation below does not mark its implementation or acceptance complete.

| Finding | Correction | Tracked delivery or criterion |
| --- | --- | --- |
| F01 | The first v3 demo omits prerequisites placed in later phases | D1, D2, D3, G1, G2 |
| F02 | Genesis, first v3 height and spork enforcement are distinct | D1, C03, G5 |
| F03 | Unchanged trie code preserves the retained-identity recovery blocker | N2, G3 |
| F04 | Only the typed committed domain can be interpreted | D1, N1, S1, C06, C07 |
| F05 | Temporal and settlement meanings require separate claims | D3, D4, result_contract, C10 |
| F06 | Use the complete 18-case suite, not18 root comparisons | D1, G1 |
| F07 | Canonical encoding and value bounds are unresolved | D1, C08, C09 |
| F08 | R3 is zkVM work, and a hash switch is a protocol migration | ZK-R3, G7 |
| F09 | Blanket archival would mix active controls with historical cohorts | D0, engineering_policy.archive |
| F10 | Static step count is the wrong acceptance budget | engineering_policy.ci |
| F11 | Module rename, public API and release qualification are separate | D0, D2, D6 |
| F12 | Compilation does not qualify browser or WASI use | D5, C15 |
| F13 | Schema identity needs more than stfSpecHash | D3, D4, D5 |
| F14 | x402 needs a payment policy around inclusion | X1, result_contract |
| F15 | Hard quotas and line-share targets can recreate the wrong incentives | engineering_policy.metrics, delivery_policy |
| F16 | Dates and consumer counts overstate control | first_month, delivery_policy |
| F17 | Commitments do not guarantee witness availability | D4, C12, result_contract |
| F18 | Embedded AGENTS text must not displace current identity and evidence agreements | engineering_policy.identity_and_publication, engineering_policy.archive |

## Source references

| Source | Pinned reference |
| --- | --- |
| main | [Current SPV main](https://github.com/edgepillar/zenon-spv/commit/df1cc52af3ae132a33bf3c41541fcb214eccc0d6) |
| runtime | [Native trust and guarantee contract](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/docs/verification-contract.md#L13-L82) |
| version | [Production v1/v2 version gate](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/internal/chain/header_version.go#L18-L25) |
| roadmap | [Current delivery order, R1 and parallel snapshot preparation](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/docs/native-roadmap.md#L46-L100) |
| ledger | [Qualified runtime baseline and preserved identity migration](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/docs/review-candidate-changes.md#L98-L150) |
| ci_docs | [Documentation-only current-main scope run](https://github.com/edgepillar/zenon-spv/actions/runs/40658702221) |
| ci_runtime | [Selected runtime baseline CI](https://github.com/edgepillar/zenon-spv/actions/runs/40648232108) |
| workflow | [Current workflow and scope gates](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/.github/workflows/ci.yml) |
| module | [Inherited module path and two pinned dependency modules](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/go.mod#L1-L8) |
| readme | [README repair opportunities](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/README.md) |
| mixed_corpus | [A current 9c71 source cohort inside the research directory](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/tools/gen-state-root-vectors/README.md#L2472-L2500) |
| cache | [Current-cohort cache recovery evidence](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/docs/cache-forward-replay.md#L1-L24) |
| smt | [Local value/proof limits](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/internal/proof/candidate_smt.go#L15-L19) |
| canonical | [Canonical observation in the mathematical primitive](https://github.com/edgepillar/zenon-spv/blob/df1cc52af3ae132a33bf3c41541fcb214eccc0d6/internal/proof/candidate_smt.go#L168-L192) |
| root_note | [Informative Zeno state-root note](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/research/state-root.md#L3-L61) |
| spec_status | [Phase 2 outline status](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-2/SPEC.md#L1-L8) |
| r3 | [Actual R3, R6 and R9 questions](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-2/SPEC.md#L129-L139) |
| r3_status | [R3 is not started](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/research/proving/R3-smt-hash.md#L1-L9) |
| vectors | [Serialized inclusion and absence proofs in the 18-case suite](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/artifacts/smt-v1-test-vectors.json#L33-L77) |
| suite | [Normative root/proof/path/applier conformance](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-1/SPEC.md#L912-L919) |
| proof_format | [Canonical zero-sibling encoding](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/artifacts/proof-format.md#L35-L47) |
| hash_contract | [Shared SMT hash and non-SMT commitments](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-1/SPEC.md#L850-L856) |
| phase1 | [Phase 1 executor-attested and testnet-only scope](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-1/SPEC.md#L32-L64) |
| finalization | [Settlement delay semantics](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-1/SPEC.md#L1207-L1214) |
| release | [Outbox relay registration and withdrawal release are separate](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-1/SPEC.md#L1024-L1026) |
| genesis | [Genesis header is v1](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/chain/genesis/momentum.go#L12-L27) |
| spork_exception | [Genesis-frontier spork exception](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/chain/momentum/embedded.go#L152-L169) |
| spork_config | [Selected devnet sporks share height zero](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/docker/devnet/genesis.json#L143-L155) |
| fold | [Actual balance/storage-only projection](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/common/trie/momentum_fold.go#L16-L43) |
| node_store | [Content-addressed node store](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/common/trie/nodestore.go#L16-L31) |
| node_init | [Startup can defer a large tree build](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/chain/state_tree.go#L198-L223) |
| node_background | [Background build driver](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/chain/state_tree.go#L526-L558) |
| node_root | [Retained root selects height](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/common/trie/nodestore.go#L395-L399) |
| node_proof | [Retained proof selects height](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/common/trie/nodestore.go#L998-L1007) |
| node_truncate | [Retained truncate identifier behavior](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/common/trie/nodestore.go#L1275-L1317) |
| node_catchup | [Ahead-tree catch-up behavior](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/chain/state_tree.go#L265-L293) |
| devnet | [Selected four-component devnet pins](https://github.com/Zeno-L2/zeno-devnet/blob/04dc0797f7bcc02e48e0acba3b0ac49df2d3289d/sources.txt#L5-L9) |
| attestation | [Attestations establish build provenance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) |
| da | [Data availability is distinct from commitment](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-1/SPEC.md#L1175-L1203) |
| client | [Client source hooks, root checks and finalized cache](https://github.com/Zeno-L2/zeno-client-ts/blob/e9e02d8b12fa4053b8d19b1a4d6257d933bfdc0a/src/gateway/verify.ts#L14-L177) |
| merkle | [Exact binary Merkle construction](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-1/SPEC.md#L1480-L1507) |
| batch_abi | [Stored BatchEntry ABI](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go#L591-L615) |
| processed | [Processed outbox registration marker](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go#L1579-L1591) |
