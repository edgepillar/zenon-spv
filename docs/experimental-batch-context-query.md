# Experimental owned three-witness query

This separate version-1 Go API and read-only CLI composes BatchEntry,
domainRecord and domainConfig at one exact owned header height/hash/root.
All full ledger keys are derived locally from the selected Settlement/domain/batch.
A missing, unavailable, noncanonical, absent, oversized or mismatched supporting
witness returns no consumer result. Production `STATE_VALUE_INCLUSION` remains
disabled; D2/D3 selected-network acceptance remains open.

## Explicit contract

`NewExperimentalBatchContextQuery` takes only an opaque `ExperimentalV3State`,
an explicit profile and an independently selected nonzero fingerprint.
Provider roots, diagnostic contexts and retained projections cannot construct it.
The legacy single-row profile, fingerprint namespace and APIs are unchanged.

The profile's exact fields are `version`, `entry`, `domain_rule`,
`domain_record`, `domain_config` and `limits`. Version 1 requires entry profile
version 1 and preserves its original JSON and fingerprint bytes. Explicit
version 2 requires entry profile version 2 with
`source_rule: "zenon-phase1-batch-fields/v1"`; mixed versions are refused.
Both version 2 contexts have separate fingerprint namespace bytes. No request,
provider, header-state or persisted-state schema is changed.
The positive local domain ID, complete legacy header/entry context, both new
schemas, source-rule version and every individual/aggregate work cap enter the
new fingerprint. Canonical encoding and presence are mandatory for all rows.
Source labels and runtime identity metadata do not authenticate runtime execution.

The rule `zenon-phase1-domain-record/v1` requires zero class/runtime/input/
execution/foreign/proposer/finality selectors, one executor, empty profileConfig/
chainBinding, and active or paused status. This local source-mapped subset is
**not all RegisterDomain or SubmitBatch validation**. Build/network-dependent
registration delay bounds remain separate. Version 2 additionally applies the
[BatchEntry source-field subset](experimental-batch-entry-query.md#version-2-source-field-policy)
after all three membership proofs and the bounded BatchEntry ABI decode.
Version 1 retains its ABI-only BatchEntry interpretation. Generic ABI decoding
alone does not establish these source rules or all submission business rules.

DomainConfig is exactly 64 bytes, with two lossless `uint64` delays. Current-H
record/spec/config does not establish submission-time context. Stored finalization
is not required to equal stored submission height plus the current delay.
W depth, Settlement delay, consensus finality, funds release and recipient receive
are separate observations.

`Query` accepts named `ExperimentalBatchContextProofs`; `QueryWitnesses` accepts
named consistency hints. Both bind exact H/hash/context/tip once and take the root
only from the owned header. `ReadCandidateSMTProofSet` preflights per-row and
aggregate work before proof hashing/copies. All proofs and strict ABI decodes must
pass before a detached consumer result is returned. Errors return a zero result.
Provider root/value hints must match; they never select authority.
The three-row API uses a separate required-row absence error and the CLI category
`required_row_absent`. It never returns the legacy single-row `BatchEntry absent`
signal for missing supporting context; no application absence or DTO fallback is
inferred. The legacy single-row API keeps its existing error behavior.

Individual proof/value/opaque-field caps and total proof/value caps must be positive.
Sibling caps are inclusive: zero means no encoded siblings. Config's fixed value
cap is 64 bytes. Individual ceilings are checked before sums on every architecture.
These are local work policies, not accepted network limits.

## Read-only workflow

```text
zenon-spv inspect-experimental-batch-context-config --config <config.json>
zenon-spv query-experimental-batch-context \
  --config <config.json> --request <request.json> \
  --expect-header-context <independently-selected-64-hex> \
  --expect-query-context <independently-selected-64-hex> \
  [--trusted-state <local-checkpoint.json> --expect-state-sha256 <independently-selected-64-hex>] \
  [--compare-gateway] <provider.json>
```

Local config requires `version`, `header_profile`, `header_policy`,
`producer_schedule` and the new `query_profile`. The separate local request
requires `context`, `height`, `header_hash`, `tip_height`, `tip_hash` and `batch_id`.
The provider cannot supply either local document. Inspection returns diagnostics,
never a populated query or typed row.

The provider schema is version 1 with `momentums` and a `witnesses` object
containing exactly `batch_entry`, `domain_record` and `domain_config`. Each witness
has `root` (hex), `value` and `proof` (base64), as in the existing RPC decoder.
Headers must extend the selected anchor and pass the finite profile/schedule,
hash/signature, linkage, retention and depth checks.

Files use the existing regular-file identity reader. Whole config/request/provider
caps are 1 MiB/2 KiB/8 MiB. Each raw witness is capped at 32 KiB; together the three
cannot exceed 96 KiB before decoded proof/value budgets apply. Missing, duplicate,
aliased or null required fields are refused. An unavailable named witness remains
unavailable, never proven absence.

After the descriptor's regular-file identity check, its bounded size is only an
allocation hint. Stable inputs use one byte buffer plus a single overflow-probe
byte; short reads and files that grow or shrink still read to EOF or the byte
cap plus one. A simultaneous data/read error or close failure returns no input.
This applies to both experimental query commands and the three-row command's
checkpoint read. It changes no schema, byte cap, digest, context or trust rule.
The in-memory read controls compare bytes and consumption with the former
bounded `io.ReadAll` behavior. The paired read benchmark measures only buffer
allocation/copying; it does not measure filesystem, JSON, proof or network costs.

Successful output has scope `EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP`,
`persistence: "read_only"`, `rpc_requests: 0` and
`production_state_value_guarantee: false`. Memberships include each full key/path,
raw value and value/proof SHA3-256 digest, typed rows, query identity and header
trust assumptions. Editing/decoding this detached data does not create authority.
Opaque non-UTF-8 executor strings cannot silently become replacement characters.

Exit 0 means the three-row query matched; 1 invalid evidence/identity; 2
unavailable/absent/unsupported evidence or retained scope; 64 invalid arguments;
70 input/configuration/operational/output failure. Error envelopes have no result.

With `--compare-gateway`, the document must also contain `gateway`. Its 17 stored
BatchEntry fields are compared separately. `gateway_comparison.stored_fields_match`
can be false while the historical result stays valid and exit 0. A missing or
malformed requested DTO is an input failure. `isFinalized` remains unauthenticated.
This informational comparison differs explicitly from the legacy command's
required-comparison error behavior.

```text
fetch-bundle experimental-batch-context --rpc <read-only-rpc> \
  --chain-id <n> --anchor-height <n> --anchor-hash <64-hex> \
  --height <n> --header-hash <64-hex> \
  --tip-height <n> --tip-hash <64-hex> \
  --domain-id <positive-u32> --batch-id <u64> \
  [--after-height <saved-tip-height> --after-hash <saved-tip-hash>] [--compare-gateway]
```

By default the collector performs the bounded selected header read, then three
`ledger.getProof(H, fullKey)` reads. Each response has a separate byte cap.
A later failed read emits no partial provider document. Collection does not
authenticate a root or select trust settings from a peer frontier. Neither
command starts a wallet, signs, transacts or deploys.

The optional paired `--after-height` and `--after-hash` select a separate local
continuation point for this command. Keep the original anchor selected. The
collector reads only immediate successors of that point through the exact tip;
the range and byte limits apply to those requested successors. At the exact tip
it makes no header RPC, emits `momentums: []`, and still completes all three
proof reads (plus the optional gateway read) before returning any document.
This also avoids adding one to a tip at the uint64 limit. Missing/repeated or
inconsistent selectors refuse before client creation. Late failure or cancellation
still returns no partial document.
The shared candidate-read helper also checks cancellation before each proof or
gateway request, including the legacy single-row mode. Default/legacy selectors
and provider schemas are preserved.

A continuation selector grants no trust and reads no checkpoint. The collector
checks the links and selected identities present in fetched rows; an older
query header omitted from transport remains unchecked by collection. The offline
query must independently select and verify its trusted local checkpoint, SHA-256
and both context pins, then find the exact query/tip identities in owned state.
A proof-only candidate cannot initialize authority in the default anchor mode.
The legacy single-row command has no continuation flags.

### Pinned read-only checkpoint reuse

The separate [checkpoint export command](experimental-checkpoint-export.md)
can produce the initial local v4 artifact after this same three-row query
matches. It streams the checkpoint to stdout and the consumer/completion report
to stderr. Existing query output and read-only behavior remain unchanged.

Repeated queries may select an existing trusted local experimental state with
both `--trusted-state` and a nonzero `--expect-state-sha256`. Once checkpoint
reuse is requested, missing, empty, repeated or unpaired selectors refuse before
input reads. Header and query
context pins remain mandatory and are checked before the checkpoint or provider.
The checkpoint is never selected by provider JSON or by a default filename.

The regular-file reader caps the state at 8 MiB and reads its bytes once. The
same buffer is SHA-256 checked and strictly decoded through
`DecodePinnedTrustedExperimentalV3State`. Profile/policy/context, retained
header layouts, root-bound hashes, signatures, finite producer authorization and
links are rechecked. A matching digest is content identity, not authentication:
trusted local provenance is still required for evicted ancestry and file origin.
The persisted v4 format and existing trusted file loader are unchanged.

The provider can contain an empty `momentums` array when all query/tip headers
are already retained, or only the bounded immediate successors of the saved tip.
Without the explicit checkpoint pair, an empty header array keeps its existing
refusal. Incorrect/pruned query identity, stale tip, replayed old ranges, invalid
successors or unavailable witnesses never fall back to a provider root or a
different state. No checkpoint is created, updated, migrated or locked for writing.

Checkpoint mode adds a `state_input` report with the selected SHA-256, bounded
byte count, provider-header count and `trusted_local_provenance_required` trust
label. The typed result retains the existing persisted-state trust assumption.
With no successor headers, `headers` is null: no extension outcome is invented.
Default anchor replay omits `state_input` and keeps its prior report/exit behavior.
Forwarded reports and result caches must preserve the checkpoint byte identity
and `header_trust` assumptions: an equal row/query fingerprint does not establish
equal local-file provenance. Detached JSON cannot construct an owned handle.
Digest mismatch is rejection 1 (`state_input/digest_mismatch`); unreadable,
oversized, empty or invalid checkpoints are input error 70. These are not proof
of absence and never produce a partial typed result.

The existing compiled two-command scenario reuses its same builds to compare
full four-header acquisition with two successor headers and a proof-only query.
The retained tail is still rechecked; a zero provider-header count does not mean
zero signature work. These small fixture counts establish reduced replay scope,
not representative network latency, R1 resource budgets or production support.

## Fixtures and qualification boundaries

The selected original node is
`digitalSloth/go-zenon@938fca3b7787da86827a5eb63371509b36e14761`.
[The immutable trace](../internal/testdata/conformance/batch-context-node-witness.json)
contains three original-node inclusions and one absence. Original RootOfLeaves
and CompactTree roots agreed; Python independently reconstructed proof bytes.
The required proofs total 1,781 bytes, with 1,312 bytes of values and five siblings.

These ABI values were **pooled**, not captured from one original ledger snapshot.
The pure node capture started no Chain, wallet, RPC or transaction, and produced
no signed original header. The exact formatted
[harness](../internal/testdata/conformance/batch-context-node-harness.go.txt) and
[inputs](../internal/testdata/conformance/batch-context-node-inputs.json) are
retained. For a separately prepared pinned-node reproduction, install them in
`vm/embedded/definition` as `spv_three_row_test.go` and `spv_three_row_inputs.json`
and select only `TestSPVThreeRowWitnessCapture`. Ordinary CI replays retained
bytes and does not rerun a node.

[The separate unit fixture](../internal/testdata/conformance/batch-context-unit.json)
binds that synthetic root to four public deterministic unit headers on synthetic
chain 9001 at H87–H90. Its finite schedule, H89/tip90 request and fingerprints
have an independent Python encoding oracle.
[The standalone header generator](../internal/testdata/conformance/batch-context-unit-headers.go)
uses a public test-only seed. These are not selected-network signatures,
activation evidence or an executed state transition.

```sh
python3 -I -B tools/gen-state-root-vectors/check_batch_context_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_batch_context.py
go test -race -count=1 -run '^(TestExperimentalCLIRead.*|FuzzExperimentalCLIRead)$' ./cmd/zenon-spv
go test -race -count=1 -run '^TestExperimentalBatchContext' ./internal/verify ./cmd/zenon-spv
go test -count=1 -run '^TestCandidateBatchContext(Collection|Resume)' ./internal/fetch
go test -count=1 -run '^TestExperimentalContextCollectionResumeCLI' ./cmd/fetch-bundle
go test -count=1 -run '^TestCompiledCLIExperimentalBatchContextWorkflow$' ./internal/conformance
```

For a short buffer-only comparison, run `go test -run '^$' -bench
'^BenchmarkExperimentalCLIRead$' -benchtime=3x -count=1 ./cmd/zenon-spv`.
It pairs the previous bounded reader with the opened-size hint at 2 KiB,
1 MiB and 8 MiB. Report the actual Go version/platform, bytes and allocations
per operation; no benchmark result is recorded here by adding the control.

The compiled workflow builds both commands together once, collects only from a
loopback fixture and consumes the typed result. It exercises all three late
collection failures, unavailable contexts and incompatible context/schema pins,
checks production guarantees stay disabled and checks no state file is created.
Checkpoint cases obtain proof-only and successor documents from the real
collector command, preserving the original anchor and comparing zero/one header
requests with the original full-range read. Invalid continuation selectors never
reach the loopback provider; each resumed late-proof failure emits no document.
The source-selected scenario `experimental_batch_context_query` records its
child outcomes and both executed binary digests in the existing offline-pilot
report. It reuses full-suite execution; it adds no second test execution lane.
Unit controls cover per-row/aggregate boundaries, opaque handles, detached values,
canonicality/absence, source-rule narrowing, persistence/pruning and legacy behavior.

The earlier Go 1.25.14 Darwin/arm64 composition qualification, before pinned
checkpoint reuse and collector continuation, passed 33 selected Go roots and 497
subtest pass events with the race detector, three independent Python control
roots, configured golangci-lint 2.6.2, vet and module verification. It finished in
78.9 seconds; the largest workspace observed after a phase was 527,327,425 bytes
under a 1 GiB task limit. This is not a continuously sampled peak. The owned
temporary source/module/build workspace was removed; evidence stayed protected.
Before the required-row error refinement, the synthetic three-row query measured approximately 134 microseconds, 3,040
allocated bytes and 24 allocations per operation in one short local benchmark.
That short benchmark was retained without reexecution. These are local
implementation observations, not network/device acceptance limits.
An earlier fixture used raw hex for the RPC producer instead of Bech32; its
failed CLI evidence was retained. The corrected wire encoding reuses unchanged
header signatures, fingerprints and original-node proofs.

A real selected-chain H2/H3 boundary, independently selected trust inputs and
matching live/captured query, representative R1 ledger data, independent review
and authenticated distribution remain external gates.
