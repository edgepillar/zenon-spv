# Read-only experimental BatchEntry CLI

The existing `zenon-spv` binary has two explicitly experimental offline commands:

```text
zenon-spv inspect-experimental-batch-config --config config.json
zenon-spv query-experimental-batch-entry --config config.json --request request.json \
  --expect-header-context <reviewed-header-pin> \
  --expect-query-context <reviewed-query-pin> [--compare-gateway] bundle.json
```

Both emit one versioned JSON document. They make no RPC requests, acquire no
state writer lock and write no state, configuration or report files. They do
not initiate wallets, signing, transactions or a live deployment. Production
`verify-state-value`, native v1/v2 profiles and their guarantee rules are separate.

The separate [`fetch-bundle experimental-batch-entry` collection mode](experimental-batch-entry-collection.md)
can acquire a bounded provider document using explicit local selectors. Its
success grants no header or proof authority; these offline commands still
require independent configuration, request and expected context pins.

This is a functional experimental consumer seam. The recorded workflow retains
its incompatible-witness control and now includes a
[matching original-node fixture](recorded-batch-entry-witness.md), with the
same two fresh executables reused for collection and the successful typed query.
A matching positive BatchEntry witness on the independently selected network
is still missing. This command does not close D0-D3 or a release gate.

## Inputs and independent selection

Configuration, request and provider data are deliberately separate inputs.
The operator must select the trust start, profiles, finite schedule, runtime
identity, local query and limits independently of the witness provider. Matching
computed fingerprints do not authenticate that selection or network activation.

`config.json` is an exact schema-1 object with these required fields:

| Field | Meaning |
| --- | --- |
| `version` | Numeric 1 |
| `header_profile` | Complete `ExperimentalV3Profile`: non-mainnet genesis, anchor, first-v3 boundary, finite coverage, selected node pin and provenance label |
| `header_policy` | Explicit positive W, retained capacity and maximum batch headers |
| `producer_schedule` | Explicit substantive schedule fields, coverage/entries and matching schedule hash; audit metadata remains external provenance |
| `query_profile` | Complete `ExperimentalBatchEntryProfile`: fixed selected Settlement/schema, local domain/runtime identity and every proof/ABI/string limit |

The [header mechanics](experimental-v3-owned-state.md) and
[typed-query contract](experimental-batch-entry-query.md) specify those schemas.
There is no default mainnet anchor, inferred activation, implicit producer
schedule or environment-based trust selection for these commands.

Inspection validates this configuration and returns `header_context` and
`query_context`, including their fingerprints. Its status is `inspected`,
scope is `EXPERIMENTAL_CONFIGURATION_DIAGNOSTIC`, and both `headers` and
`result` are null. It reads no request or provider bundle and accepts no header.
Review the complete settings and external provenance before selecting the two
expected pins for a query; inspection never automatically initiates one.

`request.json` is a separate exact object containing `context`, `height`,
`header_hash`, `tip_height`, `tip_hash` and `batch_id`. Its context must equal
the independently selected typed-query pin. Heights, hashes and the local batch
are not learned from the provider bundle. Hashes in this document use canonical
lowercase hex; full-width uint64 values remain integers throughout the native
decoder. No JavaScript number conversion is involved.

The provider bundle requires numeric `version: 1`, a `momentums` array and a
`witness` object with the exact `root`, `value` and `proof` fields. Each momentum
row uses the exact selected-node
[raw v3 RPC projection](candidate-v3-rpc.md), in contiguous order from the
configured anchor. No caller-built raw retained state or separately supplied
verification root is accepted. The bounded whole batch must authenticate
before the query handle is constructed.

With `--compare-gateway`, the bundle must additionally contain `gateway`, the
exact `embedded.settlement.getBatch` result object. Without that flag the field
is rejected rather than ignored. The selected IDs and all 17 stored fields are
compared after proof verification. Its `isFinalized` remains an unauthenticated
frontier hint; it cannot override proof failure or become a fact at H.

## Bounds, reads and outcomes

| Input | Complete local document cap |
| --- | ---: |
| Configuration | 1 MiB |
| Local request | 2 KiB |
| Provider bundle | 8 MiB |
| Witness or gateway result object | 32 KiB each |
| Producer entries or coverage rows | At most 4,096 each, checked before the larger native schedule decoder |
| Momentums | Explicit header-policy maximum, at most 4,096; existing per-row RPC bounds also apply |

These are local unsupported-data limits. The underlying profile also binds
the 4 KiB value ceiling, proof/sibling caps and all three individual/cumulative
dynamic ABI limits. They are not node protocol limits or representative hardware
measurements. Complete file caps include whitespace and growth during reading.
Regular files are required before and after open, with matching identity;
the selected identity is resolved before opening, including Windows' lazy
file-ID lookup. A same-path replacement with equal size and bytes is refused.
Final symlinks are refused. Linux/macOS open nonblocking and without following
a final symlink. Native FIFO replacement behavior is qualified only on those
platforms. File checks do not authenticate its provenance or defend a hostile
same-user writer changing regular bytes in place.

Unknown, missing, duplicate, case-alias and forbidden null fields refuse. A null
witness/gateway result is unavailable, not typed absence or zero. Both required
nonzero context pins, all unique selectors and invocation shape are checked
before any input file is read. Configuration pins are compared before request
or provider input; request context is checked before the provider bundle.

| Exit | JSON status | Interpretation |
| --- | --- | --- |
| 0 | `inspected` | Configuration diagnostics only; no header or row accepted |
| 0 | `matched` | A typed row matched the configured owned header under the experimental scope |
| 1 | `rejected` | Header authentication rejection, owned query-identity mismatch, invalid witness/value or required gateway comparison |
| 2 | `refused` | Unavailable input result, outside retained/depth scope, unsupported proof/ABI bounds or no typed value |
| 64 | `error` | Invalid invocation; no input processing |
| 70 | `error` | Setup/input/operational/encoding failure; no typed result |

Every failure has `result: null`. Reports omit supplied file paths and private
Source/peer labels. A successful query has
`EXPERIMENTAL_CONFIGURED_HEADER_MEMBERSHIP` scope, not production
`STATE_VALUE_INCLUSION`. All reports keep `production_state_value_guarantee`
false, `rpc_requests` zero and `persistence` equal to `read_only`. Header outcomes
describe only their own authentication stage. Consumers must check the actual
process exit, report status/scope and complete output. A selected
`gateway_comparison_required` also requires the successful result's gateway
comparison; an ordinary proof result must not be promoted into that claim.

JSON output refuses lossy conversion of opaque non-UTF-8 ABI strings. It emits
an encoding error with no row. A short/failed output write exits 70 and is not
retried; partial output is unusable even if it includes an earlier success
field. The usual selected UTF-8 policy is appropriate for this JSON consumer.

The command does not infer canonicality, consensus finality, STF correctness,
Settlement-delay satisfaction, funds release, recipient receive, spendability,
freshness or witness availability. The [selected-network gates](typed-state-roadmap.md)
remain open; the chain-100 fixture is not a chain-69 activation capture.
