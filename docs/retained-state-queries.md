# Querying a retained window

Use `--retained-only` to verify content commitments or account segments against
an existing trusted local state without downloading or extending headers.
This is an explicit query mode on `verify-commitment`, `verify-segment`, and
`verify-state-value`. It does not write the state file, including after ACCEPT.

```sh
zenon-spv verify-segment --retained-only \
  --state state.json --genesis-config anchor.json \
  --show-context proof.json
```

`proof.json` uses the existing bundle format, with `headers` empty, null, or
omitted and the relevant commitments/segments present. Its `chain_id` must
match the configured anchor. As with normal trusted resume, `claimed_genesis`
is informational once the saved state's anchor has been checked against the
configured anchor. Supply the same protocol profile and any required producer
schedule used for the query's trust policy.

Known top-level bundle fields must occur at most once. Repeated `headers`,
commitment/segment/proof arrays, or identity fields are parse errors, including
case variants, escaped names, and equivalent Unicode case forms. A later empty
array or null cannot erase earlier evidence. This guard also applies to normal
bundle loading and direct JSON decoding; unambiguous case variants and unrelated
extension fields remain compatible. Successful decoding replaces the object;
failed decoding leaves the existing receiver unchanged.

## Checks and outcomes

The normal bounded loader rechecks the state file's supported layouts, header
hashes and signatures, contiguous links, anchor/profile binding, and applicable
checkpoints. Required producer schedules reauthorize the retained window.
The query then applies the normal membership, account-block, depth, and resource
checks using that state. It cannot authenticate the origin of the local file;
protect its provenance as described in [the verified state API](verified-state-api.md).

| Input or result | Behavior |
| --- | --- |
| Flag omitted or explicitly false | Existing header-extension behavior; empty headers refuse. |
| Flag on `verify-headers`, or no `--state` | Usage error, exit 64, before loading configuration or evidence. |
| Nonempty bundle headers | Usage error, exit 64; supplied headers are never silently ignored. |
| Missing or valid-but-empty state | REFUSED / `ReasonMissingEvidence`, exit 2; no file is created. |
| Corrupt state or anchor/profile mismatch | Load error, exit 70; no proof is evaluated. |
| Missing producer coverage / unauthorized producer | REFUSED / REJECT with the existing reason, exit 2 / 1. |
| Target outside the retained window or lacking strict-past depth | REFUSED with the existing window/depth reason, exit 2. |
| Valid content or account evidence | Bounded ACCEPT, exit 0; state remains unchanged. |
| State-value proof | Still has no accepting implementation. |

Output starts with `retained_state: height=... hash=...` and `state_trust`.
These identify the window and its external assumptions; they are not a new
header-extension ACCEPT. Individual proof results carry their own `Proven`,
`NotProven`, and `TrustAssumptions` fields. Accepted queries retain
`TRUST_CONFIGURED_ANCHOR` and `TRUST_PERSISTED_STATE`, plus any configured
external profile/schedule assumptions. `--show-context` reports the captured
settings without private audit metadata.

## Operational limits

Queries use the file snapshot they loaded and make no RPC calls. The reported
tip does not establish that the snapshot is current, canonical, or final.
Increasing `--window` can cause a previously usable proof to refuse; it does
not recover evicted headers. Account inclusion does not prove a balance or
contract execution. Refresh state separately with verified header extensions
or `watch` when the application needs a later window.

The query does not acquire a writer role or save a truncated window back to
disk. It leaves file bytes, permissions, modification time, and file identity
unchanged. Local file provenance and concurrent state publishers remain the
operator's responsibility; this mode adds no cross-process locking.

Tests use the pinned node-derived contract corpus for accepting commitment and
embedded-account queries, including profile and schedule checks. Negative cases
cover unavailable/empty/corrupt state, invalid mode combinations, supplied headers,
wrong chain/anchor, profile downgrade, producer gaps, insufficient depth,
evicted targets, missing/tampered proofs, evidence budgets, and overwritten header
arrays. A separate decoder fuzz oracle checks aliases against standard decoding
and rejects repeated known fields without partially changing the receiver. Read-only files
and metadata checks ensure both successful and failed queries avoid persistence.
The evidence is synthetic; no public node or VM execution is involved.
