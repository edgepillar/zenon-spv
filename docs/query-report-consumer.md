# Reference query-report consumer

`tools/consume-query-report` matches a complete local query diagnostic against
independently selected expectations. It supports `verify-commitment` and
`verify-segment` in retained-only mode. It reads two regular files and writes
one fixed JSON summary; it makes no RPC requests, invokes no subprocess, and
does not load or write verifier state.

This is a reference for a read-only integration, not a signed receipt, public
SDK, or real consumer pilot. The caller must trust the local verifier executable,
capture its actual process status, and preserve the integrity of the report and
expectations files. An attacker who can replace these inputs can fabricate a
matching diagnostic. Neither the context digest nor this tool authenticates
the report, anchor, saved history, activation, schedule, peer selection, or
network freshness. Real consumer selection and independently authenticated
trust inputs remain external gates.

## Independent expectations

Prepare a private schema-1 expectations file before consuming the candidate
report. Select the command, approved context fingerprint, intended verification
tip, and the entire target batch independently. Use the previously approved
configuration pin and explicitly selected target identities; do not copy these
values from the candidate report or regenerate a pin to make a mismatch pass.

This template illustrates the fields. Replace every placeholder and illustrative
height with independently justified values; it is not an executable trust preset.

```json
{
  "schema_version": 1,
  "command": "verify-segment",
  "context_fingerprint": "<approved lowercase 64-hex fingerprint>",
  "verification_tip": {
    "hash": "<independently selected lowercase 64-hex tip hash>",
    "height": 10000
  },
  "targets": [{
    "scope": "segment",
    "index": 0,
    "block_index": 0,
    "account_header": {
      "address": "<selected lowercase 40-hex raw address>",
      "height": 42,
      "hash": "<selected lowercase 64-hex account-block hash>"
    }
  }],
  "required_guarantees": ["CONTENT_INCLUSION"],
  "allowed_trust_assumptions": [
    "TRUST_CONFIGURED_ANCHOR",
    "TRUST_PERSISTED_STATE",
    "TRUST_EXTERNAL_PROTOCOL_PROFILE",
    "TRUST_EXTERNAL_PRODUCER_SCHEDULE",
    "TRUST_RETAINED_WINDOW_DEPTH"
  ]
}
```

For commitments, use `command: "verify-commitment"`, `scope: "commitment"`,
the zero-based commitment `index`, and `momentum_height`; omit `block_index`.
For segments, include the zero-based segment `index` and `block_index`; omit
`momentum_height`. Account identity always includes address, height and hash.
Index zero is required explicitly. Heights and other unsigned integers are
decoded as `uint64`, including values above JavaScript's exact number range.

Expectations must contain 1..256 targets with unique input positions. Every
report row must match one entire expected reference, with no missing or extra
rows. Row order may differ. Each row must be `ACCEPT` with `ReasonOK`, and its
`failed_at` must be `-1` for commitments or the block index for segments, as
specified by the existing verifier report. The latter is an underlying result
index, not a failure indication on accepted segment rows.

The required guarantee set must include `CONTENT_INCLUSION`. It may also
request `HEADER_CHAIN_INTEGRITY`, `SIGNATURE_AUTHENTICITY`, or
`PRODUCER_AUTHORIZATION`, but every requested guarantee must be present in
each matching row's own `proven` array. Current inclusion rows do not establish
all those extra guarantees: requesting one they lack refuses the match. The
consumer never combines header or unrelated row guarantees, or promotes a
`not_proven` value. It refuses requests for `CANONICALITY`, `STATE_TRANSITION`
and `STATE_VALUE_INCLUSION`.

All reported state and per-row trust assumptions must be known and explicitly
allowed. Retained queries must report configured-anchor and persisted-state
trust at both levels. Omit assumptions the consumer is unwilling to accept;
the illustrative allowance list above is not a security recommendation. The
complete vocabulary is in [the verification contract](verification-contract.md).

## Capture completion, then consume

Build the reference tool and the verifier from the reviewed source candidate.
Capture the verifier's exit status immediately, including nonzero status or a
signal exit. Do not use the report's internal `exit_code` as the process status.
The status flag is mandatory even for zero. Any nonzero signed 64-bit status,
including Windows exception codes or a process API's negative signal status,
refuses the match before reading the files.
A Bash example uses `PRIVATE`, `PRIVATE_RUN` and `COMMON` from the operator
workflow. Keep the independently prepared expectations outside the candidate
report's output file:

```sh
go build -trimpath -o "$PRIVATE_RUN/consume-query-report" ./tools/consume-query-report
go build -trimpath -o "$PRIVATE_RUN/zenon-spv" ./cmd/zenon-spv

verifier_status=0
"$PRIVATE_RUN/zenon-spv" verify-segment "${COMMON[@]}" --json --retained-only \
  "$PRIVATE_RUN/candidate.json" > "$PRIVATE_RUN/query.json" 2> "$PRIVATE_RUN/query.stderr" \
  || verifier_status=$?
printf '%s\n' "$verifier_status" > "$PRIVATE_RUN/query.exit"
"$PRIVATE_RUN/consume-query-report" --report "$PRIVATE_RUN/query.json" \
  --expectations "$PRIVATE/expectations.json" --verifier-exit-code "$verifier_status"
```

`COMMON` must include the independently approved trust files, saved state and
`--expect-context` pin, as in [the operator workflow](operator-pilot.md).
If using its `record` helper, pass the recorded query exit status without
replacing a nonzero value. On Windows, capture `$LASTEXITCODE` immediately and
preserve native UTF-8 report bytes using the caller's process API. Do not feed
UTF-16 or BOM-prefixed shell output to this strict JSON consumer.

Successful output and process exit zero are:

```json
{"schema_version":1,"status":"matched","category":null,"checked_targets":1}
```

Process failure, invalid input or any mismatch produces `status: "not_matched"`,
a fixed category, and `checked_targets: 0`; no partial match is reported. Exit
2 means no match, 64 means invalid invocation, and 70 means an input/output
operation failed. Check the consumer's actual exit status too: an output error
can leave a partial summary. The summary omits references, chain identities,
fingerprints, file paths, raw errors and private report caveats. The input
files still contain sensitive query and trust information and remain private.

## Parsing and evidence limits

Matching requires report schema 1, the expected command, `retained_only`, actual
verifier exit zero, internal exit zero, `error: null`, `persistence: "read_only"`,
and a supported context schema 1 or 2. The consumer independently recomputes
the context digest using the published binary encoding and compares it with
the expected pin. It also requires the exact expected tip hash and height;
that comparison is not a canonicality or freshness test.

The parser refuses unknown, case-aliased, missing and duplicate keys, null
required values/arrays, conflicting guarantee sets, unknown trust names,
noncanonical hex, floating/exponent numbers, integer overflow and extra JSON
values. Nullable fields follow the documented report schema. It bounds input
to 4 MiB per report and 256 KiB per expectations file, nesting to 16 levels,
values to 16,384, each array/object to 256 entries, strings to 4,096 bytes and
object keys to 128 bytes. Inputs must be regular files, not directories or
symlinks. These are input bounds, not a total process heap or RSS guarantee;
stable private file ownership remains the caller's responsibility.

Unit tests cover full-width integers, ambiguous JSON, published context
fingerprints and fixed private output. A compiled node-corpus workflow covers
commitments and flattened segments, explicit retention, reordered rows,
actual process failure, and target/guarantee/trust mismatches. Mutated diagnostics
test consumption only. Native offline CI establishes bounded synthetic
compatibility; it does not select a real consumer, authenticate trust inputs,
prove finality or state values, or perform a network pilot.
