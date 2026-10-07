# Consume a complete observer diagnostic

`tools/consume-observer-report.py` checks a completed [block observer](block-observer.md)
diagnostic using an actual outer process exit, independently selected target count
and explicit `local-file` or `collected` mode. It reads bounded binary stdin and
prints one fixed schema 1 summary. It never launches a child, opens report paths,
loads state, selects a peer/trust input, retries or verifies a chain proof.

Use an explicit reviewed Python 3.9+ interpreter and reader source. Keep both
protected, together with the observer binaries, inputs, expected identities and
report channel. Source hashes do not authenticate release distribution.

## Preserve process completion before reading the report

Select mode and target count from the intended invocation and its independently
selected expectations before executing the observer. Capture stdout bytes and
the actual observer status from the same process; wait for that process to finish.
Do not extract the outer status from JSON, substitute a successful previous
report or set expected count from `checked_targets` in the candidate diagnostic.

For a protected completed local-file report, after the observer has settled:

```bash
"$PYTHON" -I -B "$OBSERVER_READER" \
  --mode local-file --expected-targets "$EXPECTED_TARGETS" \
  --observer-exit-code "$observer_status" \
  < "$RECORDS/observer.json" > "$RECORDS/observer-consumption.json"
reader_status=$?
```

`PYTHON`, `OBSERVER_READER`, `EXPECTED_TARGETS`, `RECORDS` and `observer_status`
are explicit caller selections/records. Keep the actual reader status as well;
stdout that looks successful cannot override a nonzero exit. Native process APIs
should supply the completed UTF-8 stdout bytes directly without a shell text
conversion. The shell example does not qualify Windows/Git Bash execution.

Stdin has a 16 KiB bound plus one overflow probe; short reads continue until EOF.
Parsing occurs only after EOF, so a read failure or trailing document cannot
promote a complete-looking prefix. The reader has no I/O deadline or process-tree
supervision. A producer that never closes its stream can still block; supply a
protected completed report or supervise the stream separately. Opening a selected
file through shell redirection remains the caller's protected-file responsibility.

## Match the selected mode and complete shape

| Selection or field | Required matched diagnostic |
| --- | --- |
| Actual observer exit | Integer zero provided separately by the caller. Nonzero exits refuse before stdin is read. |
| `--mode local-file` | Schema 1 with the exact seven outer fields and only verifier/consumer observations. |
| `--mode collected` | Schema 2 with the same fields plus a required collector observation. |
| `checked_targets` | An integer in 1..256 equal to the independently selected expected count. |
| `status`, `category` | `matched` and null. |
| Each child | Exact `exit_code`, `elapsed_ns`, `stdout_bytes`, `stderr_bytes` fields; reported integer exit zero, not null or a Boolean. |
| Time/count metadata | Lossless nonnegative signed 64-bit integers. Zero clock ticks are allowed. |
| Successful child stdout | Positive and within the existing observer caps: verifier 4 MiB, consumer 1024 bytes, collector 64 MiB. |
| Child stderr count | Nonnegative and at most 16 KiB. Raw diagnostics are never echoed. |

The decoder rejects duplicate fields, including escaped aliases, unknown or
missing fields, wrong types, floating/nonfinite numbers, invalid UTF-8, oversized
integers/documents, partial JSON and trailing documents. Object key order and
ordinary JSON whitespace may differ. A collected diagnostic cannot be silently
treated as a local-file diagnostic by omitting the collector field.

Success produces:

```json
{"schema_version":1,"status":"matched","category":null,"checked_targets":6}
```

Exit 0 requires that complete result and actual reader success. Exit 2 produces
`not_matched`, zero checked targets and one of `process_failure`, `invalid_report`
or `report_mismatch`. Exit 64 means invalid, missing or repeated selections and
prints a fixed usage diagnostic without reading stdin. Input/output failure is
nonzero (normally 70); interrupted reading returns 130 and `cancelled`. A partial
or successful-looking stdout from any failed reader is not a match.

The observer's elapsed/counter values are diagnostics, not authenticated resource
measurements. Matching count does not establish target identity, context, tip or
trust provenance: those fields are absent from the outer report. The existing
[query consumer](query-report-consumer.md) still performs those checks against
independent expectations inside the observer. An unrelated report with the same
count is indistinguishable here unless the caller protects/binds the invocation
and report channel. Canonicality/finality, election/activation authentication and
state-value proofs remain separate gates.

The reader result is also separate from the [private staging sampler](private-staging-observations.md)
and [post-exit empty-root check](consumer-resource-observation.md). It does not
prove cleanup, peak/physical storage, sustainable arrival rate or a consumer SLA.

## Offline qualification

```bash
"$PYTHON" -I -B tools/consume-observer-report_test.py
"$PYTHON" -I -B tools/check-observer-report-consumer_test.py
"$PYTHON" -I -B tools/check-observer-report-consumer.py \
  --observer "$OBSERVE" --verifier "$SPV" --consumer "$CONSUME" \
  --collector "$FETCH" --source-revision "$SOURCE_REVISION"
```

The qualification helper freezes expectations and the existing pinned
node-generated delayed-inclusion corpus before children run. It creates a
synthetic local saved state, then performs 12 ordinary observer invocations over
both commands and both modes: matched, wrong-target and context-pin refusals.
Collection contacts only an owned joined loopback fixture returning unmodified
node-generated envelopes. Thirty-six reader decisions additionally check changed
outer status, expected count, mode and incomplete output. All input/state bytes
remain fixed after seeding and staging roots return to empty.

CI runs controls and actual diagnostic consumption on Linux, Intel macOS and
Windows using the existing exported candidate binaries. Qualification output
records reader/source/executable byte pins and every comparison; the source
revision remains caller asserted. A later failure retains the recorded completed
or uncertain subprocess outcomes with actual exits and stdout/stderr byte hashes.
Malformed, truncated, invalid-UTF-8 or overnested completed child JSON retains
that ledger too. Invalid seed metadata (including a Boolean or floating exit
code) refuses at `seed_report`; invalid reader JSON refuses at `reader_summary`.
Those refusals preserve earlier completed outcomes without echoing raw private
output or treating a successful child process exit as qualification success.
Raw private diagnostics are not printed. Actual fixture/process failures stop the run
without claiming qualification or automatically retrying. This is offline
interoperability with synthetic trust selections, not a live network pilot,
independent review or authenticated distribution. Candidate artifact checks bind
the native report's four ordinary executables to the exported payloads separately.
