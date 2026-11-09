# Effective ledger inventory

This offline measurement tool reads a **declared effective raw-ledger** export
once, with bounded reads and memory independent of the record count. It prepares
the [R1 intake](../../docs/state-root-r1-intake.md). It does not export a node,
open a database, import a snapshot, construct an SMT or enable state proofs.

The caller must provide a consistent logical view and its separately protected
selection/consistency record. A physical LevelDB dump, patch stream or derived
NodeTree dump is a different input. The existing
[NodeTree codec](../gen-state-root-vectors/raw_kv_roundtrip_codec.py) has its own
purpose and bounds; this tool does not relabel its records as ledger leaves.

## Input and provenance

The measurement input uses bare put records in the goleveldb `Batch.Dump` record
shape, without the journal sequence/count header:

```text
01 || minimal_uvarint64(key_length) || key
   || minimal_uvarint64(value_length) || value
```

Keys must be strictly increasing in byte order and unique. Delete records,
unknown record tags, nonminimal/overflowing lengths, truncation, extra bytes and
selection mismatches refuse. Empty keys are counted separately; they are not
silently omitted or declared invalid protocol state. Empty values remain
present values. This is an inventory of final present records, not an applier
for writes or deletes.

The caller selects the expected byte count, record count and SHA-256 before this
measurement. `--provenance-sha256` references a separately protected R1 intake
record containing the network/genesis, full momentum height/hash, node source
and binary, consistency method, selection ownership, hardware and budgets. The
tool checks the reference's syntax but **does not read or authenticate that
record**. It never copies private paths, addresses, values or provenance text
into the report.

A derived-tree dump can share this record grammar. Neither matching selection
pins nor a caller's domain declaration proves that bytes are a complete,
consistent ledger snapshot. A valid selected prefix can itself be valid input.
The output therefore keeps consistency, snapshot completeness,
representativeness, profile/activation, header authentication and state-value
acceptance false. Owner acceptance belongs in a separate record; do not rewrite
the original inventory to promote its claims.

## Run under the declared qualification policy

Retain the input and provenance record under the approved ownership/retention
policy first. Run the foreground command through the approved task manager with
bounded stdout/stderr and actual exit/completeness capture. Set quotas and keep
the production free-space floor plus expected allocations/reservations before
obtaining a large export. The tool reads stdin and emits a small JSON report; it
does not make a second export, ZIP or directory tree.

The following is the measurement command inside that controller. The variables
refer to independently selected protected inputs, not live database paths:

```sh
python -I -B tools/ledger-inventory/inventory.py \
  --expect-bytes "$R1_LEDGER_BYTES" \
  --expect-records "$R1_LEDGER_RECORDS" \
  --expect-sha256 "$R1_LEDGER_SHA256" \
  --provenance-sha256 "$R1_INTAKE_SHA256" < "$R1_LEDGER_PUT_STREAM"
```

Binary stdin needs a binary-preserving transport. Do not pass a dump through a
text-decoding shell pipeline. A successful process emits one JSON document with
`status: SELECTED_STREAM_INVENTORIED`; this means only the selected ordered
stream matched its declared count/digest and reached EOF. A refused operation
exits 1 with `status: UNKNOWN`, no partial family inventory and a sanitized
reason. Interrupted or missing output remains UNKNOWN in the outer controller.
Retain the actual failed attempt and its input references rather than retrying
an acquisition or overwriting its receipt.

## Provisional measurement bounds

These limits are implementation/measurement caps, **not agreed protocol limits**.
Configure them before execution; the default limits can only be raised as far as
the hard caps below.

| Option | Default | Hard cap |
| --- | ---: | ---: |
| `--max-bytes` | 256 MiB | 16 GiB |
| `--max-records` | 2,000,000 | 100,000,000 |
| `--max-key-bytes` | 1,024 | 1 MiB |
| `--max-value-bytes` | 1 MiB | 64 MiB |

No read request exceeds 64 KiB. A final one-byte EOF probe may read one byte
beyond the selected byte count and then refuse. The retained input memory is
`O(max_key_bytes + 64 KiB)`, plus fixed family/prefix counters and the bounded
report. Values are streamed; all keys, addresses and tokens are not accumulated
in a map or set. JSON output is capped at 128 KiB. These properties do not bound
total process RSS or certify a real node's workload. Input acquisition, CAS
verification, inventory and report handling have distinct I/O/CPU scopes.

The reader amortizes small record fields through a fixed **64 KiB** input
buffer. Each returned buffer is hashed once; parsing and skipped values consume
that buffer without another underlying read or hash update per field. Prefetch
never crosses the selected byte count. A malformed record can consume a bounded
selected prefix before refusal, so the input must remain the separately retained
immutable stream rather than a shared reader whose failure position matters.
The final one-byte read still checks actual EOF or a read error before success.
See the [finite buffering comparison](../../docs/ledger-inventory-buffering.md)
for the unchanged report and resource observations.

## Measurements

Each family reports exact record count, total/minimum/maximum key, raw-value and
put-wire bytes. Put-wire size includes the record tag and minimal length fields;
it is not database allocation, tree size or proof encoding. Histograms contain
exact inclusive `[low, high, count]` power-of-two bins, with a separate zero bin.
Quantiles are explicitly not computed.

The candidate prefix layout distinguishes:

- Exact 32-byte balance keys from other widths under the same balance prefix.
- Contract storage, including actual suffix lengths, from top-level mailbox.
- Exact frontier/plasma key widths from their other-width buckets.
- Account-local receive prefixes `06` and `07`, short account/mailbox prefixes,
  other account tags, the ZNN balance index, empty keys and remaining namespaces.

Unknown top-level and account subprefixes also retain exact counts in two fixed
256-entry counter spaces. No namespace is silently dropped. Classification
records the current candidate layout; it does not settle commitment-domain or
codec decisions.

Each family separately counts present-empty values, raw 32-byte zero values and
values longer than 32 bytes. Values are never truncated or interpreted as token
amounts. Absence, deletes, spendability and excluded-state authentication are not
established. Exact distinct typed-balance address counts use ordering and one
previous address; globally distinct tokens are explicitly not computed.

Keep operational reports private until reviewed for publication. Digest equality
establishes selected-byte integrity, not snapshot origin or acceptance. Churn,
rebuild/import, retention/reorg/reopen, proof service and activation still require
their own complete input identities, actual operations and declared budgets.

## Measure one ordered patch

`churn.py` measures a selected adjacent pair of logical ledger snapshots. The
input combines a small pinned plan, the ordered patch body and the earlier
sorted put stream, in that order. Supply the later snapshot's independently
selected byte count, record count and SHA-256 in the plan. Replay computes
the exact canonical put-stream digest without reading that later snapshot or
writing a derived snapshot file.

The plan uses compact, key-sorted JSON followed by one newline. Select its
exact byte count and SHA-256 independently of the streamed input.

| Field | Required value |
| --- | --- |
| `format` | `zenon-r1-ledger-churn-plan/v1` |
| `record_space` | `effective-raw-ledger` |
| `provenance_sha256` | SHA-256 of the separately protected selection and consistency record |
| `before` and `after` | Objects with `bytes`, `records`, `sha256` and `momentum`. The latter is an object with the full `height` and `hash`. The heights must be adjacent and the hashes distinct. |
| `patch` | Object with exact `bytes`, operation `records` and `sha256` for the selected pair |

The patch is the ordered canonical body of `Batch.Dump` with no journal
header. Put records use the same format as inventory. A Delete is byte `00`,
a minimal uvarint key length and the key bytes. Use the complete effective
patch for the chosen pair, including any metadata writes required by the
selection. The source operator must establish parent linkage, consistency,
and patch completeness separately. [Selected goleveldb batch source](https://github.com/syndtr/goleveldb/blob/2ae1ddf74ef7/leveldb/batch.go)

```bash
set -o pipefail
cat "$R1_CHURN_PLAN_OBJECT" "$R1_PATCH_OBJECT" "$R1_BEFORE_OBJECT" |
  python3 -I -B tools/ledger-inventory/churn.py \
    --plan-bytes "$R1_PLAN_BYTES" --plan-sha256 "$R1_PLAN_SHA256"
```

Use the approved controller and record actual pipeline exits and complete
output. The inspector checks the plan and both input frame digests, strict
base ordering, exact counts and final EOF. It requires the replayed byte
count, record count and SHA-256 to match the selected after pin.

The report gives before and after logical counts, key/value bytes and
canonical put-wire bytes for each family. Operations count inserts, changed
values, unchanged Puts, deletes of present keys and deletes of absent keys.
Repeated-key operations count every operation after the first on that key.
Per-key order is preserved, including Puts of empty values. Prior and supplied
values are compared by length and SHA-256. No raw key or value is emitted.

The default patch bounds are 8 MiB and 32,768 operations. Explicit
`--max-patch-bytes` and `--max-patch-records` can raise them to 64 MiB and
262,144 operations. The earlier and derived snapshots use the existing
inventory bounds. The reader counts transitions after the first operation on
each key while reading the patch. The first operation is classified against
the earlier snapshot during replay. Each touched key retains the first and
latest length/digest summaries and its final value when present. Other base
values are streamed in 64 KiB slices. Python object overhead and transient
field buffers count separately from logical input sizes.

Exit 0 reports `SELECTED_PATCH_REPLAY_MATCHED`. A refusal emits `UNKNOWN`
with a static reason and no partial counts. The selected adjacent pair and
digest match remain separate from authenticated parent linkage, complete
patch provenance, representative measurements and accepted state roots.

### Repeated-key allocation observation

A paired in-memory observation compared the replay at
`a4328650c34413897de6a4eb6203df3889788840` with transition counting on
macOS ARM64 and Python 3.9.6. The repeated-key cases use the regression
fixture's 64 interleaved storage keys and 100 or 800 cycles. The singleton
case uses 16,384 storage keys with one Put each. Half of the keys start with
the value used in the first Put. Every complete report was byte-identical.

| Patch operations | Distinct keys | Previous traced peak | Current traced peak | Previous elapsed | Current elapsed |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 32,064 | 64 | 2,560,660 B | 163,233 B | 82–87 ms | 84–93 ms |
| 256,064 | 64 | 20,638,796 B | 163,289 B | 660–661 ms | 672–676 ms |
| 16,384 | 16,384 | 6,490,650 B | 5,306,234 B | 113–117 ms | 111–113 ms |

The elapsed ranges use three paired samples with tracing off. Input generation
and stream construction are outside both measurements. The cases created no
fixture files. These observations cover finite fixture allocation and latency;
representative R1 memory and throughput require a selected dataset.

## Regression controls

```sh
python -I -B tools/ledger-inventory/inventory_test.py
```

The controls use literal byte records, independent fixture encoding, malformed
streams, fragmented reads, CLI success/failure and mutable-selection cases. A
32 MiB logical value and 65,536 records are generated through bounded readers;
no large fixture file is created. The memory controls assert a small **traced
Python allocation peak during the call**, not a total-process RSS budget or a
representative network measurement.

CI runs the same complete suite on Linux amd64, macOS Intel amd64 and Windows
amd64. Its JSON record lists every attempted/passed test and all three source
digests. `--source-revision` adds the controller-selected revision; that field
alone does not authenticate execution. Native verifier source/binary/report,
independent review and distribution checks remain separate.
Each job uploads that one small JSON record from its existing test invocation;
it does not run a second suite or package a dataset for the inventory artifact.
