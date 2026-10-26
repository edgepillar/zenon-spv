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
amd64. Its JSON record lists every attempted/passed test and the two source
digests. `--source-revision` adds the controller-selected revision; that field
alone does not authenticate execution. Native verifier source/binary/report,
independent review and distribution checks remain separate.
Each job uploads that one small JSON record from its existing test invocation;
it does not run a second suite or package a dataset for the inventory artifact.
