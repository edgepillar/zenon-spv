# R1: representative state inventory and measurement intake

Status: collection procedure and acceptance inputs, **not a collected dataset**.
R1 is the representative inventory needed by M2/M4 in the
[native roadmap](native-roadmap.md). The existing
[candidate commitment contract](state-root-candidate-contract.md), v3 codec and
bounded proof primitive remain the starting point. This procedure does not
choose a protocol profile or enable state values.

The separate [read-only frontier exporter](../tools/ledger-export/README.md)
can prepare that stream from an owner-selected consistent immutable LevelDB
copy using the explicitly selected node storage layout and full momentum
height/hash. Its write-free storage adapter does not launch a node or make the
copy consistent. A completed export still needs the provenance, independent
selection and representative-data assessment below. No real dataset is supplied
by the controlled fixtures.

The [bounded effective ledger inventory tool](../tools/ledger-inventory/README.md)
can inspect a separately selected ordered put stream without keeping a key map
or copying the export. It checks selection pins, reports prefix/size counts and
reports explicit UNKNOWN/refusal boundaries. It does not establish the stream's
ledger domain, consistency, snapshot completeness or representativeness; the
real node/export and acceptance inputs below remain necessary.

## Declare the sample before collection

The node/operator and consumer owners must select and record:

1. Network, chain/genesis identity, exact momentum height **and hash**, and the
   independent source or declared operator trust for that selection. A testnet
   experiment can use one operator; its results cannot claim independent network
   acceptance merely because several RPC replies agree.
2. Node commit/tree, applied patch identity, build command, binary digest,
   toolchain, database backend/version and export/read-view format. Keep the
   original raw-ledger view distinct from derived trie nodes and version metadata.
3. A complete, consistent raw-ledger snapshot/export identity, digest, byte count
   and actual completion record. Select a finite height range and sampling rule
   separately for churn; a patch stream is not a complete state inventory.
4. CPU model/core limit, RAM, storage type, free-space floor, concurrency, retained
   window, import/rebuild/query deadlines, and byte/I/O/network budgets. Specify
   each measurement's accounting scope and rejection threshold before execution.
5. The intended consumer operation and load: typed balance proof, transport,
   import or recovery. Declare key/value/proof limits as provisional measurement
   bounds until the protocol owners accept them.

Use an owner-provided consistent export/read view, or a separately approved
immutable copy with known consistency. Do not open a live writable database or
copy active files as though they were a consistent snapshot. Keep raw data,
endpoints and operational identifiers private. Public findings can refer to
sanitized source, snapshot and report digests without publishing private paths.

Use registered disposable scratch and protected input/report references through
the approved task-storage manager. Set allocation/task quotas in advance and
retain the production free-space floor plus reservations. Preserve each actual
failed or interrupted attempt; label incomplete output UNKNOWN. Reuse verified
inputs and small manifest references instead of making another dataset archive.

## Inventory the effective raw keys

Count distinct final keys in the consistent logical ledger view. Do not count
physical LevelDB records, internal trie nodes, repeated writes or version metadata
as distinct balance leaves. Record the following families separately, with
unknown prefixes and malformed widths in their own buckets:

| Raw family | Inventory treatment |
| --- | --- |
| `03 || address[20] || 03 || token[10]` | Exact 32-byte typed balance keys; count tokens/addresses under the declared sampling/privacy policy. |
| Balance-prefixed keys of other lengths | Separate bucket; the candidate fold's minimum 22-byte prefix check is wider than the typed balance query. |
| `03 || address[20] || 04 || storage_key` | Candidate committed contract storage; record actual suffix lengths and payload sizes. |
| `03 || address[20] || 05` | Excluded plasma state; inventory but do not authenticate it from a balance proof. |
| `03 || address[20] || 00` | Excluded account frontier identifier. Account-local `06`/`07` receive indexes are separate families. |
| Top-level `04 || address[20] || ...` | Excluded mailbox/pending-send state. |
| Top-level `08 || ...` | Excluded ZNN balance index. |
| Remaining namespaces | Preserve counts, size distributions and classification uncertainty; never silently drop them. |

Record count, total key/raw-value/encoded bytes, minima/maxima, declared size
buckets and the quantile method for each family. State whether encoded size
means export wire bytes, proof encoding, logical tree bytes or physical database
allocation. Those quantities are not interchangeable.

Keep a present 32-byte zero balance, a raw present-empty value, an absent key and
an explicit delete distinct. The candidate L1 applier turns an empty Put into a
delete; the generic SMT's present-empty behavior is a different operation.
Record values above 32 bytes without truncation and leave the protocol value
range unresolved until independently specified.

For churn, bind every ordered patch to its complete momentum identifier. Count
inserts, changed values, deletes, unchanged writes and duplicate keys separately,
with before/after cardinality and byte totals. Record missing ranges, replay order
and patch completeness. A few chosen keys or a genesis export cannot establish
representative network churn.

## Measure the declared pipeline, then decide

| Measurement | Required evidence and limit |
| --- | --- |
| Inventory | Actual completion and complete input identity, per-family logical counts/bytes, exclusions and consistency method. |
| Rebuild | Fresh derived tree from the declared projection; wall/CPU time, scoped allocations/RSS, I/O, peak logical and allocated disk, reconstructed root and actual exit. |
| Transport/import | Exact manifest/chunk digests and byte caps, complete reconstruction, rejected/incomplete chunks and interruption/restart behavior. |
| Retention/reorg/reopen | Full height/hash binding, retained/pruned versions, declared depth/window, rollback and fresh-process recovery, including rejected wrong identifiers. |
| Proof service | Selected key distribution, request/proof/batch byte caps, concurrency, latency and memory accounting; actual errors and refusals. |
| Activation | Separately accepted profile and authenticated activation inputs, then pre/boundary/post behavior on the selected node. Inventory alone cannot qualify this row. |

Retain actual commands, inputs, exits and measurement boundaries. Process-lifetime
RSS cannot be labeled an isolated operation's allocation; a component timing
cannot be labeled whole-pipeline latency. A cached/replayed result is not a fresh
native run. Synthetic fixtures and the existing 19,257 source-genesis leaves or
16,384 selected proof pairs retain their narrower provenance.

A transport/chunk SHA-256 proves the selected bytes arrived intact; it is not the
SMT root. Rebuild the exact agreed projection first. Compare its root with the
owned accepted header/context only after the profile and authority gates pass.
Excluded plasma/frontier/mailbox/index state needs its own trusted or derived
provenance for a usable snapshot; the partial root cannot authenticate it or
establish spendability.

Snapshot framing, caps, consistency and import interruption work may proceed
before root activation with explicit trust. Keep that delivery separate from
authenticated root admission. Likewise, ordinary read/Stop observations that
remain INCONCLUSIVE do not become passing by replaying their records.

## Minimal intake record

This illustrative record declares missing inputs. It is not output from an
implemented exporter or proof of collection. Fill the nullable fields from the
selected real operation, retain source-bound reports for every attempt, and
record the owners' actual decisions separately.

```json
{
  "status": "INPUTS_REQUIRED",
  "network_genesis_identity": null,
  "momentum": {"height": null, "hash": null},
  "node": {"revision": null, "tree": null, "binary_sha256": null},
  "raw_export": {"format": null, "sha256": null, "bytes": null, "complete": false},
  "selection_and_consistency_provenance": null,
  "churn_range_and_sample_rule": null,
  "hardware_and_accounting_scope": null,
  "limits_and_thresholds": null,
  "protected_report_references": [],
  "representative_dataset_accepted": false,
  "profile_agreed": false,
  "activation_authenticated": false,
  "state_value_acceptance_enabled": false
}
```

R1 is ready for decision only when the declared dataset is complete and its
representativeness, accounting and provenance have been assessed. Report which
domain, encoding, retention and resource decisions the measurements support and
which remain open. Keep M2 agreement, M3 accepted-header flow, M4 workload
qualification and M5 independent review/distribution as separate exits. No
calendar estimate or successful CI run substitutes for those decisions.
