# Read-only ledger frontier export

This separate Go module prepares the [R1 inventory](../../docs/state-root-r1-intake.md)
from an **owner-selected, already consistent immutable ledger copy**. It opens
the existing LevelDB through a storage adapter with no filesystem write
operation, obtains one read snapshot and checks the caller's full momentum
height/hash against that same view. It does not launch a node, open a wallet,
import a snapshot, build a state tree or authenticate a header.

The format is explicitly selected as `zenon-9c71-frontier-v1`, based on
[`go-zenon@9c71ae8`](https://github.com/digitalSloth/go-zenon/tree/9c71ae82fc983e16f914ae085d4034030c8ebe3b).
This is a source-pinned storage layout, **not an agreed or activated protocol
profile**. Database dependencies stay in this tool's module; the native
verifier's build list and acceptance rules remain separate.

## Select and retain inputs first

Use a provided consistent export/copy or a separately approved immutable copy.
Do not copy active database files and call them a consistent snapshot. Do not
point this command at an operator's live data. The `--provenance-sha256` argument
references a separately protected selection/consistency record: network/genesis,
full momentum identity, node source/binary/backend, copy method, owners, hardware,
budgets and input-file identity. The tool checks the digest's syntax; it does
not read or authenticate that record or prove the copy is immutable.

The input must be an ordinary physical directory with no symlink ancestors or
nonregular members. Select physical targets when a compatibility path is a
symlink. `LOCK` must already exist. `CURRENT` must contain one canonical
`MANIFEST-N` name and newline; the tool does not repair metadata or choose a
backup. Ambiguous `.ldb`/`.sst` aliases refuse. Directory accounting is capped
at 100,000 entries, a provisional implementation bound rather than a protocol
rule. A writer holding the normal LevelDB lock prevents opening the copy.

The custom storage adapter is necessary because the pinned library's ordinary
filesystem constructor can create a missing `LOCK` even when read-only opening
is requested. This adapter opens existing files for reading, uses the matching
platform lock convention, discards storage log writes and refuses every create,
remove, rename and metadata-write request. It performs no automatic cleanup of
the selected input.

## Capture one completed stream

Build in a declared owned qualification workspace, using the approved task
manager for downloads, cache/scratch and output capture:

```sh
go build -mod=readonly -trimpath -buildvcs=false -o "$R1_EXPORTER" .
```

The following is the foreground measurement command inside that controller.
Its stdout is binary data, not a terminal report:

```sh
"$R1_EXPORTER" --layout zenon-9c71-frontier-v1 \
  --immutable-copy "$R1_LEDGER_COPY" \
  --expect-height "$R1_HEIGHT" --expect-hash "$R1_HASH" \
  --provenance-sha256 "$R1_INTAKE_SHA256"
```

Stream stdout once into protected content-addressed storage with explicit caps.
Retain stderr, actual exit and output completeness separately. Keep the free
space floor, reservations and task quotas before acquisition; avoid another
dump/ZIP/stdout copy. The command itself makes no output file or archive.

Success emits one small JSON record on stderr with
`status: SELECTED_FRONTIER_EXPORTED`. It requires iterator EOF, matching
identifier lookups and iterator content, successful writes and owned store
closure. The controller must additionally check actual exit **0**, complete
capture, output byte count and SHA-256 against that receipt. Matching bytes do
not authenticate their origin or completeness. `--help` exits 0 but emits an
UNKNOWN/non-export receipt; it is not a completed export.

Failures exit nonzero with UNKNOWN and no partial statistics. SIGINT requests
cancellation. If a blocking inherited output descriptor cannot close within
500 ms, the process exits **130**; a completion receipt may be missing or
incomplete. That is UNKNOWN. Preserve the actual prefix/exit and do not inventory
it as a completed dataset. External termination or missing output likewise
remains UNKNOWN. No failure renews selection or trust inputs automatically.

### Reconcile completion, then inventory the retained object

The standard-library Python 3.9+ `consume_completion.py` makes the completion
check explicit. Wait for the managed producer command to finish, then supply
its **actual** process exit, whole-command capture status and captured stdout
byte count/SHA-256 from the controller's protected channel. `complete` means
both stdout and stderr capture completed; never derive it from the producer's
JSON. Select layout, full momentum identity, provenance digest and all resource
caps separately from that JSON. Defaults must match the export command; pass
the same `--max-*` arguments to both tools when overriding them.

```sh
python3 -I -B consume_completion.py \
  --layout zenon-9c71-frontier-v1 \
  --expect-height "$R1_HEIGHT" --expect-hash "$R1_HASH" \
  --provenance-sha256 "$R1_INTAKE_SHA256" \
  --producer-exit "$R1_ACTUAL_EXIT" --capture-status "$R1_CAPTURE_STATUS" \
  --capture-bytes "$R1_CAPTURE_BYTES" --capture-sha256 "$R1_CAPTURE_SHA256" \
  < "$R1_RETAINED_PRODUCER_RECEIPT"
```

This consumer reads at most **16 KiB plus one over-limit detection byte** from
stdin and writes one small JSON result. It opens no database or paths, launches
no children and reads no put-stream bytes. Failed process, incomplete capture
or an over-budget stdout refuses before reading the receipt. It also checks
the exact receipt schema/layout, full selection, equal limits, EOF/closure
success and bounded counter relationships. Unknown fields, authority claims,
duplicate keys, noninteger counters and malformed JSON refuse. The byte/count
checks are consistency checks, not an independent physical-scan measurement.

Require exit **0** and `status: SELECTED_EXPORT_COMPLETION_MATCHED`. `--help`
exits 0 with UNKNOWN and no inventory selection. Failure normally exits 2;
invalid options exit 64, input/output errors 70 and interruption 130. Retain
UNKNOWN attempts and their actual outputs. A missing/truncated producer receipt
cannot be repaired by inferring counters from another run.

The result supplies `inventory_selection` and `inventory_limits`. Through the
same protected controller, pass their byte/count/digest/provenance fields and
four `--max-*` limits to the [independent inventory CLI](../ledger-inventory/README.md),
feeding the **same retained put-stream object** to its stdin. Preserve the
controller receipt, producer receipt, completion result and inventory result
with explicit object references; do not create another dump or archive.
Require `SELECTED_STREAM_INVENTORIED` as well as a successful inventory exit.

The completion result's record count is a producer observation that the
inventory must independently recount from bytes. It is not an independently
selected expectation of correct network state. This consumer does not
authenticate the caller's outer completion channel or provenance record;
substituting fabricated exit/digest arguments is outside its guarantee.
Owner acceptance of ledger origin, snapshot completeness and representativeness
stays in a separate record. Matching completion alone has not executed inventory.

## Exact record space and bounds

The selected view is the physical frontier prefix `55`. Physical empty values
are tombstones and are omitted. A present value is `00 || raw_value`; a lone
`00` therefore exports a **present empty value**. Present 32-byte zero values
remain present. Other existence markers refuse for this selected layout.

The frontier identifier is protobuf `HashHeightProto{HashProto{hash[32]},height}`
with the existence marker, not a flat 40-byte hash/height concatenation. The
expected encoding is locally derived from caller-selected hash/height. Other
encodings refuse for this layout; refusal is not a claim of network invalidity.

Every final present logical key in this frontier is exported in strict byte
order, including logical metadata and unknown namespaces. Physical prefix `55`
and the existence marker are removed. Rollback/patch namespaces and derived
NodeTree records are different inputs. Output is the bare canonical put shape:

```text
01 || minimal_uvarint64(key_length) || key
   || minimal_uvarint64(value_length) || value
```

| Option | Default | Hard cap |
| --- | ---: | ---: |
| `--max-bytes` | 256 MiB | 16 GiB |
| `--max-records` | 2,000,000 | 100,000,000 |
| `--max-scan-bytes` | 256 MiB | 16 GiB |
| `--max-scan-records` | 2,000,000 | 100,000,000 |
| `--max-key-bytes` | 1,024 | 1 MiB |
| `--max-value-bytes` | 1 MiB | 64 MiB |

All are provisional measurement caps. Scan bytes mean the sum of iterator key
and encoded-value lengths, including prefix/marker bytes; they are not measured
physical disk I/O. Tombstones consume scan budgets. Output bytes mean canonical
put-wire bytes. No output write request exceeds 64 KiB. The encoder keeps one
previous key and streams borrowed values without a key/value map.

The backend can read/decompress a block or materialize a value before these
logical checks. Its 4 MiB block-cache setting and 16-entry open-file-cache setting
are not total RSS, allocation, file-descriptor or physical I/O limits. Use the
outer process deadline and independently declared hardware/resource budgets.
No synthetic memory control qualifies a representative node workload.

## Qualification boundaries

```sh
python3 -I -B consume_completion_test.py -v
go test -mod=readonly -count=1 ./...
go vet -mod=readonly ./...
```

The controls exercise literal protobuf/put bytes, tombstones versus present-empty
and zero, budgets, partial writes, changed metadata, errors/panics and release
paths. Real finite closed LevelDB fixtures test snapshot isolation, read-only
file preservation, missing locks and mutation refusal. One ordinary compiled
binary supplies both the completion-to-Python-inventory comparison and the blocked
output interrupt case. CI can supply that binary through
`SPV_LEDGER_EXPORT_TEST_BINARY`; otherwise the package builds one temporary
binary. The 32 MiB value is a prebuilt in-memory fixture, not a large disk file.
Its allocation observation covers the encoder and controlled fake lifecycle;
it excludes fixture construction and is not process RSS.

Completion controls use finite literal wire records and receipts in memory.
The ordinary binary's selected bytes are compared with independently written
literal bytes before the helper's selection is passed to inventory. Reused
producer metadata with failed actual exit, incomplete capture or changed capture
digest must refuse. `SPV_LEDGER_EXPORT_COMPLETION_SCRIPT` can select the source
script in an owned qualification workspace, alongside the existing Python and
inventory-script overrides. No fixture database or export is retained twice.

The dedicated `ledger-export` workflow builds one ordinary executable per
Linux amd64, macOS Intel amd64 and Windows amd64 job. Each job reuses that same
binary for the independent inventory comparison, retains actual test/skip
events in the CI log, and checks its downloaded module cache offline. Each
artifact contains only the binary, a source/run/platform manifest, the MIT
license and dependency notices. The manifest records observed identity and
digests; it is not an authenticated release signature. No ledger fixture or
database dump is archived. The verifier's existing artifact workflow stays
separate.

Windows cannot inject `os.Interrupt` through `os.Process.Signal`, so that finite
control has an explicit skip there. A symlink-creation control can also skip if
the Windows runner cannot create the fixture link; ordinary physical-path and
file-preservation controls still run. Retain the actual skip ledger rather than
claiming those paths executed.

These are controlled storage/transport observations. They do not establish a
real R1 dataset, ledger origin, snapshot completeness, representative budgets,
canonicality, consensus finality, profile/activation agreement, absence proofs,
header authentication, state-value acceptance or reviewed distribution. The
existing production state-value refusal remains in force.
