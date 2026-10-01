# Read-only operator pilot

This workflow connects the shipped commands into a bounded native-client
experiment: select trust inputs, record settings, initialize state, advance
and restart watch, collect account evidence, and query a retained window.
Network operations are read-only. Local state and report files are written;
there is no wallet, signing, transaction submission, or balance-proof step.

Executable conformance cases are `TestCompiledPinnedOperatorWorkflow` for
trust-input pinning and `TestCompiledRetentionDepthWorkflow` for explicit K.
Run it without public-network access using cached Go dependencies:

```sh
go test -count=1 -run '^TestCompiledPinnedOperatorWorkflow$' ./internal/conformance
go run ./tools/offline-pilot > ../offline-pilot.json
```

The [offline report](offline-pilot.md) records exact source inputs, tested
binary hashes, scenarios, and skips on native Linux, macOS, and Windows CI.
That is synthetic integration evidence. The following operator procedure
still requires independently selected network trust inputs.

## Prepare inputs and records

Use a protected local directory whose state and companion lock files other
users cannot replace. Preserve it between runs. Never use a downloaded state
file merely because its internal signatures validate: retained-state and
evicted-history provenance remain trusted. See [writer ownership](state-writer-locks.md).

Prepare and retain these inputs privately:

| Input | Operator decision |
| --- | --- |
| `anchor.json` | Explicit chain ID, positive height, and nonzero hash with independently established provenance. See [anchor configuration](anchor-configuration.md). |
| `activation.json` | Exact anchor-bound version rules, coverage end, and source evidence. Do not infer activation from the presence of v2 bytes. See [profiles](header-versions.md). |
| `producers.json` | Valid operator-attested schedule covering initialization, retained headers, and planned watch heights. Peer-derived schedules are still attestations, not authenticated election results. |
| Peer selection | Explicit endpoints and agreement threshold; record operator assumptions privately. Distinct URLs do not establish independent peers. |
| Query targets | Expected account-header/segment identities and required guarantees. A successful report for another target is insufficient. |

The procedure deliberately requires a schedule and profile. Outside this pilot,
a legacy v1 experiment can omit either only as a deliberate change in trust policy,
followed by reviewing and recording a new context. A profile must match
persisted state exactly, including its private source label. Extending a
profile requires a new state built from a trusted anchor; fingerprint equality
does not override state compatibility checks.

Record the source revision, toolchain/dependency provenance, build commands,
and binary hashes. `version --json` describes embedded metadata, which can
be unknown or forged; it is not a hash or signed release attestation. Avoid
publishing raw Git status, build logs, environment values, or filesystem paths.
Keep source/binary identity separately from the verification-context pin.

## Initialize with pinned settings

The examples below use Bash and `jq` (including Git Bash on Windows). Build
both programs from the selected source, for example with `go build -trimpath
-o zenon-spv ./cmd/zenon-spv` and a separate equivalent build for `fetch-bundle`.
On Windows use the `.exe` output names. Set these variables privately before
running the commands; do not enable shell tracing:

- `SPV` and `FETCH`: paths to the chosen executables.
- `PRIVATE`: an existing protected input/state/evidence directory containing
  the three reviewed JSON files above.
- `RECORDS`: a new directory for this run's reports; use a different directory
  for the next run so evidence is not overwritten.
- `PEERS`: comma-separated endpoints; `QUORUM`: the chosen threshold.
- `SEED_COUNT`: a bounded number of initial headers, at least the selected
  window's startup requirement and within profile/schedule coverage.

```bash
set -eu
umask 077
mkdir "$RECORDS"
PRIVATE_RUN=$(mktemp -d "$PRIVATE/run.XXXXXXXX")
git rev-parse HEAD > "$RECORDS/source-revision.txt"
git status --porcelain=v1 > "$PRIVATE_RUN/build-status.txt"

# Always save the real process status beside output. Raw stderr stays private.
record() {
  local name=$1
  shift
  local status=0
  "$@" > "$RECORDS/$name" 2> "$PRIVATE_RUN/$name.stderr" || status=$?
  printf '%s\n' "$status" > "$RECORDS/$name.exit"
  return "$status"
}

record zenon-build.json "$SPV" version --json
record collector-build.json "$FETCH" version --json

CONFIG=(--genesis-config "$PRIVATE/anchor.json"
        --protocol-profile "$PRIVATE/activation.json"
        --schedule "$PRIVATE/producers.json" --window low --retain-headers 256)
record config.json "$SPV" inspect-config "${CONFIG[@]}" --json
PIN=$(jq -er 'select(.schema_version == 1 and .status == "configured" and .exit_code == 0 and .error == null)
  | .verification_context | select(.schema_version == 2 and .policy.retain_headers == 256 and .fingerprint_status == "available")
  | .fingerprint | select(test("^[0-9a-f]{64}$"))' "$RECORDS/config.json")
printf '%s\n' "$PIN" > "$RECORDS/context-pin.txt"
```

Review the context's anchor, capacity, depth/resource limits, profile range and v2
boundary, required producer mode, schedule hash, and applicable checkpoints.
Store the approved pin with the protected run records. On resume use that
saved pin; regenerating it from edited files would bless the drift being
checked. Inspecting configuration does not establish input provenance or
schedule coverage for a particular candidate height.

For example, record executable SHA-256 values without including local paths
(Python 3 is only needed for this optional hashing command):

```bash
python3 - "$SPV" "$FETCH" > "$RECORDS/binaries.json" <<'PY'
import hashlib, json, sys
digests = {}
for name, path in zip(("zenon-spv", "fetch-bundle"), sys.argv[1:]):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    digests[name] = digest.hexdigest()
print(json.dumps({"schema_version": 1, "sha256": digests}))
PY
```

Collect the initial consecutive headers immediately after the approved anchor.
The collector reads the preceding anchor as well; do not export its observation
as a new trusted checkpoint. The verifier checks the candidate against the
independently selected anchor. Keep the collection diagnostics private.

```bash
ANCHOR_HEIGHT=$(jq -er '.height' "$PRIVATE/anchor.json")
SEED_END=$((ANCHOR_HEIGHT + SEED_COUNT))
"$FETCH" --peers "$PEERS" --quorum "$QUORUM" \
  --height "$SEED_END" --count "$SEED_COUNT" --out "$PRIVATE_RUN/seed.json" \
  > "$PRIVATE_RUN/seed-collection.stdout" 2> "$PRIVATE_RUN/seed-collection.stderr"

# First initialization must use a new state path. Resume is a separate step.
test ! -e "$PRIVATE/state.json"
COMMON=("${CONFIG[@]}" --expect-context "$PIN" --state "$PRIVATE/state.json")
record initialized.json "$SPV" verify-headers "${COMMON[@]}" --json "$PRIVATE_RUN/seed.json"
```

Require process exit 0, report `outcome: "ACCEPT"`, `error: null`,
`persistence: "saved"`, the expected tip, and the reviewed context fingerprint.
Inspect the header result's guarantees and trust assumptions. Initial header
ACCEPT does not yet establish inclusion or depth for an account target.

## Advance, restart, and inspect

This example selects K=256 and W=6. It uses state schema 3 and context schema
2; keep the explicit retention option on restart. Review the actual header
count/range before querying: increasing K cannot recover evicted headers.
See [retention policy](retention-policy.md). Before trust-input renewal, follow
the [lifecycle procedure](trust-input-lifecycle.md), preserving the prior inputs,
pin, state snapshot, and failure records.

```bash
record watch-1.jsonl "$SPV" watch "${COMMON[@]}" --json --once \
  --peers "$PEERS" --quorum "$QUORUM" --safety-margin 6 --batch-size 60
```

`--once` attempts one bounded tick; it does not run until fully synchronized.
Exit 0 can mean `advanced` to a partial batch or `caught_up` relative to these
peers. Check the complete `started` and tick events, target/tip, settings,
context, verification, and persistence fields. `advanced` requires accepted
header verification and a completed save; `caught_up` verifies no new batch.
A save/output/lock-release error takes precedence over an accepted outcome.
After ambiguous persistence or output failure, inspect the protected state
before deciding what to do next; do not infer the saved tip from a partial log.

To restart in a new shell, restore the same executable/input paths and explicit
`CONFIG` selection, load `PIN` from the previous `context-pin.txt`, reconstruct
`COMMON`, and run another `watch --once` into a new run directory. This is a new
process loading trusted local state; it must pass the same pin and retained
authorization checks. Use continuous `watch` only when ongoing polling is
intended; its JSON stream and termination rules are in [watch events](watch-events.md).

```bash
record state.json "$SPV" inspect-state "${COMMON[@]}" --json
```

Inspection should exit 0 with `status: "inspected"` and `persistence: "read_only"`.
It describes the effective retained/depth-eligible range without RPC, proof
verification, or state writes. Missing/empty state exits 2. A context mismatch
exits 70; malformed/empty pins exit 64. Never fix a mismatch by dropping the pin
or schedule. Identify the changed setting and deliberately select the intended
configuration. Some state/profile failures occur before the pin check.

## Collect and verify a retained target

Select `SEGMENTS` privately, using `z1ADDRESS:START-END` or a comma-separated
list. Ensure the commitments required by those blocks are in the inspected
window and satisfy its depth policy. Save the expected target identities
independently of the collected bundle.

```bash
TIP=$(jq -er '.retained_window.tip.height' "$RECORDS/state.json")
OLDEST=$(jq -er '.retained_window.oldest.height' "$RECORDS/state.json")
QUERY_COUNT=$((TIP - OLDEST + 1))
"$FETCH" --peers "$PEERS" --quorum "$QUORUM" \
  --height "$TIP" --count "$QUERY_COUNT" --proof-only --segments "$SEGMENTS" \
  --out "$PRIVATE_RUN/candidate.json" \
  > "$PRIVATE_RUN/query-collection.stdout" 2> "$PRIVATE_RUN/query-collection.stderr"
record commitments.json "$SPV" verify-commitment "${COMMON[@]}" \
  --json --retained-only "$PRIVATE_RUN/candidate.json"
record segments.json "$SPV" verify-segment "${COMMON[@]}" \
  --json --retained-only "$PRIVATE_RUN/candidate.json"
```

Collection includes one predecessor header for its own bundle construction;
the proof-only output has no headers and cannot export a checkpoint.
Collector success means evidence was collected, not verified. The retained
queries perform no RPC or state write. If a running writer advances far enough
to evict the target, the query can refuse; inspect/reselect explicitly.

Require the actual exit status, complete JSON schema/command identity,
`mode: "retained_only"`, `persistence: "read_only"`, `error: null`, expected
context/tip, exact target references, and each required result's `proven`
guarantees. Top-level ACCEPT alone is insufficient. Targets outside retained
coverage/depth must not be treated as absent or zero. `verify-state-value`
continues to REFUSE because no accepting state-root proof exists.

## Native Windows invocation and evidence boundary

The same arguments work directly in PowerShell. Use arrays for common flags
and inspect `$LASTEXITCODE` immediately; `$?` or a successfully written JSON
file is not enough. A bounded invocation after loading the saved pin is:

```powershell
$pin = (Get-Content -Raw "$records/context-pin.txt").Trim()
$privateRun = New-Item -ItemType Directory -Path (Join-Path $private ([guid]::NewGuid().ToString()))
$common = @('--genesis-config', "$private/anchor.json",
  '--protocol-profile', "$private/activation.json", '--schedule', "$private/producers.json",
  '--window', 'low', '--retain-headers', '256', '--expect-context', $pin, '--state', "$private/state.json")
& $spv watch @common --json --once --peers $peers --quorum $quorum `
  --safety-margin 6 --batch-size 60 > "$records/watch-next.jsonl" 2> "$privateRun/watch-next.stderr"
$status = $LASTEXITCODE
$status | Set-Content "$records/watch-next.exit"
if ($status -ne 0) { throw 'Watch did not complete successfully; inspect the recorded result.' }
```

Raw trust files, state, bundles, collection diagnostics, and endpoint/peer
inventories belong in private storage. Version/configuration/verification
reports omit paths, credentials, endpoints, and private source labels, but
contain chain/anchor identities and, for proof results, account targets.
Review that experiment metadata before sharing any record. These are local
observations, not signed attestations; preserve original exit codes and
partial/failure outputs rather than presenting only successful rows.

Matching pins establish settings consistency only. The implementation still
relies on external anchor/state provenance, operator-attested activation and
producer schedules, and the selected peer assumptions. It does not establish
canonicality, consensus finality, authenticated election transitions, VM
execution, Dynamic Plasma price-transition correctness, or state values.
See the [verification contract](verification-contract.md) for open network
provenance and deployment gates.
