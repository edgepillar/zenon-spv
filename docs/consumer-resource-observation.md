# Observe resources around a read-only consumer call

Use this guide to connect the [block observer](block-observer.md),
[query-report consumer](query-report-consumer.md) and
[private staging sampler](private-staging-observations.md). The example makes
one local-file observer call with a finite metadata series and a separate final
scan. It does not contact RPC, advance state or select trust inputs.

First follow the [operator workflow](operator-pilot.md) for independently selected
anchor/profile/schedule, trusted saved state, explicit K/W/context and target
expectations. The local query still requires `W < K <= 4096`; this example uses
K=256 and the previously approved `low` context. Choose the candidate bundle and
expectations before running; changing expected fields to match a candidate would
change the acceptance question. An evicted or out-of-depth target is a refusal,
not absence or a zero value.

Use reviewed verifier/consumer/observer binaries and their separately established
pins. Select the sampler from the same reviewed source and an explicit Python
3.9+ interpreter. Source/build hashes and context equality do not authenticate
binary distribution or trust-input provenance. Keep the executables, source,
state, inputs and report channel protected against replacement. See
[candidate artifacts](candidate-artifacts.md) and [build identity](build-identity.md).

## Keep inputs, staging and records separate

Select these existing protected directories before invoking the example:

| Selection | Contents and ownership |
| --- | --- |
| `PRIVATE` | Fixed anchor, activation profile, producer schedule, state, candidate bundle and independent expectations. |
| `STAGING_ROOT` | Initially empty directory used only by this observer invocation. Inputs and records remain outside it. |
| `RECORDS` | Fresh directory for this attempt's stdout, private stderr and actual exit records. Preserve it even on refusal. |

On POSIX the sampler requires its root to be owned by the current user with no
group/other permission bits. Windows requires an established private ACL;
`umask` cannot establish that boundary. The caller protects the entire selected
root against concurrent replacement and excludes unrelated writers. A shared
root containing another live observer cannot support this invocation's empty-root
conclusion. The sampler neither creates/repairs directories nor removes remnants.

Set the following variables privately, without shell tracing: `OBSERVE`, `SPV`,
`CONSUME`, `SPV_SHA256`, `CONSUME_SHA256`, `PYTHON`, `SAMPLER`, `PRIVATE`,
`STAGING_ROOT`, `RECORDS` and `PIN`. Executable/script paths are explicit; the
example does not choose binaries from `PATH`. Use `.exe` names on Windows.
The recipe targets Bash, including a configured Git Bash environment. The
documentation recipe controls were executed locally on Darwin arm64; native
Windows/Git Bash recipe execution is not qualified by those controls. Applications
using native process APIs should preserve UTF-8 stdout bytes and actual statuses
directly, without recoding JSON through a shell text pipeline.

## Run one bounded series and preserve each result

Save the following Bash recipe as a separate script and run it after reviewing
the selections above. It records failures and waits for its finite sampler even
when the observer refuses. The final scan occurs after both processes settle.
The root protection and input provenance remain caller requirements.

```bash
set -u
umask 077
: "${OBSERVE:?}" "${SPV:?}" "${CONSUME:?}" "${SPV_SHA256:?}" \
  "${CONSUME_SHA256:?}" "${PYTHON:?}" "${SAMPLER:?}" "${PRIVATE:?}" \
  "${STAGING_ROOT:?}" "${RECORDS:?}" "${PIN:?}"

observer_status=0
sampler_status=0
final_scan_status=0
empty_check_status=0

"$PYTHON" -I -B "$SAMPLER" --private-dir "$STAGING_ROOT" \
  --samples 100 --interval-ms 10 --max-entries 128 --max-depth 2 \
  > "$RECORDS/staging-series.json" 2> "$RECORDS/staging-series.stderr" &
sampler_pid=$!

"$OBSERVE" \
  --verifier "$SPV" --verifier-sha256 "$SPV_SHA256" \
  --consumer "$CONSUME" --consumer-sha256 "$CONSUME_SHA256" \
  --command verify-commitment \
  --genesis-config "$PRIVATE/anchor.json" \
  --protocol-profile "$PRIVATE/activation.json" \
  --schedule "$PRIVATE/producers.json" --state "$PRIVATE/state.json" \
  --bundle "$PRIVATE/candidate.json" \
  --expectations "$PRIVATE/expectations.json" --private-dir "$STAGING_ROOT" \
  --expect-context "$PIN" --window low --retain-headers 256 --timeout 30s \
  > "$RECORDS/observer.json" 2> "$RECORDS/observer.stderr" || observer_status=$?

wait "$sampler_pid" || sampler_status=$?
"$PYTHON" -I -B "$SAMPLER" --private-dir "$STAGING_ROOT" --samples 1 \
  --max-entries 128 --max-depth 2 \
  > "$RECORDS/staging-final.json" 2> "$RECORDS/staging-final.stderr" || final_scan_status=$?

"$PYTHON" -I -B - "$RECORDS/staging-final.json" \
  > "$RECORDS/staging-empty.json" 2> "$RECORDS/staging-empty.stderr" <<'PY' || empty_check_status=$?
import json, sys
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result
def integer(value, wanted):
    return type(value) is int and value == wanted
def nonfinite(value):
    raise ValueError("nonfinite value")
empty = False
try:
    with open(sys.argv[1], "rb") as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("report bound")
    report = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
    samples = report["samples"]
    row = samples[0]
    counts = row["staging"]
    zeros = ("entries", "directories", "regular_files", "logical_file_bytes", "vanished_entries")
    blocks = counts["filesystem_reported_allocated_bytes"]
    empty = (integer(report["schema_version"], 1) and report["status"] == "observed" and
             report["category"] is None and report["failed_sample_index"] is None and
             integer(report["requested_samples"], 1) and integer(report["observed_samples"], 1) and
             type(samples) is list and len(samples) == 1 and integer(row["index"], 0) and
             type(row["elapsed_ns"]) is int and row["elapsed_ns"] >= 0 and
             type(counts) is dict and set(counts) == set(zeros) | {"filesystem_reported_allocated_bytes"} and
             all(integer(counts[key], 0) for key in zeros) and
             (blocks is None or integer(blocks, 0)))
except (OSError, ValueError, KeyError, IndexError, TypeError, RecursionError):
    pass
print(json.dumps({"schema_version": 1, "status": "empty" if empty else "not_empty_or_unobserved"}))
sys.exit(0 if empty else 2)
PY

printf '%s\n' "$observer_status" > "$RECORDS/observer.exit"
printf '%s\n' "$sampler_status" > "$RECORDS/staging-series.exit"
printf '%s\n' "$final_scan_status" > "$RECORDS/staging-final.exit"
printf '%s\n' "$empty_check_status" > "$RECORDS/staging-empty.exit"
for status in "$observer_status" "$sampler_status" "$final_scan_status" "$empty_check_status"; do
  if [ "$status" -ne 0 ]; then exit "$status"; fi
done
```

The metadata series requests 990 ms of gaps plus scan overhead. It can finish
before the observer; it does not guarantee coverage of the whole call, a maximum
gap, a storage I/O deadline or peak usage. Each observer child has its own 30-second
deadline; preflight, metadata scanning and filesystem operations have no separate
deadline. The recipe waits for the actual sampler exit and does not supervise an
arbitrary process tree. External termination, interpreter/setup or report-write
failure can interrupt recording; retain available files and reconcile actual
owned process completion before any cleanup or reuse.

The final reader is a bounded local diagnostic over the protected sampler report.
It refuses malformed, duplicate, partial, wrong-schema or nonempty final data;
it is not a verification-report consumer or authenticated filesystem proof.
Unknown file allocation stays null; an empty visible directory does not establish
zero physical usage, free space or absence of unlinked open files.

## Interpret application and metadata results separately

| Recorded result | Required interpretation |
| --- | --- |
| Observer exit 0 | Require its complete local-file schema 1, `matched`, null category, expected positive target count and actual zero verifier/consumer exits. The independently selected expectations and trusted report channel remain required. |
| Observer nonzero or partial stdout | No application match, even if a fragment says `matched`. Preserve its actual status and investigate the fixed category. |
| Sampler exit 0, `observed` | The requested bounded scans returned metadata. This says nothing about verification acceptance or complete lifetime/peak coverage. |
| Sampler nonzero, `not_observed` | Retain completed samples and refusal/cancellation category; do not promote the partial series. Exit meanings are in the [sampler reference](private-staging-observations.md). |
| Final scan exit 0 and empty-check exit 0 | One protected post-exit scan observed no entries/files/directories/logical bytes. Other storage and unobserved changes remain outside the result. |
| Nonempty, unsafe or unavailable final scan | Preserve evidence and remnants; inspect ownership and cleanup before reuse. Successful scanning alone does not mean the root is empty. |

All zero statuses are necessary for this complete example, but application
acceptance still requires parsing the complete observer report. The empty reader
does not consume observer JSON. Do not overwrite failed records with a retry,
delete unexpected remnants automatically or change context/target expectations
to obtain success. Keep raw stderr and all selections private; sharing even
scalar reports requires reviewing their workload/timing information.

## Choose relevant evidence before choosing a budget

| Resource report | Measured boundary |
| --- | --- |
| [Shared immutable queries](shared-query-resources.md) | Retained API-level work under explicit K/W; excludes startup, RPC, file staging and consumer processes. |
| [Selected observer](selected-observer-resources.md) | Fixed selected-height signed-capture replay, including process completion, sampled RSS and group elapsed time. |
| [Five-block observer](signed-batch-observer-resources.md) | Complete fixed signed batch replay; live network latency is outside the observation. |
| [Joined pipeline](joined-pipeline-resources.md) | Synthetic collector/verifier/consumer/observer costs, stream caps, cancellation and private staging boundaries. |
| [Private metadata and repeated cycles](private-staging-observations.md#repeated-local-observer-cycles) | 348 fixed-state groups, finite non-atomic file/RSS samples and fault-followed-by-fresh-call recovery. States do not advance. |

Select consumer hardware, concurrency, target mix, retention, storage and latency
criteria independently, recording the source, toolchain, binaries, inputs and
every outcome. Published developer alarms are observations for their stated
synthetic workload, not a consumer SLA, production capacity, physical quota or
sustainable arrival rate. Separate an advancing-state/restart/stale-peer/coverage
expiry pilot from fixed-state replay. An explicit single-RPC engineering run can
use the [existing collection invocation](block-observer.md#collect-and-observe-from-one-explicit-rpc)
after its separate trust selections; this example supplies no endpoint or network
authorization. Canonicality/finality, election/activation authentication,
state-value proofs, independent review and authenticated release distribution
remain separate gates.
