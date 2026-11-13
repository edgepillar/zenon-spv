# Second authorized owned-devnet attempt

The separately authorized `834d551` attempt is
[Actions run 43521575781](https://github.com/edgepillar/zenon-spv/actions/runs/43521575781),
attempt 1. The experiment job ran from 22:43:25 to 22:46:25 UTC on
13 November 2026 and concluded `failure`. The evidence upload succeeded.
The original ZIP was acquired once with its exact byte count and SHA-256,
then reviewed in place against separately retained run, job and artifact API
responses. The reviewer returned `HOSTED_RECORDED_NON_ACCEPTING_OUTCOME`
with actual exit 1 and complete output, verifying all 504 indexed files without
extracting or reexecuting the consumer.

| Input or result | Exact identity |
| --- | --- |
| Runner source | `834d551fc285bb2ec0cc7617e0164caa0023eadf` |
| Source tree | `ff8031ad3c98e89f86f31494e838670639d30661` |
| Execution ref | `codex/owned-devnet-query-runner` |
| Reference-gas contract | SHA-256 `6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31` |
| Selected consumer/oracle source | `7493c5929c7dbcfb29f94be521f7533d90a1a687` |
| Experiment job | `132216873251` |
| Artifact | `14083545779`, `owned-devnet-query-43521575781-1` |
| Original ZIP | 241,270 bytes; SHA-256 `d72488b944afb2bba8c8753fa5eb8f0efaadddef9338eaaf4a7852481b6d848a` |
| Terminal | `FAILURE`, stage `nodes`, reason `command_failed` |
| Failed command | `rpc-01`; exit 56, complete output, zero stdout bytes, quiescent process group |

## Established observations

Source, component, host and filesystem admission completed. The initial host
sample reported four effective CPUs, 15,766,315,008 available memory bytes and
91,472,769,024 free disk bytes. Across 632 budget samples, peak observed new
disk use was 3,014,742,016 bytes (about 2.81 GiB) and peak observed evidence
size was 421,232 bytes. The final budget sample was at 171.94 seconds with
no refusal. These are sampled filesystem observations, not an OS aggregate
quota, isolated writer attribution or measurements between samples.

Both image builds completed with exit 0 and complete captures. Their loaded
image IDs and source/recipe labels passed the selected checks. The owned
BuildKit container stopped with exit 1; both retained stopped-state summaries
reported no OOM, runtime error, active PID, restart, dead or paused state. The
builder-only policy accepted this handoff before runtime startup. This actual
observation belongs to this run; it does not reconstruct the missing state or
reclassify the [first attempt](owned-devnet-attempt-2026-11-13.md).

The controller created and started `pillar`, `pillar2`, `pillar3` and `rpc`.
The first `ledger.getFrontierMomentum` command then returned curl exit 56 in
about 29 milliseconds, with complete capture and no response bytes. The existing
startup wait admitted only exits 7 and 28, so it propagated this failure instead
of waiting for another readiness observation.

Cleanup recorded all four create-returned runtime container IDs closed. Their
retained stopped-state summaries reported exit 0, PID 0 and no OOM or runtime
error. No executor or gateway container was started. No manual volume, image
or network removal was performed; the fresh hosted VM remains the disposal
boundary.

## Remaining uncertainty and bounded repair

The artifact retains the failed command's exact stdout/stderr pins and capture
receipt, but not the raw stderr or service logs. It does not identify the server
side cause or prove a healthy RPC service would have appeared on a later read.
A port publication/startup race is a possible explanation, not an established
diagnosis. Persistent receive failures must still terminate the readiness wait.

The follow-up admits curl exit 56 only within startup readiness, alongside the
existing exits 7 and 28, when the command started, completed its capture, has
no capture refusal, reports a quiescent process group and produced exactly zero
stdout bytes. The existing 90-second checked deadline, 30-attempt bound,
three-second backoff and shared 96-call limit remain. Every actual failed
command keeps its receipt; a later successful observation does not rewrite it.
Partial responses, malformed RPC data, identity mismatches, unknown exits,
incomplete captures and non-startup failures remain terminal.

Regression controls use simulated responses and regular temporary files. A
POSIX control executes a small local process that returns 56, followed by a
synthetic response, and checks that both actual command receipts survive with
outcomes `FAILURE` and `SUCCESS`. It executes no curl request, Docker service,
chain, signing operation or native state-proof consumer. The repair therefore
does not qualify a new devnet execution.

The run reached no fixture configuration, deposit, opening-header capture,
closed-ledger oracle or consumer command. It establishes no actual H2/H3
transition, selected state proof, native consumer acceptance or production
eligibility. The one-attempt authorization is consumed. Another signed fixture
requires a reviewed exact source and explicit approval; this repair does not
retry the failed workflow. Representative R1 data, independent review and
applicable release/production gates remain open.
