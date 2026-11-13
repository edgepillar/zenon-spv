# First authorized owned-devnet attempt

The single authorized chain-69 attempt on 13 November 2026 is
[Actions run 43394208316](https://github.com/edgepillar/zenon-spv/actions/runs/43394208316),
attempt 1. The job ran from 08:34:01 to 08:37:37 UTC and concluded `failure`.
The evidence upload succeeded. The retained-result reviewer bound the completed
run, experiment step, upload and artifact, verified the ZIP and its indexed
members in place, and returned `HOSTED_RECORDED_NON_ACCEPTING_OUTCOME`.

| Input or result | Exact identity |
| --- | --- |
| Runner source | `4a1d03e06c848edebcf611e964e84967d85679d1` |
| Frozen ref | `codex/owned-devnet-query-runner` |
| Reference-gas contract | SHA-256 `6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31` |
| Selected consumer/oracle source | `7493c5929c7dbcfb29f94be521f7533d90a1a687` |
| Experiment job | `131781091748` |
| Artifact | `14022038779`, `owned-devnet-query-43394208316-1` |
| ZIP | 116,801 bytes; SHA-256 `5cc723584b09a7bc5a1eb5fe26f7cba405a13d16a2f76cd6ba2ace204279a2e3` |
| Terminal | `REFUSED`, stage `images`, reason `container_not_gracefully_stopped` |

## What the run establishes

Host admission and the same-filesystem engine check passed. The initial sample
reported four effective CPUs, 15,742,156,800 available memory bytes and
92,081,213,440 free disk bytes. Across 751 budget samples, peak observed new
disk use was 3,014,713,344 bytes (about 2.81 GiB); the final sample was at
207.47 seconds and the budget reported no refusal. These are sampled filesystem
observations, not an OS aggregate quota or measurements between samples.

Both Docker build commands completed with exit 0 and complete captures. The
first builder-stop command also completed with exit 0 in about 0.35 seconds.
The following inspection command succeeded, but its parsed state failed the
existing stopped-container policy. Cleanup repeated the owned stop/inspection
and recorded closure as unresolved. A successful Docker stop command is not
proof of successful container exit or the required stopped state.

The artifact contains only the owned builder in the cleanup roster, no runtime
layout and no fixture-configuration, deposit, header-capture or consumer receipt.
The run stopped before chain-node startup and signed fixture transactions.
It establishes no actual H2/H3 transition, closed-ledger schedule, state proof or
native consumer acceptance. The disposable hosted VM remains the disposal
boundary; no manual volume/image/network removal or retry was performed.

## Diagnostic gap and next source change

The original command receipts preserve the post-stop inspection's exact size
and SHA-256, but its stdout was not selected for upload. They do not preserve
the actual container exit code, OOM flag, PID and other stopped-state fields.
The `container_not_gracefully_stopped` reason can represent several failed
predicates. The exact failed field and its cause therefore remain unknown.
In particular, this record does not establish an OOM, forced kill, timeout or
benign signal exit. The hash cannot recover the missing inspection bytes.

The follow-up retains a bounded allowlisted state summary before stopped-state
validation and includes the existing per-image JSON reports when a later phase
refuses. It preserves separate normal/cleanup inspections and their original
stdout digests, while excluding arbitrary engine error text, mounts, labels,
configuration and raw logs. It keeps the existing ownership/resource checks and
zero-exit policy. Regression controls use in-memory engine replies and regular
temporary files; they start no daemon, chain, wallet or signed transaction.

This change supplies diagnostics for a future run, not a retrospective pass or
a confirmed repair of the unknown shutdown cause. The frozen execution ref and
original contract bytes remain unchanged. The one-attempt authorization is
consumed; another fixture execution or rerun needs a new reviewed source and
explicit approval. D0-D3 actual-network exits, representative R1 input,
independent review and applicable release/production gates remain open.

## Subsequent builder compatibility review

The preceding record describes the original attempt and the diagnostic-only
follow-up. It remains unchanged. A later review of the pinned image's publisher
metadata and declared BuildKit source found a requested-signal path that can
return exit 1. The [builder-only shutdown policy](owned-builder-shutdown.md)
therefore gives the disposable cache builder its own strict quiescence check;
the six runtime services retain the original zero-exit requirement.

This source-supported compatibility fix does not identify the missing field in
run 43394208316, establish its exit code, or reclassify its result. Its regression
controls start no actual builder or chain. Another fixture execution still
requires a separately reviewed exact source and explicit authorization.
