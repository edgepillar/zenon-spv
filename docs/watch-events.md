# Watch events

`zenon-spv watch --json` writes one compact JSON object per line to stdout.
Text mode remains the default; `--json=false` selects it explicitly.
Embedders select the same stream with `syncer.Loop.JSON = true` and `Out`.
Each event has `schema_version: 1` and `command: "watch"`. This schema is
separate from the single reports produced by verification and inspection.

```sh
zenon-spv watch --json --peers "$ZENON_SPV_PEERS" \
  --state trusted-state.json --genesis-config checkpoint.json
```

Use a previously initialized, nonempty state and the matching profile and
producer schedule when applicable. JSON mode includes captured verification
settings in every event. `--show-context` adds no separate line in this mode.

## Event meanings

| `event` | `persistence` | Meaning |
| --- | --- | --- |
| `started` | `not_attempted` | The state was loaded and revalidated while holding the writer lock. No tick has run. |
| `advanced` | `saved` | A new header batch verified and its candidate state was saved before reporting. |
| `caught_up` | `saved` | The agreed target matches the hash, public key, and signature of a locally retained header. The existing state was saved; no new header batch was verified. |
| `rejected` | `not_attempted` | The new batch failed verification. The retained state was not advanced or saved. |
| `refused` | `not_attempted` | Evidence was unavailable or verification could not establish the required conditions. No state save occurred. |
| `save_failed` | `failed` | Saving an accepted candidate or caught-up state failed. The loop retained its previous in-memory state. |

There is deliberately no top-level `ACCEPT` field. In particular, an accepted
`verification` inside `save_failed` does not mean the service saved progress.
`caught_up` describes the configured peers' target, not network freshness,
independent finality, or a newly verified header batch.

## Fields

All fields below are present. Unavailable objects or values are `null`;
guarantee and trust arrays use `[]` when empty.

| Field | Meaning |
| --- | --- |
| `state_tip` | `{hash, height}` of the loop's retained in-memory state at reporting time. |
| `previous_tip_height` | Tip before the tick; null at startup. |
| `candidate_tip` | Exact candidate `{hash, height}` after an accepted header extension, even if saving fails. Null when no extension was accepted. |
| `target_height` | Selected and agreed query height; null when frontier selection failed or at startup. |
| `fetched_count` | Number of headers returned by the tick's range fetch for processing, including a target-binding refusal before verification. Target-selection queries are not counted; zero does not prove that no RPC requests occurred. |
| `reason` | Tick reason-code token; null at startup. `ReasonOK` is a verification/control-flow result, not a persistence guarantee. |
| `persistence` | `not_attempted`, `saved`, or `failed`, independent of the verification result. |
| `consecutive_save_failures` | Consecutive failed save attempts. A successful save resets it; rejection/refusal does not. |
| `error` | Fixed `{stage, category}` for RPC, target-consistency, or save failures; otherwise null. No arbitrary error text is included. |
| `verification` | Actual header-extension result, or null if no extension was attempted. Contains `outcome`, `reason`, `failed_at`, `proven`, `not_proven`, and `trust_assumptions`. |
| `verification_context` | Captured anchor, policy, activation profile, producer settings, checkpoints, and diagnostic fingerprint. See [verification context](verification-context.md). |
| `state_trust` | External trust inputs used by the retained state, including its local file provenance. |
| `source_trust` | `TRUST_RPC_QUORUM`, separate from the verifier's cryptographic claims. |
| `settings` | Startup-only peer count, effective quorum, interval, safety margin, batch size, and maximum save failures. Null on ticks. |
| `caveats` | Fixed interpretation limits, present on every event. |

Error stages are `frontier`, `fetch`, `retained_target`, `target_binding`, and
`persistence`. RPC categories are
`quorum_unavailable`, `peer_disagreement`, or `unavailable`; persistence uses
`operational`. A retained-target conflict uses `header_mismatch` and
`ReasonRetainedHeaderMismatch`; an out-of-window target uses `height_unavailable`
and `ReasonHeightOutOfWindow`. Both are refused ticks with no new verification
or save. See [retained target consistency](watch-persistence.md#retained-target-consistency).
If a fetched batch reaches the selected target with a different signed envelope,
`target_binding / header_mismatch` and `ReasonTargetHeaderMismatch` report the
conflict before verification or persistence. `fetched_count` can be positive
while `verification` is null on this path.
A verifier rejection/refusal is represented by `verification`
and `reason`, without inventing an operational error. Detailed safe per-peer
messages remain available in text mode.

`failed_at` is the verifier's zero-based batch index, or -1 if not applicable.
Only guarantees listed in `verification.proven` were established by that
operation. No event proves canonicality, consensus finality, or state values.
An operator-attested producer schedule or activation profile remains an
external trust input. All heights are unsigned 64-bit JSON integers; consumers
must preserve their exact values rather than round them through binary floats.

The reported batch size includes its default. A positive
`verification_context.policy.max_headers` can further cap actual requests.
A zero configured quorum is reported as the effective unanimous peer count.
Peer counts and position labels do not establish independent operators.

## Persistence and stream boundaries

`state_tip` describes memory, not a fresh observation of the file on disk.
A save can fail after replacing the file, for example on a directory sync.
The `save_failed` event then retains the old `state_tip`; `candidate_tip` may
already be visible on disk. The event does not assert rollback or durability.
A restart revalidates the file actually present. See
[watch persistence](watch-persistence.md#filesystem-boundary).

The stream starts only after successful state loading. It has no guaranteed
terminal event. Consumers must read complete newline-terminated records and
check the process exit status: graceful shutdown is 0, usage errors are 64,
and returned operational errors are 70. REJECT and REFUSED ticks remain
nonfatal in continuous mode and do not determine its eventual process exit
status. With `--once`, exactly one tick is attempted: saved ACCEPT exits 0,
REJECT exits 1, and REFUSED exits 2; operational failures still take precedence
with exit 70. See [single-step watch](watch-persistence.md#single-step-watch).
Fatal setup
or runtime failures after argument parsing use stage-only stderr diagnostics
in JSON mode. Syntax failures before startup emit the fixed stderr diagnostic
`arguments: invalid command syntax`; explicit help still prints usage. Neither
starts the event stream, loads state, acquires writer ownership, or queries RPC.
Cancellation observed between ticks stops before another RPC round, including
when an immediate catch-up timer is ready. Cancellation during a running tick
can still produce that tick's refusal event before shutdown.

A write error or short write stops the loop without replaying the event.
Partial output is not a complete record. An earlier completed save is not
rolled back if its event cannot be delivered, so this stream is not an
exactly-once journal or an authenticated receipt. An embedder can explicitly
discard events by leaving `Out` nil.

Events omit paths, endpoints, credentials, raw RPC/storage errors, profile
`Source`, and schedule peer metadata. They do contain chain hashes, heights,
and selected verifier settings; they are not an anonymity mechanism.

Tests exercise real local RPC, save failures before and after replacement,
retry recovery, output errors/short writes, and writer-lock release. Compiled
CLI checks cover node-derived v2 headers, operator schedules, profile expiry,
refusal/rejection, separate output streams, and trusted resume. RPC frontier
hints and injected faults are synthetic; these are offline conformance tests.
