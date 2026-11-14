# Owned startup nodes before cleanup

The single authorized main-source attempt at
`f09006d77b7c8386d17504446d865d7d6e0478c6`,
[run 43620852418, attempt 1](https://github.com/edgepillar/zenon-spv/actions/runs/43620852418),
ended `REFUSED` at `nodes` with `owned_rpc_readiness_deadline`. Domain
configuration, vault setup, the fixture deposit, the closed-ledger oracle and
the native consumer were not reached. The one-dispatch authorization was consumed.

## Retained observation

The original result ZIP is 323,951 bytes with SHA-256
`141916d3aa9f788463d068acb1ef29e6e04348c683f841d8e0c8d496c0427eab`.
Its 661 indexed files were checked in place, including the selected metadata,
file digests and actual command receipts. The reader exited 1 with
`HOSTED_RECORDED_NON_ACCEPTING_OUTCOME` and no consumer comparison. Acquisition
retained one original ZIP, without extraction or repackaging.

Requests 2 through 30 each returned a v1 candidate at height 1 with hash
`fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`.
Request 31 reported `SyncDone`, current height 1 and target height 1. The next
frontier request, 32, again returned that same v1 height/hash. Its 1,988-byte
original response has SHA-256
`597c4950793cd0ac80150eb4fc5a07ecd61a9269774d348c63a1ad9b97bd7966`.
The stats and frontier reads are sequential, not an atomic snapshot. This attempt
establishes no H2 anchor, accepted v3 header, StateRoot or typed consumer result.
The earlier attempt's reported height of two remains a separate observation.

After cleanup stop calls, RPC and pillar reported exit 0, pillar2 reported 137
and pillar3 reported 2. All four reported `OOMKilled: false`. These after-stop
observations do not identify the pre-cleanup failure time or cause. Exit 137
alone does not establish an out-of-memory event; exit 2 alone does not identify
a panic. No readiness, peer-count, clock, genesis or producer-schedule relaxation
is justified by these records.

The budget report sampled peak new disk use of 3,003,854,848 bytes and peak
evidence use of 527,549 bytes; it recorded no budget refusal. These are samples,
not OS-enforced aggregate quotas or proof that transient peaks were absent.

## Next bounded observation

After the original initial-height refusal and existing sync/frontier reads,
the controller can observe the four owned node containers before cleanup.
At most nine read-only Docker commands run: one engine identity probe, four
owned-ID inspections and four log-tail reads. Each command has a five-second
deadline and a fresh resource guard. Inspection requires the admitted engine,
owned container, expected image and configured limits before logs are requested.

Each log read selects at most 128 tail lines and caps each captured stream at
32 KiB. The exported summary contains only fixed event counters, bounded state
fields and allowlisted relative source-file/line pairs. Arbitrary log text,
panic messages, arguments, peer addresses and raw inspection output are excluded
from the public index. Unknown lines are counted without exporting their text.
Failures and interruptions retain actual exit/completeness receipts and do not
become successful observations.

The reader binds the summary's stream pins to command receipts and checks
observed-command start records, scope, bounds and ordering before cleanup stop
commands. Raw log bytes are deliberately absent, so it marks the summary as
diagnostic assertions whose original text was not independently rechecked.
It cannot supply accepted-header authority. Legacy archives without this optional
record keep their report shape; existing archives receive no backfilled data.

The original refusal, 90-second / 30-attempt readiness bound, shared 96 RPC-call
cap and overall resource limits remain. Anchor, profile, schedule and context
pins are unchanged. Local controls, exact-source hosted CI, artifact review and
a later separately authorized fixture remain distinct gates. The selected-network
D2/D3/D5 result, representative R1 measurements, independent review and applicable
release/production gates remain open.
