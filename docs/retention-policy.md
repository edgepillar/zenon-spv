# Retained capacity and verification depth

W is the required number of consecutive verified headers after a commitment's
momentum. K is the retained header capacity. Select them independently:

```sh
zenon-spv inspect-config --genesis-config anchor.json --protocol-profile activation.json \
  --schedule producers.json --window low --retain-headers 256 --json
```

Supply the same options and reviewed `--expect-context` pin to every verifier,
watch, or state-inspection command. `low`, `medium`, and `high` select W=6,
60, and 360. Explicit K must satisfy **W < K <= 4096**; malformed, empty, zero,
negative, too small, or oversized CLI values fail with exit 64 before state
or RPC access. Omission preserves legacy K=W+1. The API uses
`Policy.RetainHeaders`; zero means legacy mode, never unbounded storage.

For a full contiguous window with tip T the depth-eligible range is
`[T-K+1, T-W]`, inclusive. A partially filled window starts at its actual
oldest retained header. For example, T=110, K=10, W=2 permits heights 101..108.
An account segment can have blocks confirmed at heights 104 and 107 and
still verify after a delay. K does not change W or any other proof check.
Inspection's `retained_window` reports actual count, capacity, oldest/tip
identities, and the depth-eligible interval.

Missing retained headers return `REFUSED/ReasonHeightOutOfWindow`. A retained
but shallow target returns `REFUSED/ReasonInsufficientFinality`. That legacy
reason name describes local depth, not consensus finality. Bad content or
signatures remain REJECT. No missing target means a zero balance or absence.

## State and context compatibility

| Selection | Saved state | Nested context | Resume |
| --- | --- | --- | --- |
| K omitted / API zero | Schema 1 without a profile, 2 with a profile | Schema 1, existing fingerprints unchanged | Existing legacy behavior |
| Explicit K | Schema 3; `capacity` is K; profile optional | Schema 2 with `policy.retain_headers` | Explicit K required |

Schema 3 makes older clients fail on an unsupported version instead of silently
resizing to W+1. New clients refuse schema 3 when K is omitted. The outer
verification, inspection and watch report schemas remain version 1; their
nested context must also be version checked. No report or state is a signed
provenance attestation.

To opt in from a protected schema 1/2 state, stop its writer, preserve a private
snapshot and original inputs, inspect/review the new explicit-K context, then
load with those settings and the new pin. Existing headers are revalidated;
only an accepted stateful save writes schema 3. Read-only inspection and queries
never migrate the file. Increasing capacity retains future arrivals but cannot
recover evicted history. To recover it, construct a separate state by verifying
consecutive history from an independently trusted anchor.

An explicitly changed K can resize a schema 3 view after the entire saved
window's integrity, profile and producer authorization checks. Shrinking must
not hide an unauthorized header in the portion about to be evicted. The old
context pin rejects the change; review a new pin deliberately. Inspection/query
resizing stays in memory. Writer locks cover load through any later save.

## Resource and evidence limits

The first explicit-K release caps capacity at 4096. Working header storage is
allocated for capacity rather than the whole incoming batch. The FIFO append
implementation shifts up to K headers when full; it does not promise constant
time append. Owned-state copies cost O(K); resume reauthorization covers the
entire saved count before resizing, even when it exceeds the newly selected K.
After checking and resizing, the loaded state releases the old backing array
so evicted envelopes are no longer retained by it. Transient decoding is still
bounded by the saved-file limits, not the newly selected K. Existing bundle,
proof and RPC count/byte caps remain independent and unchanged. Persistence
also retains its 64 MiB file limit and global decoded-header limit; meeting a
count cap does not guarantee any file fits its byte cap.

Core tests use signed synthetic headers with separate confirming heights to
check delayed segments, exact eviction boundaries, unchanged state on failure,
profile/no-profile migration and authorization before shrinking. Compiled tests
use the pinned node corpus for schema-3 startup, watch, restart, shallow/refused
then accepted queries, multiple depth-eligible heights, and omitted/changed K.
The pinned node corpus currently places its account targets at one confirming
height; the mixed-height core fixture is not presented as independent node
compatibility evidence. Independent node-derived mixed-height data and full
capacity network measurements remain roadmap gates.
