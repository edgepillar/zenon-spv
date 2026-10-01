# Read-only trusted-state inspection

Inspect a saved state without a bundle or RPC refresh:

```sh
./zenon-spv inspect-state --state state.json --json
./zenon-spv inspect-state --state state.json --genesis-config anchor.json \
  --protocol-profile activation.json --schedule producers.json --window medium --json
```

The command uses the same explicit/default anchor selection, strict window
tiers, activation-profile matching, bounded state loader, and retained producer
authorization as verification. Supply the same trusted anchor and profile used
to create the file. A producer schedule is required only when selected with
`--schedule`; the file does not remember or mandate that optional policy.

Inspection rechecks retained header layout, hashes, signatures, linkage, and
applicable checkpoints before describing the effective window. It cannot
authenticate the file's origin or reconstruct evicted ancestry. Protect the
local state and configuration as trust inputs.

## Read-only behavior

Inspection never initializes, saves, or replaces state; it creates no writer
companion or temporary output file and makes no RPC requests. It can run while
a cooperating writer holds the [state lock](state-writer-locks.md). It reads the
snapshot visible when the file is opened, so a concurrent replacement may make
the displayed tip stale immediately. It provides no transaction spanning later
commands, and filesystem access-time behavior is outside this guarantee.

The requested policy controls the in-memory window. A smaller policy can trim
the loaded view without changing the saved file. A larger policy increases its
capacity but cannot recover previously evicted headers. The report describes
this effective view, not the original file's capacity or complete history.

With explicit `--retain-headers K`, depth W and capacity K are independent.
Schema 3 files require that option on resume; omission is an operational error.
The full saved window is reauthorized before any resize. The nested context
is schema 2 and identifies K. See [retention policy](retention-policy.md).

## JSON schema 1

`--json` emits one object on stdout with no progress text. Omit it, or pass
`--json=false`, for a short text report. Text failures use stderr. Invalid
arguments are not echoed. `--help` prints usage and exits 0 without loading
configuration. As with other commands, put flags before any positional input;
inspection accepts no positional input at all.

| Field | Meaning |
| --- | --- |
| `schema_version`, `command` | `1` and `inspect-state`. |
| `status`, `exit_code` | `inspected`/0, `rejected`/1, `refused`/2, or `error`/64 or 70. |
| `reason` | A verifier reason for missing evidence or a retained producer authorization failure; otherwise `null`. |
| `error` | Fixed `stage` and `category` for usage/setup failures; otherwise `null`. Raw error text and input paths are excluded. |
| `persistence` | Always `read_only`. |
| `verification_context` | Captured [settings and fingerprint](verification-context.md) after successful loading and authorization; otherwise `null`. |
| `retained_window` | Effective `count`, `capacity`, oldest/tip hash-height references, and optional `depth_eligible` range; otherwise `null`. |
| `state_trust` | External trust inputs for the inspected state; empty on failure. |
| `caveats` | Explicit limitations; these are not proof guarantees. |

The `depth_eligible` range contains retained heights with at least `W` headers
strictly after them, including both `from_height` and `through_height`. A
`null` range means no retained height satisfies that condition. It does not
indicate missing content evidence, balance proofs, or consensus finality.
For example, heights 4003 through 4009 with `W=6` have one depth-eligible
height, 4003. Inspecting that same file with `W=60` still succeeds, but reports
no depth-eligible height. A proof query must independently satisfy every other
verification requirement.

Missing and initialized-but-empty files return `refused` with
`ReasonMissingEvidence`; they are never created or populated. A producer
mismatch is `rejected`, and uncovered producer heights are `refused`. Invalid
files, anchor/profile mismatches, and unreadable configuration return an
operational error. Usage errors exit 64. Failures expose no authorized window.

Both stdout framing and the exit status matter: an output write failure exits
70 even if an earlier serialized report said inspection succeeded. A closed
pipe can instead terminate the process according to the operating system.
Parsing errors use JSON only if `--json` was parsed successfully before the
failure. Heights use unsigned 64-bit integers; consumers must decode them
without floating-point precision loss.

## Evidence and privacy limits

`inspected` is a diagnostic status, not proof ACCEPT. There are no `outcome`
or `proven` fields. The report establishes no network freshness, elected
producer set, canonicality, consensus finality, or state-value inclusion.
Paths, RPC endpoints, profile source labels, and schedule audit metadata are
omitted. Anchor, header, schedule, and settings identities remain visible by
design. Record [build identity](build-identity.md) separately when needed.

`VerifiedState.RetainedSummary()` exposes the same constant-size window view
without copying signatures or headers. Its values are detached; changing them
cannot mutate the state handle. Zero handles return `ErrUninitializedState`;
initialized empty handles have zero count and null bounds/range.

Tests compare depth ranges with real proof queries, including maximum uint64
heights, zero depth, eviction, and a stronger resume policy. Command and
compiled-process tests exercise node-derived bounds, invalid state, producer
authorization, output failures, active-writer coexistence, zero RPC calls,
and unchanged file bytes, identity, modification time, and mode.
