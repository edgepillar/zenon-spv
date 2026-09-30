# JSON verification reports

Use `--json` on `verify-headers`, `verify-commitment`, `verify-segment`, or
`verify-state-value` to receive one schema-versioned JSON object on stdout.
Put flags before the bundle path. The default and `--json=false` retain the
existing text output. Watch does not support this report format.

```sh
zenon-spv verify-segment --json --retained-only \
  --genesis-config anchor.json --state trusted-state.json proof-only.json
```

The report is emitted after verification and any state save attempt. It always
includes the captured [verification context](verification-context.md) when
setup completes. `--show-context` adds no separate line in JSON mode.

## Completion and verification are separate

Check the **process exit code** before using the report. Require a complete
JSON object with supported `schema_version`, the expected command and mode,
matching `exit_code`, and the required result references and guarantees.
An inclusion result only covers its identified target under the stated trust
inputs. It does not establish a balance, state execution, canonicality, or
consensus finality. A report is an unsigned local diagnostic, not a portable
proof receipt or an authentication mechanism.

| Process exit | Top-level `outcome` | `error` | Meaning |
| --- | --- | --- | --- |
| 0 | `ACCEPT` | `null` | All requested checks accepted and any requested state save returned success. |
| 1 | `REJECT` | `null` | At least one implemented validity check failed. |
| 2 | `REFUSED` | `null` | The verifier could not establish the requested result. |
| 64 | `null` | `usage` | The parsed invocation is invalid. |
| 70 during setup | `null` | `operational` | Configuration, bundle decoding, writer ownership, or state loading failed. |
| 70 during saving | `ACCEPT` | `operational` at `persistence` | Evidence accepted, but saving failed. This is not successful command completion. |
| 70 during lock release | Prior outcome, if available | `operational` at `state_lock` | Releasing writer ownership failed; state may already be saved. |

Worst-result ordering remains REJECT, then REFUSED, then ACCEPT. Header or
setup failure stops proof evaluation. An accepted header row followed by a
refused proof does not make the overall request accepted. Missing proof arrays
produce REFUSED, never an empty successful query. State-value proofs have no
accepting implementation.

Flag syntax errors (including unknown flags, invalid Boolean syntax, and
`--help`) occur before JSON mode is selected: stdout is empty, diagnostics
remain on stderr, and exit 64 is preserved. Once flags parse and JSON mode is
selected, operational errors use fixed stage/category fields instead of raw
error text. Ordinary reported results and errors leave stderr empty.

If encoding fails or a stdout write returns an error, the process exits 70
and attempts to write a fixed diagnostic to stderr. A closed stdout pipe can
instead terminate the process through the platform's SIGPIPE behavior.
Stdout may be absent or partial; even an apparently complete report cannot
override a failing process exit. A state
save that already succeeded is **not rolled back** by a later output failure.
There is no transaction spanning the state file and the report destination.

## Schema version 1

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1`; consumers must reject unsupported versions. |
| `command` | The selected `verify-*` command. |
| `mode` | Requested `extend` or `retained_only` mode. |
| `exit_code` | Intended process exit code before report-output errors. |
| `outcome` | `ACCEPT`, `REJECT`, `REFUSED`, or `null` when no overall verification outcome is available. |
| `error` | `null`, or `{ "stage": "...", "category": "usage" or "operational" }`. |
| `persistence` | `not_requested`, `not_attempted`, `read_only`, `saved`, or `failed`; see below. |
| `verification_context` | Existing context schema version 1, or `null` if setup stopped before context capture. |
| `verification_tip` | `{ "hash": "...", "height": ... }` for the state used after successful extension or retained-state validation; otherwise `null`. This is not a freshness claim. |
| `state_trust` | External assumptions of that state, as an array. |
| `results` | Ordered result rows for checks actually performed, including setup refusals/rejections. |
| `caveats` | Existing acceptance caveats when the overall verification accepted, even if saving subsequently failed. |

Error stages are `arguments`, `genesis`, `protocol_profile`, `bundle`,
`schedule`, `state_lock`, `state`, `context`, `verification`, or `persistence`. These are
diagnostic stages, not proof reasons. Decoding an invalid/ambiguous bundle is
an operational error; an oversized bundle is a resource REFUSED result.
Byte or array-count refusals during decoding use the `bundle` scope with the
matching `ReasonOversized*` code. They precede state loading and context
capture, so they do not identify an evaluated segment or block. Empty segments
that reach evaluation retain their synthetic `segment` reference.

Stateful commands enforce [writer ownership](state-writer-locks.md) before
loading state. Contention or an unavailable lock is an operational setup
failure, not a proof REJECT or REFUSED. Retained-only queries do not take a
writer lock or create its companion file.

`not_requested` means no state destination was configured. `not_attempted`
means a destination was configured but execution stopped before saving.
`read_only` records requested retained-only mode: it never saves, even on
failure. `saved` means the existing save API returned success on this platform.
`failed` does not guarantee the old file is intact: a failure after rename
can leave new bytes visible with durability unconfirmed. See the existing
[persistence boundary](watch-persistence.md).

Each result row contains:

- `reference`: a scope and optional input indices/target described below.
- `outcome` and `reason`: uppercase outcome and stable `Reason...` tokens,
  preserving the verifier's tri-state semantics.
- `failed_at`: the underlying verifier index, or `-1` if not applicable.
- `proven`, `not_proven`, `trust_assumptions`: explicit arrays, including `[]`
  for empty lists. A missing guarantee is not established. Never combine
  guarantees from unrelated rows into a stronger claim about one target.

Reference scopes and indices:

| Scope | Reference |
| --- | --- |
| `bundle`, `state`, `headers` | A whole-input, trusted-state, or header-extension result. |
| `commitments`, `segments`, `state_value_proofs` | The requested proof array was missing or empty. |
| `commitment` | Zero-based `index`, `momentum_height`, and input `account_header` triple. |
| `segment` | Zero-based segment `index`; per-block results also include `block_index` and input `account_header`. Synthetic segment refusals have no block reference. Decode-time resource refusals use `bundle` instead. |
| `state_value_proof` | Zero-based proof `index` and input `momentum_height`. Consult the input entry for its other claim fields; none are authenticated today. |

An `account_header` has raw hex `address`, unsigned `height`, and hex `hash`.
References describe input claims even when REJECTED or REFUSED; only the
associated accepted guarantees authenticate anything about them. Arrays keep
input order, and index zero is explicitly present. Heights, chain IDs, and
context values can reach the full unsigned 64-bit range. Use a lossless JSON
integer parser; JavaScript's ordinary `JSON.parse` number representation is
not sufficient for every valid value.

## Privacy and resource boundaries

Reports omit file paths, RPC URLs, raw operational error strings, arbitrary
verifier messages, protocol-profile `Source`, producer peer audit metadata,
and state-proof keys/claimed values/proof nodes. They still contain selected
account targets, chain configuration, hashes, and outcomes. Treat this query
information according to the application's privacy policy before sharing it.
Flag parser diagnostics and normal text mode retain their existing behavior.

The existing bundle byte/count limits run before report rows are collected.
Reports keep only result envelopes and selected references, not full evidence
or header arrays. JSON mode collects and encodes the report in memory; the
existing limits are not a total process-memory or cumulative-query budget.
No new RPC calls, state writes, acceptance paths, or stronger trust guarantees
are introduced by choosing JSON output.
