# Verification context

`VerifiedState.VerificationContext()` returns a detached diagnostic snapshot
of the handle's verification settings. `VerificationContextJSON()` encodes
the same snapshot as one JSON object. Both refuse an uninitialized handle.
The snapshot is not a proof, a signed receipt, or a way to import verified state.

## Record settings with a result

Inspect configuration before creating state or contacting a peer:

```sh
zenon-spv inspect-config --genesis-config anchor.json \
  --protocol-profile activation.json --schedule producers.json --window low --json
```

This loads and validates the selected trust inputs, constructs an empty
`VerifiedState`, and reports its captured context. It does not read a state
file or bundle, acquire a writer lock, contact RPC, or check producer coverage
for any requested evidence. Without an explicit anchor it follows the same
environment/embedded-mainnet selection as verification. Use an explicit
anchor for reproducible operator runs.

The configuration report has `schema_version: 1`, `command: "inspect-config"`,
`status: "configured"` on exit 0, `exit_code`, `error`, `verification_context`,
`trust_assumptions`, and fixed `caveats`. There is no proof outcome or retained
window. Invalid arguments exit 64; configuration/output errors exit 70.
Errors expose only a fixed stage/category, with no context or trust claims.
Text mode prints one `verification_context: {JSON}` line and caveats.

After reviewing those settings, retain the reported fingerprint separately
from editable configuration files and require it on subsequent commands:

```sh
zenon-spv verify-headers --genesis-config anchor.json \
  --protocol-profile activation.json --schedule producers.json --window low \
  --expect-context "$EXPECTED_CONTEXT" --json bundle.json
```

`--expect-context` is available on every `verify-*` command, `inspect-state`,
and both watch modes. It accepts exactly 64 hexadecimal characters (either
case), without a prefix or whitespace. Omission preserves existing behavior;
an explicitly empty or malformed value exits 64 and cannot disable the check.
All verification flags must precede the bundle path.

A mismatch exits 70 before new evidence verification, watch startup/RPC, or
state saving. Verification and state-inspection JSON reports identify
`error.stage: "context_pin"`; they contain no proof outcome or usable context.
JSON watch emits no event and the fixed stderr message `watch: operation failed`.
Normal setup checks still apply first: the bundle can be decoded and rejected
by its limits/identity checks, saved state can be loaded and re-authorized,
and writers can acquire/create a companion lock before comparing settings.
Those earlier failures retain their existing classifications. State bytes
are not saved by a failed pin check; do not remove a companion lock file.

The API equivalent is `state.RequireContextFingerprint(expectedHash)`;
it checks the handle's owned settings, not a caller-created context object.
An uninitialized handle fails; a required custom authorizer fails with
`ErrContextFingerprintUnavailable`. `syncer.Loop.ExpectedContext` applies
the same requirement after trusted-state loading and before startup output.
A match adds no guarantees and preserves ordinary ACCEPT/REJECT/REFUSED
outcomes. See the [operator workflow](operator-pilot.md) for the complete path.

The optional `--show-context` flag is available on every `verify-*` command
and on `watch`:

```sh
zenon-spv verify-headers --genesis-config anchor.json \
  --protocol-profile activation.json --schedule producers.json \
  --show-context bundle.json
```

In text mode, verification commands emit one `verification_context: {JSON}`
line on stdout after successful setup and bundle preflight, before verification.
The line can therefore precede REJECT or REFUSED; it does not mean ACCEPT.
Setup/preflight errors do not produce a context. Watch emits the same line
on its configured log writer once after loading and re-authorizing state,
before its first tick. The default output and per-tick format are unchanged.
Applications can set `syncer.Loop.ShowContext` for the same startup diagnostic.

With `--json`, verification commands include the context inside the single
[verification report](verification-reports.md). In that mode `--show-context`
does not produce an extra line.

An application can record the API value without logging raw configuration:

```go
raw, err := state.VerificationContextJSON()
if err != nil {
    return err
}
fmt.Printf("verification_context: %s\n", raw)
```

The object includes:

- Schema version, anchor chain ID, height, and hash.
- Depth `W` and every captured resource limit, including disabled zero limits.
- The explicit profile's schema, coverage end, and first v2 height. Its anchor
  is already required to equal the context anchor. A null profile means legacy
  v1-only verification without an activation assertion.
- Producer mode and source classification. Built-in schedules include their
  validated substantive `ScheduleHash`; disabled authorization includes none.
- Applicable embedded checkpoints, sorted by height. Non-mainnet contexts
  carry an empty list, matching the verifier's current checkpoint selection.

These fields describe configuration, not guarantees established by an
operation. In particular, aggregate bundle limits still require CLI preflight,
and `W` is not a finality certificate. Record the result, required `Proven`
guarantees, trust assumptions, evidence, retained-state provenance, peer
assumptions, and source/binary identity separately. Watch interval, quorum,
safety margin, persistence behavior, and retained history are outside this
verifier-settings object.

## Privacy and identity boundaries

Paths, endpoint URLs, schedule audit metadata, and the profile's free-form
`Source` label are omitted entirely, including from the fingerprint. Only this
diagnostic object is filtered; existing error and progress logs are unchanged.
The remaining anchor and policy fields still identify the selected experiment,
so reporting is opt-in.

For disabled authorization and the built-in schedule authorizer,
`fingerprint_status` is `available`. The SHA3-256 fingerprint identifies the
displayed settings under the encoding below. It is stable across extension,
save/resume, and JSON formatting. Changing an anchor, rule, limit, schedule,
or applicable checkpoint changes it. A profile Source-only edit intentionally
does not change it, although existing state loading still requires the entire
profile, including Source, to match. Equal fingerprints are therefore not a
state-file compatibility token and do not authenticate provenance.

A required custom authorizer reports `kind: "custom"`,
`fingerprint_status: "unavailable_custom_authorizer"`, and a null fingerprint.
The API cannot identify or freeze arbitrary callback behavior. Its captured
source classification is a caller declaration, not a proof. Context inspection
does not invoke the callback or change authorization/verification outcomes.

The context does not identify the verifier implementation or binary. Matching
settings across different builds do not establish identical verifier behavior.
These records add no canonicality, network activation, elected-producer, or
consensus-finality guarantee.

## Fingerprint encoding, schema 1

Hash the following concatenation with SHA3-256. Integers, including presence
flags and schema versions, are unsigned 64-bit big-endian. Hashes are their
32 raw bytes. Strings are UTF-8 prefixed by an unsigned 64-bit byte length.

1. ASCII `zenon-spv/verification-context/v1` followed by one zero byte.
2. Context schema version, anchor chain ID, anchor height, anchor hash.
3. Policy values in order: `w`, `max_bundle_bytes`, `max_headers`,
   `max_commitments`, `max_flat_evidence_members`,
   `max_total_flat_evidence_members`, `max_segments`, `max_segment_blocks`,
   `max_total_segment_blocks`, `max_state_value_proofs`,
   `max_state_proof_nodes`, `max_state_proof_bytes`.
4. Profile presence (`0` or `1`). When present: profile version,
   `valid_through`, `v2_from_height` (including an explicit zero).
5. Producer mode string (`Disabled` or `Required`), source string (`None` or
   `OperatorAttested` for fingerprintable contexts), and kind string
   (`disabled` or `schedule`).
6. Schedule-hash presence (`0` or `1`), followed by its raw hash when present.
7. Checkpoint count, followed by each ordered checkpoint's height and hash.

Neither the `fingerprint` nor `fingerprint_status` presentation fields are
inputs to the hash. No fingerprint is emitted for custom authorizers.
Future semantic fields require an explicit schema/encoding review; never
silently reuse schema 1 for a different input sequence.

## Validation

Tests cover every policy field, anchors, profile rules, metadata exclusion,
schedule and checkpoint identity, detached views, custom callbacks, concurrent
readers, CLI outcomes, and watch persistence. The node-derived v1/v2 corpus
checks that context is stable through extension and trusted resume.

Two [synthetic vectors](../internal/testdata/verification-context/README.md)
were computed with Python's `hashlib.sha3_256`, independently of the Go
fingerprint implementation. Check them with:

```sh
python3 tools/check-verification-context.py
go test -race ./...
```
