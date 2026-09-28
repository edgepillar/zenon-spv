# Verified state API

The CLI verification commands and watch loop use `verify.VerifiedState`.
It owns the retained headers and captures their anchor, policy, activation
profile, and producer authorization settings. The lower-level `HeaderState`
and free verifier functions remain available for compatibility and testing;
they still require callers to maintain verified-state provenance themselves.

## Construct and extend

`NewVerifiedState(anchor, opts)` creates an empty handle under explicitly
trusted inputs. It checks the anchor, profile, producer configuration, and
policy window before allocating state. Windows above 100,000 are refused.
Negative resource limits are invalid; zero limits retain their documented
disabled meaning, so applications should start with `DefaultPolicy()`.

```go
opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
state, err := verify.NewVerifiedState(anchor, opts)
if err != nil {
    return err
}
result, next := state.Extend(headers)
if result.Outcome != verify.OutcomeAccept {
    // Keep state. REJECT and REFUSED never advance the handle.
    return fmt.Errorf("header verification: %s", result)
}
if err := next.Save(statePath); err != nil {
    // A failure after rename can leave new bytes visible on disk.
    // Keep the prior in-memory state and report the persistence error.
    return err
}
state = next
commitmentResult := state.VerifyCommitment(evidence)
```

`Extend` returns a separate handle on ACCEPT. Query methods use the captured
policy; callers cannot lower `W` or replace an activation profile at query
time. `VerifySegment` and `VerifyStateValue` preserve the existing bounded
semantics. State-value verification still has no accepting implementation.
Per-item resource checks remain in the core; aggregate bundle checks remain
in the CLI preflight. This API does not replace those bundle limits.

The zero value refuses verification and persistence. Direct JSON encoding or
decoding of a handle fails: use `Save` and `LoadTrustedState`. There is no
constructor that turns an arbitrary `HeaderState` into a verified handle.

## Ownership

- Accepted headers, including public-key and signature bytes, are detached
  from caller-owned input. Inputs must remain unchanged until the call returns.
- `Tip` and `Snapshot` return detached copies. Editing them cannot change the
  handle, its predecessor, or a later extension. `Snapshot` supports inspection
  and persistence adapters; it is not a route for importing verified state.
- Activation profiles and built-in producer schedules are copied. Schedule
  structure, hash, and chain ID are checked, and its lookup index is rebuilt.
- Custom producer authorizers remain trusted caller-supplied behavior. They
  must remain stable and be safe for concurrent use when shared. Their source
  classification is captured; required authorization refuses missing or
  unsupported source classifications. Callbacks receive disposable public-key
  copies rather than access to state memory.
- Immutable handles support concurrent reads. This does not authorize
  concurrent writers to a state file; the existing exclusive-writer
  persistence requirement still applies.

The watch persistence adapter receives a detached `HeaderState` snapshot.
Its success still means the adapter fulfilled its persistence contract; the
verifier cannot prove that an arbitrary adapter actually wrote durable bytes.

## Trusted local resume

`LoadTrustedState(path, anchor, opts)` explicitly crosses a local trust
boundary. It initializes an empty handle if the file is absent. For an
existing file it runs the bounded integrity checks, requires the configured
anchor and activation profile to match, and re-authorizes retained producers
under the requested policy. It does not trust a caller-supplied authorization
flag from JSON. Authorization failures retain their REJECT or REFUSED result
in `StateAuthorizationError`; file/configuration errors return ordinary errors.

Accepted API results report `TRUST_CONFIGURED_ANCHOR`. Results descended from
a nonempty loaded window also report `TRUST_PERSISTED_STATE`, including after
later extensions replace the retained entries. Applicable protocol-profile
and operator-schedule assumptions remain explicit. `TrustAssumptions()` returns
these captured inputs without claiming that a proof has succeeded; watch
prints them at startup.

The handle protects in-process ownership and verification provenance. It does
not authenticate the origin of a local file, reconstruct evicted history,
establish an independently elected producer set, select a canonical fork, or
prove consensus finality. Protect the anchor and state file externally. See
[the verification contract](verification-contract.md) and
[watch persistence](watch-persistence.md).

## Validation

Tests cover zero and deserialized handles, caller/view mutation, captured
depth and profile policy, transactional extension, corrupt resume files,
producer reauthorization and schedule mutation, callback memory isolation,
concurrent readers, and CLI/watch integration. The independent node-derived
corpus also exercises a v1-to-v2 transition through save, resume, and content
verification using this API. These are synthetic and local-server checks,
not evidence of public-network activation or deployment readiness.
