# Compiled CLI query conformance

`TestCompiledCLIQueryWorkflow` builds the shipped `zenon-spv` and
`fetch-bundle` commands into a temporary directory and invokes them as
subprocesses. This covers command dispatch, actual exit status, JSON framing,
stdout/stderr separation, and file effects across both programs.

Run the focused workflow with the repository's Go toolchain on `PATH`:

```sh
go test -race ./internal/conformance -run TestCompiledCLIQueryWorkflow -v
```

It also runs as part of ordinary `go test ./...`. CI executes the full suite
on native Linux, macOS, and Windows runners. The macOS/Windows jobs disable
test-result caching with `-count=1`; Linux retains its race-enabled test and
lint job. No public RPC, wallet, or credentials are required.
Subprocess builds use the local Go toolchain and cached dependencies
with module/network lookup disabled. The normal repository dependencies must
already be available, as they are after the parent test build.
Command and internal helper source files are registered as test inputs so
an edit to a package used only by the CLI invalidates Go's cached result.

## Exercised boundaries

The fixture uses the pinned node-derived [contract batch corpus](contract-batches.md).
The test owns three loopback JSON-RPC servers and temporary files. RPC URL
credentials and query tokens are synthetic; it verifies that requests preserve
them and normal command output does not disclose them.

The workflow checks:

- Seed a trusted retained window with the compiled header verifier.
- Collect a proof-only account segment with two agreeing peers and one peer
  whose reordered descendant blocks fail account conversion.
- Query commitments and segments in new verifier processes. Decode the report
  independently of the command package and check command identity, zero-based
  result references, exact node-derived targets, anchor/context identity, and
  bounded `CONTENT_INCLUSION` guarantees.
- Stream the same complete bundle to stdout without mixing progress logs into it.
- Refuse invalid collection options before RPC or output-file changes.
- Preserve explicit-mode, retained-state, strict-past-depth, chain-identity,
  and content-integrity checks across real process boundaries.
- Keep state-value inclusion unsupported, with an explicit REFUSED report.
- Preserve the prior candidate when all peers return invalid account evidence,
  emit no partial stdout bundle, and keep that prior candidate usable.
- Reject replaced or oversized momentum/account range lists before collecting
  evidence; preserve candidate bytes, identity, mode, and modification time,
  and emit no partial stdout bundle.
- Reject oversized nested content and descendant lists during RPC decoding,
  with the same file and stdout guarantees and no private payload in diagnostics.
- Report usage/setup failures separately from proof outcomes and save failures
  separately from accepted header verification.
- Return a nonzero process status for a closed stdout pipe while preserving
  state already saved before the report write.

Queries preserve trusted-state bytes, file identity, modification time, and
mode. The fixture marks that file read-only but does not rely on permissions
alone: replacing a file through a writable parent must also be detected.
Per-process timeouts bound a hung test; the closed-pipe check accepts platform
error/signal behavior rather than prescribing one Unix shell exit number.

`TestCompiledCLIStateWriterExclusion` synchronizes a watch process inside a
local RPC request, then runs competing stateful commands and a read-only
query. The writers must fail before verification/RPC; the query keeps its
ordinary depth refusal. After watch shutdown, the next process can acquire
ownership and advance the saved tip. This locks in the lost-update regression
described in [state writer ownership](state-writer-locks.md).

The actual save-failure scenario precreates a usable companion lock in a
directory without write permission. It is skipped when the filesystem or
process privileges still permit writes there; other scenarios continue.

`TestCompiledCLIBuildIdentity` also invokes the version commands in both
executables and compares their reports with independently read binary metadata.
It checks version dispatch before configuration or RPC access; see
[build identity](build-identity.md).

`TestCompiledCLIStateInspection` seeds state through the compiled verifier,
then checks the separate [inspection report](state-inspection.md) against
node-derived header identities. It checks policy changes, missing/invalid
state, private error filtering, no companion-file creation, and read-only
coexistence with a writer in another process. A counted loopback endpoint
confirms that inspection makes no RPC requests.

## Evidence limits

This is synthetic offline inclusion evidence against explicitly trusted local
anchor/state inputs. It does not validate VM execution, live activation,
balance proofs, freshness, canonical-chain selection, or consensus finality.
When used, `-race` instruments the Go test and its in-process peer handlers;
the compiled child CLIs are ordinary builds. Existing command/core race tests
cover the code in-process separately. The workflow is a focused query-path
conformance test, not the full CLI or platform conformance plan.
