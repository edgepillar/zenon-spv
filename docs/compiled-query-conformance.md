# Compiled CLI query conformance

`TestCompiledCLIQueryWorkflow` builds the shipped `zenon-spv` and
`fetch-bundle` commands into a temporary directory and invokes them as
subprocesses. This covers command dispatch, actual exit status, JSON framing,
stdout/stderr separation, and file effects across both programs.

Run the focused workflow with the repository's Go toolchain on `PATH`:

```sh
go test -race ./internal/conformance -run TestCompiledCLIQueryWorkflow -v
```

It also runs as part of ordinary `go test ./...` and the existing CI test
step. No additional service, workflow, public RPC, wallet, or credentials are
required. Subprocess builds use the local Go toolchain and cached dependencies
with module/network lookup disabled. The normal repository dependencies must
already be available, as they are after the parent test build.
Command source files are registered as test inputs so a CLI-only edit
invalidates Go's cached result for this workflow.

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
- Report usage/setup failures separately from proof outcomes and save failures
  separately from accepted header verification.
- Return a nonzero process status for a closed stdout pipe while preserving
  state already saved before the report write.

Queries preserve trusted-state bytes, file identity, modification time, and
mode. The fixture marks that file read-only but does not rely on permissions
alone: replacing a file through a writable parent must also be detected.
Per-process timeouts bound a hung test; the closed-pipe check accepts platform
error/signal behavior rather than prescribing one Unix shell exit number.

## Evidence limits

This is synthetic offline inclusion evidence against explicitly trusted local
anchor/state inputs. It does not validate VM execution, live activation,
balance proofs, freshness, canonical-chain selection, or consensus finality.
The `-race` flag instruments the Go test and its in-process peer handlers;
the compiled child CLIs are ordinary builds. Existing command/core race tests
cover the code in-process separately. The workflow is a focused query-path
conformance test, not the full CLI or platform conformance plan.
