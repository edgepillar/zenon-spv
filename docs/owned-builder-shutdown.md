# Owned BuildKit shutdown policy

The disposable image builder and the six runtime services have different
shutdown contracts. Both builds must complete, their loaded image IDs and
source/recipe labels must match, and the owned builder must stop before any
runtime image can be returned. The builder does not contain the RPC ledger.
Its cache shutdown exit code does not establish or replace ledger closure.

## Pinned upstream behavior

The reviewed contract selects the Linux/amd64 image
`moby/buildkit@sha256:97719ccb2ac86fb44fd36f330a6d302f63dddd5326f3ada24f9c05ccac0d9098`.
The 2,261-byte OCI manifest binds a 2,667-byte configuration with SHA-256
`e0eaf1662033859b0b7c643e456061567d3c4eec7c7ced0e2952c5301b0d2814`.
The configuration declares version `v0.34.2`, source repository
`https://github.com/moby/buildkit` and revision
`8c579433824224dc64a158cf8734495b6e2b186a`.

At that declared revision:

- [The entrypoint](https://github.com/moby/buildkit/blob/8c579433824224dc64a158cf8734495b6e2b186a/hack/buildkitd-entrypoint#L15) execs `buildkitd`, optionally through its cgroup namespace wrapper.
- [The signal context](https://github.com/moby/buildkit/blob/8c579433824224dc64a158cf8734495b6e2b186a/util/appcontext/appcontext.go#L51) cancels with a non-nil error on the first SIGTERM/SIGINT.
- [The daemon action](https://github.com/moby/buildkit/blob/8c579433824224dc64a158cf8734495b6e2b186a/cmd/buildkitd/main.go#L459) takes that context cause, performs server shutdown and returns the error; `main` exits with code 1 for an application error.

This source path admits exit code 1 during a requested signal shutdown. A
universal zero-exit requirement can therefore reject this source-supported
builder shutdown case. These observations bind immutable registry bytes and the publisher's
declared Git source. They are not signed distribution or independently
reproduced binary/source correspondence. The review retained about 64 KiB of
manifest/configuration and source bytes without downloading image layers.

## Builder-only acceptance

`owned-buildkit-quiescence/v1` accepts exit code 0 or 1 only for the exact
create-returned `buildkit` container. The existing daemon, owner nonce,
contract, image and configured-resource checks remain in force. The state
must report all of the following:

- `Running`, `Restarting`, `Dead`, `Paused` and `OOMKilled` are false.
- PID is the integer zero; status is `exited`; the runtime error string is empty.
- Exit code is an integer 0 or 1, with matching post-stop and final observations.

Missing fields, coercions, OOM, active processes, runtime errors, changed
ownership/limits and other exits, including 137/143, refuse the handoff. Only
the owned immutable container ID is removed, without a force option. Each
stopped-state observation remains in the evidence index. The image preparation
report records the policy and observed exit code, and explicitly establishes
no runtime-ledger closure.

Code 1 alone does not classify a particular exit as benign. Successful build
captures and verified loaded images precede the handoff; an incomplete or
mismatched build cannot return runtime images merely because the builder stops.
Cleanup can observe the owned cache service stopped while the original build
failure remains a failure.

The six services `pillar`, `pillar2`, `pillar3`, `rpc`, `executor` and `gateway`
retain the original zero-exit predicate. None can use the builder-only scope.
The closed-ledger roster, original RPC volume, read-only oracle, header/profile,
producer schedule and query context requirements remain separate.

## Historical and execution limits

The [first authorized attempt](owned-devnet-attempt-2026-11-13.md) remains
`REFUSED` at image preparation. Its missing state fields cannot be reconstructed
from the retained stdout hash. The source finding identifies a compatibility
defect; it does not establish which historical predicate failed or turn that
run into a successful builder, chain or consumer execution.

The regression controls use synthetic daemon replies and regular temporary
files. They run no image, node, wallet or signed fixture operation. A new actual
fixture requires a separate exact-source approval and retained run/command/
artifact verification. Actual H2/H3, closed-ledger schedule, proof and consumer
acceptance remain open; production eligibility and representative R1 inputs
retain their independent gates.
