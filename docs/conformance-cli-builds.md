# Fresh grouped command builds for conformance

Compiled conformance scenarios previously invoked the Go tool once for each
selected command. A scenario using the collector, verifier, query consumer and
observer therefore loaded the shared package graph four times before running
the same four ordinary executables.

The test helper now builds its selected main packages in one Go invocation with
an explicit private output directory. The Go build uses `-p 1` to bound build
parallelism. Every invocation still creates all selected ordinary executables
in that test's fresh temporary directory. There is no shared executable cache,
hard link, cross-test path reuse, skipped build or retry.

This affects the test harness only. The shipped command sources, runtime
verification, fixture bytes and scenario selections are unchanged. The existing
full test suites, 59-scenario offline pilot, content/retention grids, application
concurrency, process-memory checks and independent byte oracles remain required.

## Execution and evidence boundaries

The source-read registrations that invalidate cached Go test results remain
unchanged. Toolchain selection, disabled downloads, ordinary child build flags,
per-command binary hashing, candidate export checks and execution markers also
remain unchanged. A failed grouped build fails the scenario before binary
execution or export; any partial compiler output belongs only to the test's
temporary directory.

The grouped command receives the sum of the previous one-minute per-command
build allowances. It no longer applies a separate one-minute deadline to each
individual command within that group. The caller's whole test/pilot deadline
still bounds the scenario. Current selections contain at most seven commands.
Build concurrency is separate from application test concurrency, which is
unchanged.

Candidate exports remain independent files. Repeated exports compare complete
size/hash evidence and preserve the original file identity instead of replacing
an earlier export. Parent race instrumentation does not turn the exported child
executables into race builds.

## Controls and observations

`TestQueryCLIBuildBatch` preserves the complete previous helper body from
`6fa8300ac6fa0df638cfa727abfb641ee9630ca1` as its individual-build reference.
It compares all seven supported command binaries byte for byte, checks native
ordinary build metadata, and verifies distinct output identities. It then
mutates a newly built private output, builds that command again into another
fresh directory, and checks that the reference and all existing candidate exports
retain their original bytes and file identities.

The reference runs seven Go build commands for the seven-command group; the
grouped helper runs one. The separate fresh-rebuild control runs one additional
command. `TestQueryCLIBuildPlan` covers five selections, including reversed order,
single and mixed command/tool groups, output paths with spaces, ordinary flags
and bounded build parallelism.

A separate native child deliberately selects a missing package. Its actual
exit must be 1, without a deadline or retry, binary execution marker or partial
candidate export. The parent checks that an unrelated retained control file
keeps its bytes and identity. This expected failure is separate from the
successful control-suite result.

Native CI executes these controls on Linux, macOS and Windows. Its single
reference-then-grouped timing observation is not counterbalanced and has no
performance threshold. Initial local counterbalanced observations used a new
owned compiler cache warmed for all seven packages; those timings also include
task-manager supervision. Neither observation qualifies a whole-CI speedup,
peak-memory reduction or sustainable device budget. The reduction in Go-tool
launches is distinct from those performance claims.

No canonicality, consensus finality, activation, state-value acceptance or
production qualification follows from this test-harness change.

## Reproduce

Use cached dependencies and an owned bounded workspace for compiler caches,
temporary outputs and private diagnostics.

```sh
go test -race -count=1 -run '^TestQueryCLIBuild' ./internal/conformance
go test -race -count=1 -timeout=10m ./internal/conformance
go run ./tools/offline-pilot --race --export-binaries "$NEW_PRIVATE_CANDIDATE_DIRECTORY"
```
