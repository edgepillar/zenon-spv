# Tested native candidate artifacts

The offline pilot can retain the ordinary compiled executables that its
scenarios actually execute. This supplies the same byte candidates for
independent review and a later controlled read-only pilot. It does not
complete either acceptance gate or publish an authenticated release.

## Export during a run

Use a new absolute directory outside the checkout, with an existing protected
parent. The parent, source, toolchain, module cache and running tests remain
trusted. The option is explicit; ambient `ZENON_SPV_*` values cannot enable an
export in the driver. An existing directory is refused without replacement.

```bash
go run ./tools/offline-pilot --race \
  --export-binaries "$NEW_CANDIDATE_DIRECTORY" > "$REPORT_FILE"
```

Check the actual exit status. Successful tests with source unchanged export
seven executables: `zenon-spv`, `fetch-bundle`, `derive-checkpoints`,
`derive-producer-schedule`, `verify-mainnet-genesis`, `consume-query-report`
and `observe-block`. Windows filenames end in `.exe`. The driver does not
perform a separate packaging build. Repeated scenario builds must have the
same bytes, and an earlier exported executable is never overwritten.
Each executable is a regular file of at most 128 MiB.

The final directory also contains `offline-pilot.json`, exactly matching the
successful stdout report, and `manifest.json`. The manifest is written last
after all seven saved executable hashes match every scenario's execution
records. Missing, additional, changed, empty or nonregular files and
conflicting execution records prevent completion. Metadata files are created
exclusively, never over an existing file. Failed or interrupted runs can leave
partial exports; a directory's existence is not a successful result. A final
stdout write failure can leave a complete package while the actual driver
exit is nonzero. Preserve that failure rather than claiming a successful run.

These checks assume the protected directory and files are stable while used.
They do not authenticate filesystem ownership, Windows ACLs, continuous source
history or a concurrently modified executable. No binary is installed or run
as part of packaging after the tests complete.

## Manifest schema 1

The fixed mode is `offline_synthetic_candidate`. The manifest records native
OS/architecture, filtered Go version, observed source revision/modified state
and input fingerprint, six corpus identities, the report's relative filename,
SHA-256 and byte size, and each executable's fixed relative filename, SHA-256
and size. Its `test_status` preserves `passed_with_skips`; inspect the report's
scenario counts and skip reasons in the corresponding CI logs.

The source fingerprint retains the [offline report's scope](offline-pilot.md):
Go/module/JSON inputs including tests and fixtures. It excludes docs, CI,
Python checkers, the toolchain and external build inputs. A source archive may
have unknown Git fields, and local work can be modified. Those diagnostics do
not become reviewed release provenance. Native CI artifacts below require an
independently checked checkout and successful pipeline before use.

## Select and check a CI archive

Each successful native CI pilot uploads `tested-candidate-linux`,
`tested-candidate-macos-latest` or `tested-candidate-windows-latest`, alongside
the existing `offline-pilot-*` report. Artifacts expire after 14 days. A package
contains exactly nine files, with no source archive, installer or signing key.
Do not infer a successful full pipeline merely from an upload step.

Select the repository, run/event, actual tested checkout, target platform and
expected input fingerprint independently. Review successful Linux/macOS/Windows
checks, skips, source tree, toolchain/dependency provenance and the workflow
that created the artifact. A pull-request run can test a synthetic merge
checkout; its revision can differ from the PR feature head. Use the verified
checkout revision and compare its tree with the reviewed candidate.

Obtain the ZIP SHA-256 from that selected artifact's GitHub metadata, and
verify the downloaded bytes. A digest copied out of the downloaded manifest
cannot authenticate its own provenance. Do not derive every expected pin from
the candidate archive being checked.

The stdlib-only Python checker reads a protected ZIP without extracting or
executing any payload:

```bash
python3 tools/check-candidate-archive.py \
  --archive "$CANDIDATE_ZIP" \
  --expect-archive-sha256 "$SELECTED_ZIP_SHA256" \
  --expect-revision "$SELECTED_CHECKOUT_REVISION" \
  --expect-inputs "$REVIEWED_INPUTS_SHA256" \
  --expect-os "$SELECTED_OS" \
  --expect-architecture "$SELECTED_ARCHITECTURE"
```

On Windows, use the Python 3 executable available to the operator. `os` is
`linux`, `darwin` or `windows`; architecture is the selected native Go target.
The checker requires clean, known Git fields matching the selected pins. It
refuses duplicate/extra/path-traversal ZIP entries, directory/symlink entries,
encrypted/unsupported compression, duplicate or unknown metadata fields,
floats and non-uint64 numbers, inconsistent status/source/platform metadata,
and report/executable hashes that disagree with the recorded execution. It
streams opaque binary hashes; it does not validate executable semantics or
authenticate test execution or the scenario selection. Archive input is at
most 256 MiB, manifest input 256 KiB and report input 4 MiB, with bounded JSON
depth, strings, collections and nodes. Keep the open archive stable during
checking; in-place replacement by an untrusted writer is outside this tool.

Exit 0 and `status: verified` mean these byte/pin/consistency checks passed.
Exit 2 rejects an archive, 64 rejects invocation and 70 means output delivery
failed. Output has only fixed status/category and binary/skip counts; paths,
pins and raw errors are not echoed. Inspect the actual process exit too.

The unsigned manifest and diagnostic do not authenticate a release, reviewer,
network, anchor, activation, producer election, canonicality, consensus
finality or state value. Independent exact-candidate review and binary/report
channel provenance remain required. Follow the [operator workflow](operator-pilot.md)
with independently selected inputs before any controlled network run.
