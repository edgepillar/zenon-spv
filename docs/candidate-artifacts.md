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
Each executable must be a nonempty regular file of at most 128 MiB. The driver
checks the selected path and opened descriptor, requiring the same file
identity and size before hashing. It streams exactly that length through a
32 KiB buffer, then requires real EOF and a successful close. Shrinkage,
growth, replacement identity, read errors and close errors discard the digest.
Linux/macOS opens also refuse a final-component symlink replacement and avoid
waiting for a replacement FIFO writer. Native Windows controls cover regular
file identity, size, type and descriptor cleanup; they do not qualify Unix
FIFO behavior or a Windows reparse-point ownership boundary.
Windows captures the initial file identity from a metadata handle before
opening the hashing descriptor, because path metadata can defer identity
lookup until after a replacement. That metadata handle is closed before the
read open and never reads executable contents.

The conformance scenarios apply the same opened-descriptor, exact-length, real
EOF and successful-close checks when recording a compiled executable's raw
SHA-256, copying a new export, and comparing an earlier export. Copying closes
both input and output before success. A read, write, size, digest or close
failure removes only the newly created incomplete copy. A failed repeated
export preserves the earlier file, and its selected input must also close
successfully. These checks retain the 128 MiB limit and 32 KiB read buffer;
they do not freeze contents between hashing, exporting and scenario execution.

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
and input fingerprint, pinned corpus identities, the report's relative filename,
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
`tested-candidate-macos-15-intel` or `tested-candidate-windows-latest`, alongside
the existing `offline-pilot-*` report. Artifacts expire after 14 days. The tested
export contains exactly nine files, with no source archive, installer or signing
key. The workflow packages those same files into one canonical
`candidate-v1.tar.xz` payload inside a stored ZIP envelope. Original direct
nine-member ZIPs remain readable and keep their original evidence identities.
Do not infer a successful full pipeline merely from an upload step.

The current hosted macOS job uses the Intel image and produces `darwin/amd64`
binaries. Match the artifact manifest to the intended OS and architecture;
these results do not establish hosted macOS ARM coverage for this successor.

Before that upload, native CI also checks the actual exported directory with
`tools/check-exported-candidate.py`. It independently reads the current
checkout's Go/module/JSON inputs using the offline pilot's length-prefixed
SHA-256 format, checks its clean Git root and expected checkout revision,
then opens all nine exported regular files and streams each member once through
the existing archive checker's shared complete payload validator. No temporary
candidate ZIP is created. Exact directory layout, metadata, execution records,
source/platform pins and actual payload hashes must pass. A second checkout check
refuses source drift during validation. The source-checked stream writer and
completed-file readback run after the compiled-consumer checks; candidate upload
also requires that stream step and the scenario inventory to succeed. The pinned
upload action stores the already compressed payload without recompressing it.
The checker never executes an exported binary or
replaces an exported file. See the [direct validation contract](direct-candidate-validation.md).

The checkout input scan allows at most 32,768 entries, 32 directory levels and
64 MiB of selected input bytes. Export input bounds match the archive checker,
with a combined payload limit of 256 MiB minus 64 KiB of ZIP overhead. Files
must be regular. Their opened descriptors must match the selected OS file
identity and size before source hashing or export streaming, and keep that
size while read. Direct export validation also retains all nine descriptors
until final path/descriptor metadata and exact directory inventory checks pass; available
nonblocking/no-follow flags are used. Protected stable source/export parents
and the CI job deadline remain required. This checks local export consistency;
the later uploaded/downloaded ZIP still needs its separately selected GitHub
digest and independent candidate/review provenance checks below.

Select the repository, run/event, actual tested checkout, target platform and
expected input fingerprint independently. Review successful Linux/macOS/Windows
checks, skips, source tree, toolchain/dependency provenance and the workflow
that created the artifact. A pull-request run can test a synthetic merge
checkout; its revision can differ from the PR feature head. Use the verified
checkout revision and compare its tree with the reviewed candidate.

The native workflow pins each external action to a full commit SHA. Review
action changes as executable build inputs and confirm the downloaded action
identities in the selected run's setup logs. These pins do not freeze runner
images, the selected Go/Python version ranges, downloaded tools or module-cache
contents, and do not authenticate a candidate release.

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

The reader accepts the original direct ZIP layout and the single stored
`candidate-v1.tar.xz` member configured for new CI uploads, using the same payload
checks. See the [stream format and qualification limits](candidate-stream.md)
and verify the actual selected run before use. Original evidence is not converted
or replaced.
For a directly selected XZ file, the explicit `--raw-stream` option avoids
creating a wrapper ZIP; select the raw file's digest for that operation.

On Windows, use the Python 3 executable available to the operator. `os` is
`linux`, `darwin` or `windows`; architecture is the selected native Go target.
The checker requires clean, known Git fields matching the selected pins. It
refuses duplicate/extra/path-traversal ZIP entries, directory/symlink entries,
encrypted/unsupported compression, duplicate or unknown metadata fields,
floats and non-uint64 numbers, inconsistent status/source/platform metadata,
and report/executable hashes that disagree with the recorded execution. It
requires the `compiled_query_consumer_scaling` case from `internal/conformance`,
named `TestCompiledQueryConsumerScaling`, with records for both `zenon-spv` and
`consume-query-report`. It checks all three fixed workloads and all 21 native
observations per workload, including completeness and first-process agreement.
It also requires `compiled_content_scaling`, named
`TestCompiledContentScalingWorkflow` in `internal/conformance`, with only the
`zenon-spv` executable record, four completed subtests and no skips. Its four
unique verifier workloads must have the declared member/proof dimensions,
exact record fields, positive input bytes up to 64 MiB, elapsed time up to
60 seconds, and a positive native peak-memory counter up to 2^50 bytes.
Linux/macOS use `process_rusage`; Windows uses `windows_peak_working_set`.
Missing/null records, unknown fields and measurements attached to a different
case fail consistency checks. Removing or renaming either measurement case
cannot bypass these checks. These bounds validate record shape; they do not
establish actual execution or target-hardware performance acceptance.
Use the checker from the selected candidate revision; reports without either
the verifier grid or the repeated consumer observations cannot pass these
completeness checks.

Before constructing the standard ZIP reader, the checker scans at most the
last 65,557 bytes for end metadata and counts the actual central-directory
records. Exactly nine fixed filenames must consume the declared directory;
an end record claiming nine entries cannot hide additional records. The
preflight reads fixed headers and names, skips bounded extras/comments, and
rejects malformed directory boundaries before the reader can allocate its
entry list. Ordinary archive comments, prepended ZIP bytes and complete
single-disk ZIP64 end records are supported. ZIP64 end records with extensible
data sectors, competing records at locator-selected offsets, and multi-disk
archives are refused. This bounds ZIP metadata
parsing; it does not prescribe a whole-process peak-memory acceptance limit.

Local ZIP names, compression methods and supported flags must agree with the
central directory. Without a data descriptor, local CRC and sizes must match;
when general-purpose flag bit 3 is set, the required descriptor must supply the
matching CRC and sizes. Signed and unsigned descriptors, and ZIP64 local size extras with
64-bit descriptor sizes, are supported. Malformed placeholders, missing
extended sizes and contradictory records are refused. These layout checks
follow the [PKWARE ZIP specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT),
sections 4.3.9, 4.4.7-9 and 4.5.3.

The checker regression suite runs with Python 3.13 on Linux, macOS and Windows
CI. Its opaque-byte fixtures test archive consistency, not executable behavior
or authenticated test execution.

The checker streams opaque binary hashes; it does not validate executable
semantics or authenticate test execution or the overall scenario selection.
For a separately selected clean source checkout, the
[scenario inventory companion](scenario-inventory.md) additionally compares the
retained report's complete root-scenario selection and declared command records
with the source-owned registry. It reads the existing report and source inputs;
it creates no second candidate ZIP and does not replace the payload validator.
Archive input is at most 256 MiB, manifest input 256 KiB and report input 4 MiB,
with bounded JSON depth, strings, collections and nodes. Metadata reads request
the declared entry size plus one after the nonempty and category-limit checks.
Exact returned length and the ZIP reader's CRC checks remain required, and the
entry stream closes on success or refusal. Stored and deflated fixtures cover
small entries, exact limits, malformed CRC/length and refusal before entry open.
These read bounds do not qualify a whole-process peak-memory budget.
Before opening the selected archive
target, it requires a nonempty regular file within the archive size limit.
It requires the opened descriptor to match the selected OS file identity and
size before hashing or ZIP parsing, and closes it on rejection. Native controls
bound hashing reads to at most 1 MiB and the remaining descriptor-selected
length plus one. Hashing requires the exact selected length and a real EOF;
growth is refused after reading at most one byte beyond that length, before
the extra bytes can update the digest. Short reads continue until EOF, and
shrinkage or a read error prevents a successful hash. Actual-file controls
cover the chunk boundary, partial reads, controlled growth/shrinkage after the
descriptor size check, injected read errors and size refusal before a read.
The caller closes the descriptor on each outcome. These controls do not freeze
contents or establish a whole-process resource budget. The existing controls
replace real files at the open boundary, including replacements with identical
bytes, and grow an archive while preserving its identity. These controls also
check descriptor cleanup and stable-file acceptance. On platforms with
`O_NONBLOCK`, opening also uses that flag so
a FIFO substituted after the initial check cannot wait for a writer. The
native FIFO subprocess controls run on Linux/macOS and explicitly skip on
Windows where `os.mkfifo` is unavailable. Windows still runs the descriptor
type/size and cleanup controls; there is no Windows FIFO execution claim.
Keep the protected directory and open archive stable during checking;
nonblocking open support does not authenticate ownership or exclude every
replacement race, and in-place changes by an untrusted writer remain outside
this tool.

Exit 0 and `status: verified` mean these byte/pin/consistency checks passed.
Exit 2 rejects an archive, 64 rejects invocation and 70 means output delivery
failed. Output has only fixed status/category and binary/skip counts; paths,
pins and raw errors are not echoed. Inspect the actual process exit too.

The unsigned manifest and diagnostic do not authenticate a release, reviewer,
network, anchor, activation, producer election, canonicality, consensus
finality or state value. Independent exact-candidate review and binary/report
channel provenance remain required. Follow the [operator workflow](operator-pilot.md)
with independently selected inputs before any controlled network run.
