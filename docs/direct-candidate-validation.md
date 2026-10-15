# Direct candidate validation before upload

The native CI export checker previously wrote all seven executables and both
metadata files into a temporary uncompressed ZIP, hashed the ZIP, then read its
members again. Upload subsequently created its own archive. The temporary ZIP
was an additional full payload allocation during local export validation.

`tools/check-exported-candidate.py` now opens the nine existing regular files
read-only and streams them directly through the same complete payload validator
used by `tools/check-candidate-archive.py`. It creates no candidate ZIP, extracted
copy, workspace, hard link or second retained payload. Each member is consumed
once. Source fingerprinting still runs before and after validation.

The shared validator retains its exact metadata shapes, duplicate JSON key and
numeric checks, source/platform pins, report digest/count, complete executable
hashes and sizes, scenario execution bindings, and every content/consumer resource
sample. Refactoring this function does not add a new acceptance path for payloads.
The separate ZIP reader retains all central/local record, CRC, compression,
layout, archive digest and independently selected expectation checks.

## Descriptor and resource bounds

The directory must contain exactly the selected seven native command names,
`manifest.json` and `offline-pilot.json`. Each member must be nonempty and regular;
the existing per-file limits and combined 256 MiB minus 64 KiB payload ceiling
remain. Layout and size admission finish before payload validation starts.

All nine descriptors remain open for the complete check. Selected path and
opened descriptor identities and sizes must agree before reading; available
nonblocking/no-follow flags remain in use. Each descriptor can be selected by
the shared validator only once. After all payload checks, every descriptor and
current path must retain its device/inode, mode, link count, size, modification
time and change time. Path and descriptor metadata have separate initial
snapshots: platform APIs may expose different metadata values for the same file.
Their OS file identity and size must agree, and each view must remain stable
against its own snapshot. The directory must retain its identity and exact member
inventory. ExitStack closes every descriptor on success or failure.

These are cooperative stable-input checks, not an atomic filesystem snapshot
or protection against an adversarial same-user writer. Protected stable parent
paths and the CI job deadline remain required. Changes after this check and
before/during upload remain outside its scope. On platforms where an open file
cannot be replaced, an attempted replacement may be denied by the OS itself.

The old `write_archive` function remains an explicit compatibility utility. Default
verification does not call it. Existing CLI arguments, six-field result and exit
codes remain unchanged. Uploaded/downloaded ZIPs still need independent archive
qualification; the direct check cannot establish GitHub artifact provenance.

## Qualification

`tools/check-direct-candidate_test.py` compares successful direct/ZIP results on
all three platform naming recipes and 28 adverse payload refusals. It also checks
exact layout/aggregate limits, short binary reads, read failures, descriptor
cleanup, repeated/nonselected adapter requests, links, FIFO admission and
post-read member/directory changes. A separate native metadata control reports
which path/descriptor fields differ, and three finite alternate-view controls
require stable views to pass while later descriptor changes are refused.
These are opaque synthetic fixtures.

A seven-binary 28 MiB fixture asserts one read of every payload and no new ZIP or
workspace. The fixture establishes an avoided logical copy, not physical APFS
reclaim, peak memory, whole-CI latency or production capacity. Existing native
tests, all resource grids/samples, 59 offline pilot scenarios, ordinary executable
exports and later archive qualification remain unchanged and required. Independent
review, consumer/network acceptance, trust inputs and release gates remain open.

Run the new controls and both existing suites in an owned bounded workspace:

```sh
python -I -B tools/check-direct-candidate_test.py -v
python -I -B tools/check-candidate-archive_test.py -v
python -I -B tools/check-exported-candidate_test.py -v
```
