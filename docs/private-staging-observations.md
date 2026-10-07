# Private staging metadata observations

`tools/sample-private-staging.py` observes an explicitly selected existing
private directory. It reads file metadata and returns scalar counts and sizes;
it does not read file contents, print paths/names, launch children, access a
network, delete remnants or select verifier trust inputs. The ordinary Go
observer/verifier/collector/consumer code is unchanged by this tool.

Use Python 3.9 or later. Select the same caller-protected directory used by
`observe-block --private-dir`, and keep it protected throughout the scan. On
POSIX the root must be owned by the current user with no group/other permission
bits. Windows callers must establish a private ACL; Unix mode bits do not
authenticate that boundary. Directory traversal is path based, so protection
against concurrent directory replacement remains a caller requirement.

```sh
python tools/sample-private-staging.py --private-dir private-observations --samples 100 --interval-ms 10
```

The root already exists. The sampler does not create or repair it. Invocation
options require 1-4096 samples, 1-1000 ms nominal gaps, at most 60 seconds of
requested gaps, 1-4096 entries per scan and directory depth 0-16. Defaults are
one sample, 10 ms, 128 entries and depth 2. These bounds do not impose a storage
I/O deadline; scanning overhead adds to elapsed time.

The JSON report uses schema version 1. `status=observed` means every requested
scan returned metadata under its selected bounds. `not_observed` retains any
completed samples and the failed sample index/category; it does not promote a
partial sequence. Invalid options exit 64, entry/depth refusals exit 2, input or
unsafe-entry refusals exit 70, and interrupted sampling exits 130. Argument and
filesystem errors use fixed categories without private values or tracebacks.

Every sample preserves its elapsed time, visited entry count, directory and
regular-file counts, logical file byte sum, filesystem-reported file allocation
sum when available, and known disappearing-entry count. The root itself and
directory blocks are excluded. Observed symlinks, reparse points, special entries
and device changes refuse the scan. Missing allocation metadata stays null.

Logical file sizes and allocated blocks are different observations. Python's
optional `st_blocks` counts 512-byte units, including sparse-file behavior.
Windows cached `DirEntry.stat` device identity is unsuitable for the device
check; the sampler requests current unfollowed `os.stat` metadata. See the
[Python stat-result documentation](https://docs.python.org/3.13/library/os.html#os.stat_result)
and [directory-entry documentation](https://docs.python.org/3.13/library/os.html#os.DirEntry.stat).

Scans are non-atomic: file sizes are read at different times, short peaks and
unobserved changes can be missed, and known disappearing-entry races remain in
the result. Hard links may be counted repeatedly; unlinked open files, directory
blocks, filesystem compression/deduplication effects and unrelated storage are
not characterized. A sampled sum is neither guaranteed peak usage, physical disk
consumption, free-space/quotas nor a consumer-selected service level. Sampling
can influence timing and filesystem behavior.

The controls cover actual empty/nested/sparse files, repeated owned cleanup,
unchanged owned bytes, bounded scans, unsafe/missing entries, nullable allocation,
known races, root identity changes, current versus cached metadata, private CLI
errors, incomplete sequences and interruption. A real symlink control can be
skipped on Windows when fixture creation is unavailable; reparse metadata is
still tested separately. Mocked metadata/race controls are not authenticated
filesystem or adversarial replacement proofs.

```sh
python -I -B tools/test_private_staging.py
```

A separately source-bound local experiment will record repeated ordinary
observer cycles, private-file observations and fault-followed-by-recovery
outcomes using fixed synthetic full-retention inputs. Its results require all
raw records and measurement boundaries to be retained. This helper and synthetic
tests do not establish canonicality, finality, authenticated election/activation,
state-value proofs, live-network consumer acceptance or an authenticated release.
