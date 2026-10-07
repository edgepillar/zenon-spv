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

## Repeated local observer cycles

This separately predeclared experiment measures source revision
`1b4331a1941269ec3cee242d1fe9771710e6d1e2`. Its 365 Go/module/JSON runtime and
existing test inputs, and all four local ordinary executable byte hashes, are
identical to parent `5bf2df1565fe820d672828ae6b97fa09b60dea09`.
The sampler and its controls are new. This is an instrumented engineering
observation, without a causal speedup claim or production capacity qualification.

The local host was Darwin arm64, with eight reported physical CPU cores and
20 GiB memory. Native hosted macOS CI qualifies amd64 separately. Input preparation
and builds are outside timing. The 78 fixed synthetic input files reuse a node
fixture pinned to go-zenon `3a4131e63881058b6ce2ee81d3a41d0033fafc99`;
13,068 header preimages, flat content roots, schedule/context fingerprints,
expectations and fixed RPC bytes were independently recalculated before running.
Synthetic signatures were reused, with no new signing or external RPC.

Each K/T/C cell runs 25 fresh ordinary observers per worker using the same
full-retention state, explicit anchor/profile/schedule/context pin and selected
targets. A loopback fixture persists per worker across those cycles. K is 256 or
4096, T is 1/16/256, and C is 1 or 4. States do not advance; this does not measure
forward history or a sustainable request arrival rate. T=256 uses a 36,374,884-byte
bundle containing a 1,000-member flat content list per target.

Timing starts at the first observer launch and ends after all actual outer exits,
child/copy completion and final private-directory metadata observation. Requested
10 ms gaps separate POSIX `ps` candidate-tree RSS and bounded metadata scans;
sampling overhead is included. Fixture setup/shutdown, handler settlement,
compilation and subsequent immutable-input byte guards are outside timing.
Fixtures use 5-second socket/settlement bounds, a 10-second gate hold ceiling and
50-second group supervision. Ordinary children use 15 seconds per stage; selected
collector timeouts use 500 ms. Handler settlement precedes each next cycle and
all 54 fixture servers in 18 sets are joined at the end of their series.

Every baseline, fault and recovery group begins and ends with an empty selected
private root. Scans use 128 entries and depth 2. The table reports nearest-rank
p95 over all 25 baseline rounds and maximum sampled file/RSS observations. All
rounds are retained: no warmup discard, sample filtering, failed-round retries or
forced ordinary Go GC. Sizes are MiB (2^20 bytes), times milliseconds.

| K | T | C | p95 elapsed ms | Sampled RSS MiB | Sampled logical file MiB | OS-reported file blocks MiB |
|---:|---:|---:|---:|---:|---:|---:|
| 256 | 1 | 1 | 88.194 | 24.781 | 0.138 | 0.145 |
| 256 | 1 | 4 | 90.824 | 82.594 | 0.545 | 0.562 |
| 256 | 16 | 1 | 153.948 | 31.109 | 2.183 | 2.188 |
| 256 | 16 | 4 | 164.692 | 123.391 | 8.710 | 8.727 |
| 256 | 256 | 1 | 1221.624 | 149.453 | 34.894 | 34.898 |
| 256 | 256 | 4 | 1424.126 | 594.875 | 139.275 | 139.289 |
| 4096 | 1 | 1 | 269.208 | 37.000 | 0.138 | 0.145 |
| 4096 | 1 | 4 | 281.980 | 146.812 | 0.545 | 0.562 |
| 4096 | 16 | 1 | 336.847 | 45.078 | 2.183 | 2.188 |
| 4096 | 16 | 4 | 355.947 | 181.500 | 8.732 | 8.750 |
| 4096 | 256 | 1 | 1420.212 | 156.469 | 34.894 | 34.898 |
| 4096 | 256 | 4 | 1640.474 | 624.250 | 139.124 | 139.137 |

The predeclared local alarms are p95 10 seconds serial / 30 seconds concurrent,
1 GiB sampled group RSS, 256 MiB outer-process `wait4` high water, and logical
private-file bytes of C * 71,565,312 bytes (68.25 MiB per observer, derived from
existing output caps). All 12 baseline cells remained below these alarms. All
348 groups also remained below the sampled RSS and outer high-water limits.
These are developer-selected engineering alarms, not independent consumer
acceptance, physical storage quotas or guaranteed peak bounds.

For each K/T pair, four C=4 groups select exactly one collector timeout, active
SIGINT cancellation, successful partial-report helper or expired target. The
other three observers remain healthy. Every fault is immediately followed by
four fresh healthy observers on the same settled fixture set and original fixed
inputs. The expired input is used only for its selected fault; recovery uses the
original state. This tests owned process/fixture cleanup and fresh-call recovery,
without persisting or advancing candidate state.

The complete series retains 348 group records, 2,580 raw run files, 942 actual
outer exits and 2,796 child outcomes: 3,732 ordinary candidate process outcomes
plus six explicit partial-report helper outcomes. There are 918 matches, 24
expected refusals, 72 healthy fault siblings and 96 healthy recovery matches.
All 1,872 loopback requests are retained as fixed-byte response attempts;
cancelled-client attempts are not asserted to have delivered payloads.
Independent raw-record recalculation invokes no candidate or network.

The 7,512 RSS samples and 8,208 metadata scans preserve 19 known disappearing
entry races. No metadata scan refused. The largest sampled logical file sum was
146,040,638 bytes; the largest filesystem-reported file allocation sum was
146,055,168 bytes; up to 12 regular files were observed. All 348 final scans were
empty, and all fixed input/executable bytes remained unchanged. This rules out
remaining visible named files at those selected post-exit checks, not short
peaks, unlinked open files or storage outside the selected root.

The 17 sampler controls run locally and in all three native CI jobs. Actual
filesystem controls and modeled unsafe/race metadata remain distinct. Local
executable provenance is separately recorded clean source/build evidence;
embedded VCS metadata was unavailable, and no authenticated or reproducible
release claim follows. Raw inputs, process reports, samples, fixture lifetimes,
byte audits and executable pins remain in the private qualification packet.

This helper and synthetic experiments do not establish canonicality, finality,
authenticated election/activation, state-value proofs, a qualified live-network
consumer pilot, independent human review or an authenticated release.
