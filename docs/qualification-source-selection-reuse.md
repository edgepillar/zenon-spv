# Serial source selection in recorded controls

The cache forward-replay controls repeatedly validate copies of one frozen
recording. A local profile found 137 reconstructions of the same complete node
source selection during the 21-test suite. The serial class now retains one
selection and returns independent deep copies for its corpus checks.

The class hashes its reader, test source and declared input files at admission
and checks them again at teardown. It also rebuilds the complete selection at
both ends. The existing no-backend control explicitly invokes the uncached
builder. Unittest class cleanup restores the normal builder even when a test
body or teardown fails. Normal reader invocations construct their source
selection afresh.

Eight additional controls exercise independent returned values, source-byte
drift, selection drift, failed admission, exception cleanup, the real
no-backend path and fresh reader behavior after the class. Drift is injected
through in-memory mocks; these controls do not modify repository files.

## Local recorded comparison

The baseline test source is pinned at
[main commit 06bdd711](https://github.com/edgepillar/zenon-spv/blob/06bdd711e01c87530b83979584fd32323935bedf/tools/gen-state-root-vectors/check_cache_forward_replay_test.py)
with SHA-256
48afb9c980b62c26ff2a9c60a55bd04086254f2e5c3de36b1b2109071840caaa.
The tested RAM variant has SHA-256
c7706bfd7ba6cba054b8b73bb491667b7055638e40f5018cb617aa1624787c03.

Fresh processes executed each source variant as an isolated in-memory main
module. Timings include the complete original suite, imports and class
lifecycle; a separate complete checker-report comparison follows that timing.
The runtime observed after the runs was CPython 3.9.6 on Darwin ARM64. The
ordinary samples had no profiler enabled and were interleaved on the same host.

| Sample | Baseline suite, seconds | Reuse variant, seconds |
| --- | ---: | ---: |
| 1 | 19.212 | 0.743 |
| 2 | 19.037 | 0.745 |
| 3 | 19.004 | 0.752 |

All 21 original method names and assertions remain. Instrumented samples
executed 136 corpus checks in both variants and reduced complete source
reconstructions from 137 to four. Every complete positive checker report was
byte-equivalent under the comparison's JSON encoding. The eight added boundary
controls are separate from these suite timings.

These are local test-harness observations. Hosted CI speedup and representative
production resource budgets remain unqualified. The selection stays in process
memory; no persistent cache or new download is used.

## Validation

Use an admitted qualification workspace and select its temporary-file root
before running the controls:

```sh
python3 -I -B tools/gen-state-root-vectors/check_cache_forward_replay_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_forward_source_reuse_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_forward_replay.py
```
