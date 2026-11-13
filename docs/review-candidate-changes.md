# Frozen review candidate and development baselines

The selected human-review candidate remains
[`6ecc2310538d511e3b26bea4c658082853266a11`](https://github.com/edgepillar/zenon-spv/tree/6ecc2310538d511e3b26bea4c658082853266a11).
Its selected [CI run](https://github.com/edgepillar/zenon-spv/actions/runs/39066131743)
and unsigned handoff have their own scope: 892 tracked files, 555 selected
Go/module/JSON inputs, 48 evidence families, nine archives, 21 ordinary
executables and 59 scenarios per platform. Five Windows skips remain explicit;
Linux and macOS have zero. This is mechanical qualification, not independent
human acceptance or authenticated distribution.

## Current qualified runtime baseline

Evidence cut: **13 November 2026**. The ledger-selected runtime is
[`e143ade8507a45a1f125de7bc15b92541036ef85`](https://github.com/edgepillar/zenon-spv/tree/e143ade8507a45a1f125de7bc15b92541036ef85),
tree `0cfe07a72796b985e4d51483807c7a168d16c2e3`, from the local merge of
[PR #385](https://github.com/edgepillar/zenon-spv/pull/385). Both author and
committer are `edgepillar`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/43472323191)
passed all seven jobs on attempt 1; its separate
[transport main CI](https://github.com/edgepillar/zenon-spv/actions/runs/43472322970)
passed all three platform jobs on attempt 1.

| Context | Feature revision | Actual checkout revision | General run | Transport run |
| --- | --- | --- | --- | --- |
| PR #385 | `652398428ecbc0bd266232bbf99d1b5e5b6a2a0e` | `123923cba7036661e813e95f91f73398e025e604` | [43466376012](https://github.com/edgepillar/zenon-spv/actions/runs/43466376012) | [43466375992](https://github.com/edgepillar/zenon-spv/actions/runs/43466375992) |
| Main | `e143ade8507a45a1f125de7bc15b92541036ef85` | `e143ade8507a45a1f125de7bc15b92541036ef85` | [43472323191](https://github.com/edgepillar/zenon-spv/actions/runs/43472323191) | [43472322970](https://github.com/edgepillar/zenon-spv/actions/runs/43472322970) |

Each context retains its own run, archive and binary bindings despite equal file
trees. General qualification selects 19 archives: three tested candidates,
three complete root-suite receipts, three scope-control reports, three ledger
inventories, three snapshot/header-binding reports, three recorded-oracle
selection manifests and one change-scope archive. The candidate readers check
all 21 native binary/source/platform bindings. Three transport archives add
81 bounded controls per platform. These are 22 primary archives per context.

The other 21 general-workflow archives per context were separately accounted
for by exact run/source/platform selection, archive SHA-256, ZIP CRC and bounded
JSON/JSONL readback. The separate offline-pilot payload matches the already
qualified selected-report digest. This supplemental inventory does not
independently requalify diagnostic semantics or resource measurements. Embedded
historical source labels keep their original meaning; workflow association
does not turn an earlier record into new native execution. Across
PR and main, all **86 archive IDs** are accounted for: 44 primary qualification
archives and 42 supplemental integrity/readback archives. No second stdout/ZIP
copy, extraction tree or new native execution was needed for these readers.

The complete root suites cover 16 root-module packages. Counts below apply to
each context separately; skipped tests are included in inventory totals, and
the selected-scenario skip ledger is not added again.

| Platform | Root tests | Subtests | PASS events | SKIP events | Failures |
| --- | ---: | ---: | ---: | ---: | ---: |
| Linux amd64 | 987 | 6,412 | 7,399 | 0 | 0 |
| macOS Intel amd64 | 987 | 6,412 | 7,399 | 0 | 0 |
| Windows amd64 | 983 | 6,495 | 7,462 | 16 | 0 |

Native job logs separately bind the five new candidate-hash benchmark cases
per platform and context to the existing three-iteration recipe. The
[hash-input observations](candidate-rpc-hash-inputs.md) retain their local
Darwin ARM64 baseline/current samples and final-predicate checks. Hosted values
are not replaced with that local table. Finite function allocation savings do
not establish whole-process RSS, general latency or representative budgets.
The first [PR CI revision](https://github.com/edgepillar/zenon-spv/actions/runs/43461462004)
at `e784ea72a65826560f1b0c1e30dfb566e052ec3f` remains FAILURE at Linux lint;
its completed native jobs were not interrupted. The original local assertion
failure and completed benchmark samples also remain retained. The corrected
revision has its own qualification, rather than relabeling either failed attempt.

The owned-experiment preparation, closed-parent oracle and ledger-export
workflows did not execute at this runtime revision. Their earlier qualifications
keep their original sources. The separately authorized
[first fixture run](owned-devnet-attempt-2026-11-13.md) at `4a1d03e` remains
refused before chain startup. The frozen runner ref, selected `7493c59`
consumer/oracle inputs and reviewed `834d551` follow-up packet are not replaced
by the current runtime selection. The follow-up remains unexecuted and needs
its own source-specific authorization. Current CI supplies no selected-network
BatchEntry consumer acceptance, independent human review or authenticated
release. Production state proofs and irreversible settlement remain NO-GO.

### Source and review scope

Fresh comparisons read the exact revisions' Git blobs. The frozen-review to
`e143ade` pair contains **550 changed tracked paths**, **226 selected-input
changes** and **130 root-module Go paths**: 59 implementation/driver files and
71 tests. Root `go.mod` and `go.sum` are unchanged. The frozen source has six
nested modules and the current source has seven; ownership is determined
independently at each revision, after checking path existence.

The preceding ledger runtime `5caa58d` to `e143ade` pair contains **24 changed
tracked paths**, **three selected-input changes** and **three root-module Go
paths**: one implementation file and two tests. The Go paths are
`internal/fetch/candidate_v3.go`, `candidate_rpc_hash_test.go` and
`candidate_rpc_hash_bench_test.go` in that same directory. The complete pair
also changes the owned-builder diagnostic/shutdown Python path, the joint
retention qualification controller, workflow/selector source pins and their
documentation. Those paths remain outside the Go/module/JSON input selector
and require their own review. Unchanged module files and selected-input
comparisons do not qualify that Python/workflow delta.

The [fingerprint table](#recomputable-input-fingerprints) retains all historical
rows and adds the current 747-input identity: 36,055,705 content bytes with
framed SHA-256 `074fa8d0cdb5c0dddd7d5fcb0c5945998d8ff400c67f56d7ca8da270fce24672`.
Independent framing agrees with the exporter at the actual PR checkout and
main. A source digest is not native execution or independent acceptance.

```sh
git diff --name-status --no-renames 6ecc2310538d511e3b26bea4c658082853266a11 e143ade8507a45a1f125de7bc15b92541036ef85
git diff 6ecc2310538d511e3b26bea4c658082853266a11 e143ade8507a45a1f125de7bc15b92541036ef85 -- cmd internal tools go.mod go.sum
git diff --name-status --no-renames 5caa58d43a452714f044c081e00ec69388894c08 e143ade8507a45a1f125de7bc15b92541036ef85
```

This ledger update runs no native workload and transfers no human review.
Later documentation-only heads retain runtime qualification at `e143ade`;
scope-only CI does not qualify a new executable. Earlier ledger sections retain
their original revision pairs, results, failures and meanings of "current".

## Historical source-specific records

The following records preserve their original revisions and meanings of
"current". They do not replace the runtime selection above or the frozen
human-review selection at the start of this document.

### Earlier runtime selection: `5caa58d`

Evidence cut: **13 November 2026**. The ledger-selected runtime is
[`5caa58d43a452714f044c081e00ec69388894c08`](https://github.com/edgepillar/zenon-spv/tree/5caa58d43a452714f044c081e00ec69388894c08),
tree `35beac2f0ca30286927be6483f8eed551cca1607`, from the local merge of
[PR #380](https://github.com/edgepillar/zenon-spv/pull/380). Both author and
committer are `edgepillar`. Its own
[main CI](https://github.com/edgepillar/zenon-spv/actions/runs/43377831318)
passed all seven jobs on attempt 1. Qualification covers 19 selected archives:
three tested candidates, three root-suite receipts, three scope-control reports,
three ledger-inventory reports, three snapshot/header-binding reports, three
recorded-oracle selection manifests and one change-scope archive. The candidate
readers checked all 21 native binary/source/platform bindings. Archive counts
and older gate records retain their source-specific meanings.

The complete root suites cover 16 root-module packages. Linux and macOS each
record 983 root tests and 6,377 subtests: 7,360 PASS events, zero skips/failures.
Windows records 979 root tests and 6,460 subtests: 7,423 PASS and 16 explicit
platform SKIP events, zero failures. Inventory counts include skipped tests;
the separate selected-scenario skip ledger is not added to these totals.

The [PR CI](https://github.com/edgepillar/zenon-spv/actions/runs/43372986044)
qualifies feature `02487f9a8ea4bbd388582214d95a4589f810380c` at actual test-merge
checkout `a8a88d528858c18fcbf4296d1f7748f5b1d0422e`. It has its own seven-job,
19-archive qualification. PR and main have the same file tree and selected-input
fingerprint, but each retains its own source/run/platform evidence. Across the
two contexts, all 38 archive selections and 42 binary bindings were checked.
Seventy-two same-process account-codec benchmark samples per context record
nonce/token decode allocation reductions; they do not establish whole-CI latency,
peak memory, production resource limits or measured physical disk savings.

The separate owned-experiment preparation, closed-parent oracle, ledger-export
and ledger-transport workflows did not execute at this runtime revision. Keep
their earlier source/run qualification attached to the original revisions.
The [typed-query readiness ledger](typed-query-readiness.md) distinguishes the
current runtime, frozen runner `4a1d03e`, selected consumer/oracle source
`7493c59`, original/reference-gas contracts and the unchanged human-review
candidate. No owned experiment dispatch or selected-network BatchEntry consumer
acceptance is recorded at this cut. Production state proofs and irreversible
settlement remain NO-GO.

### Source and review scope

Recomputed directly from each revision's Git blobs, the frozen-review-to-current
pair contains **540 changed tracked paths**, **224 selected-input changes** and
**128 root-module Go paths**: 59 implementation/driver files and 69 tests. Root
`go.mod` and `go.sum` are unchanged. The frozen source has six nested modules;
the current source has seven. Determine module ownership independently at each
revision before counting a changed Go path.

The preceding ledger runtime `2092095` to current `5caa58d` pair contains 128
changed tracked paths, 47 selected-input changes and 40 root-module Go paths:
25 implementation/driver files and 15 tests. The selected input stream includes
nested research modules; it is not a claim that every selected input belongs to
the root module. Python, workflow and other excluded paths require their own
review. The full [fingerprint table](#recomputable-input-fingerprints) preserves
all earlier rows and adds the current source's 745-input identity.

```sh
git diff --name-status --no-renames 6ecc2310538d511e3b26bea4c658082853266a11 5caa58d43a452714f044c081e00ec69388894c08
git diff 6ecc2310538d511e3b26bea4c658082853266a11 5caa58d43a452714f044c081e00ec69388894c08 -- cmd internal tools go.mod go.sum
```

This ledger update runs no native workload and transfers no human review.
Later documentation-only heads retain runtime qualification at `5caa58d`;
scope-only CI does not qualify a new executable. Earlier ledger sections retain
their original revision pairs, results, failures and meanings of "current".

### Earlier runtime selection: `2092095`

The runtime baseline selected by this ledger is
[`2092095126ca6f3243b99b9d8b34c4661f5d6934`](https://github.com/edgepillar/zenon-spv/tree/2092095126ca6f3243b99b9d8b34c4661f5d6934),
tree `98790a73fa06e16bf602147b38ef0c10e4657cd4`, following the local merge of
[PR #343](https://github.com/edgepillar/zenon-spv/pull/343). Both author and
committer are `edgepillar`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41988312888)
passed all seven scheduled jobs on attempt 1. All 37 selected archive IDs and
59,975,037 archive bytes were reconciled, including 21 ordinary
native binary bindings, source/build metadata, architecture checks and selected
61-scenario reports. The separate exporter/transport workflows did not run at
this runtime revision; earlier observations keep their original source pins.

The complete uncached root-suite receipts cover 16 root-module packages.
Linux and macOS each record 965 root and 6,333 subtest completions: 7,298
passing events and zero skips. Windows records 961 root and 6,416 subtest
completions: 7,361 passing events and 16 skip events. Completion counts include
skips. The selected Windows reports separately retain five skips; these counts
are not additive.

The [candidate CI](https://github.com/edgepillar/zenon-spv/actions/runs/41979306603)
has its own source/run/artifact reconciliation. Attempt 1 remains FAILURE:
the macOS runner reported two `CreateArtifact` `ENOTFOUND` errors, and dependent
later steps were skipped. All 34 available archives and its actual job log were
retained before one macOS-only recovery. The six successful jobs were not
requested again. GitHub's attempt-2 API records clone those six completed
executions with new job IDs; their original times and steps remain bound to
attempt 1. Only macOS executed afresh on attempt 2.

The complete candidate gate selects 37 archives (59,975,069 bytes): 28 from
attempt 1 and nine bound to the new macOS job's upload IDs and log. Six earlier
macOS archives remain preserved outside this selected gate. It does not call
all seven jobs fresh attempt-2 execution. Candidate feature
`21dd142945616fc0ba0f0d52faed2203c36e1bf1`, checked out as
`f59a6960788291bdde193646e4adae8635bc8989`, and main have equal trees but
separate qualification. Together they have 74 selected archives and
119,950,106 compressed bytes; the six excluded first-attempt
macOS archives are additional retained evidence. Archive readers reuse verified
CAS objects, extract no payload files and execute no new native tests or binaries.

### Reusing an actually executed source root

The [fixed source-enumeration group](source-root-control-reuse.md) replaces two
duplicate ordinary-parent Go processes and their 32,769-entry directory fixtures
on macOS/Windows. It requires the exact package/root, six passed subtest
completions and zero skipped/failed children inside a complete source-bound
stream and successful process. The Python reader independently checks names,
integer-only counts, selected-scenario disjointness and suite totals.

This is opt-in `zenon-root-suite/v4` qualification metadata. The default
producer retains v3; v1/v2/v3 verification remains supported. Linux retains its
separate ordinary-parent control alongside the instrumented complete suite.
Full package/model coverage, cryptographic checks and verifier acceptance rules
are unchanged. Historical dedicated-step times of 11 seconds on macOS and
44 seconds on Windows are observations, not a controlled whole-CI speedup claim.

Local targeted evidence contains 21 passed Go roots and 18 subtest completions
with race instrumentation, 17 independent Python checker roots, a Go-to-Python
group-contract comparison, vet and module integrity. The small actual Go-event
fixture is synthetic; the complete hosted suites run the unchanged real directory
test. A [source review at `21dd142`](https://github.com/edgepillar/zenon-spv/pull/343#issuecomment-6652166973)
reports 75 Linux race tests, 17 checker tests and two discriminating mutations.
Those are reviewer-reported observations, not a new frozen release-review
selection or authenticated distribution.

The preceding [incremental retained-window decoder](streamed-state-window.md),
[per-header ownership copies](owned-header-copies.md), version 2 BatchEntry
source-field policy, independent ABI vectors and version 1 compatibility remain
covered. No current observation establishes selected-network activation,
complete SubmitBatch validation, executor authorization, state transitions or
consensus finality.

### Source and review scope

The frozen-to-current pair contains 462 changed tracked paths, 196 changed
selected inputs and 107 root-module Go paths: 47 implementation/driver files
and 60 tests. Root `go.mod` and `go.sum` are unchanged. The narrower historical
`da04d418`-to-current pair contains 189 tracked changes, 111 selected-input changes
and 95 root-module Go paths: 44 implementation/driver files and 51 tests.
Module ownership is determined separately at each revision.

The direct preceding-runtime `fdd17be`-to-`2092095` pair contains ten changed
tracked paths, four selected inputs and four root-module Go paths: three
implementation/driver files and one test. Python helpers, documentation and the
workflow require separate inspection outside the selected-input fingerprint.

| Path | Earlier blob | Selected baseline blob | Review impact |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | `79b320fbd9c921533bb5fb9998b2332140e52538` | `5dd0b1e98f2f206c2946ceae53503d0dda71ff33` | Reuses the required ordinary-parent group on macOS/Windows; Linux's separate ordinary control remains. |
| `docs/native-roadmap.md` | `1014a605472b2acc0d3ce4a8dc858dc5a4c3a2c6` | `088c7a4e5e1066ed5568576811d7db6ed2c88f50` | Preceding source-specific ledger update; no new native execution by the documentation itself. |
| `docs/review-candidate-changes.md` | `63e1b7a669e978a6176de3587305e35ea611f0d7` | `50bb63aa923be39ae9908b901de3889b964f121e` | Preceding qualification record and preserved history. |
| `docs/source-root-control-reuse.md` | — | `6ed2a16648caadbc458a82e730fef052a3379f93` | Fixed-group contract, observations and limits. |
| `tools/check-root-suite.py` | `3f7b0cffab52e7fd5782cf11151bf5ed60fe726b` | `005dc4d69e10cc9c7c912f87073b6f82808be2af` | Strict v4 group, inventory/count checks and explicit older-receipt refusal; legacy formats remain. |
| `tools/check-root-suite_test.py` | `0423b3f26ba6d1edb4d20e522c19037bc91e56fa` | `6c3d1d8dc53d07dcf218cecb5d8e31bef0a972ef` | Finite schema/type/count/recipe refusal controls. |
| `tools/offline-pilot/full_suite.go` | `707a273031f56012eea4ab852c944219d02fd6bd` | `9a3340abe27a793f5975dd4ef2f1e0c457c0815b` | Collects the required root after lifecycle validation; incomplete groups cannot pass. |
| `tools/offline-pilot/main.go` | `8262857ced272cb65db926598e917f111bc63aec` | `d852f49bebfb904efc48c26f142f34e1dc484e20` | Validates the opt-in selector before setup and emits v4 only when requested. |
| `tools/offline-pilot/source_roots.go` | — | `d04b0813e438c501f38d21b51bd9c380b2a07497` | Fixed root and six-child counters; no dynamic labels or diagnostics in the receipt. |
| `tools/offline-pilot/source_roots_test.go` | — | `981209855ba7317f72b71b832589d2738944272c` | Lifecycle, skip/failure, privacy and small actual Go-event fixture controls. |

Review the complete pair explicitly:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 2092095126ca6f3243b99b9d8b34c4661f5d6934
git diff 6ecc2310538d511e3b26bea4c658082853266a11 2092095126ca6f3243b99b9d8b34c4661f5d6934 -- cmd internal tools go.mod go.sum
```

The second command includes nested research modules and excluded material.
The 729-input fingerprint below was independently recomputed from Git blobs.
This ledger update supplies no new native execution and preserves the preceding
runtime record verbatim. Later documentation-only heads retain runtime
qualification at `2092095`; scope-only CI cannot qualify native execution.

The [D0-D6 contract](typed-state-roadmap.md) still requires the selected real
network/query/profile/anchor/producer authorization and actual consumer capture,
representative R1 data, independent release review and authenticated distribution.
Production state proofs and irreversible settlement remain NO-GO.

### Earlier runtime selection: `fdd17be`

The runtime baseline selected by this ledger is
[`fdd17be9d3c9a7b0a98068a72b44bb2b10eb253e`](https://github.com/edgepillar/zenon-spv/tree/fdd17be9d3c9a7b0a98068a72b44bb2b10eb253e),
tree `87dd030885f21059c9d1a8626bc1838c99f7f769`, following the local merge of
[PR #341](https://github.com/edgepillar/zenon-spv/pull/341). Both author and
committer are `edgepillar`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41971763273)
passed all seven scheduled jobs on attempt 1. Reconciliation covers all 37
actual archive IDs and 59,974,847 archive bytes, including 21 ordinary native
binary bindings, source/build metadata, architecture checks and selected
61-scenario reports. The separate exporter/transport workflows did not run at
this runtime revision; earlier observations retain their original source pins.

The complete uncached root-suite receipts cover 16 root-module packages.
Linux and macOS each record 960 root and 6,333 subtest completions: 7,293
passing events and zero skips. Windows records 956 root and 6,416 subtest
completions: 7,356 passing events and 16 skip events. Completion counts include
skips. The selected Windows reports separately retain five skips; the two
traces' skip counts are not additive. The
[candidate CI](https://github.com/edgepillar/zenon-spv/actions/runs/41968659940)
has its own completed source/run query and qualification of 37 archives
(59,974,783 bytes). Equal file trees did not transfer qualification between
candidate feature `eab89bbbdcba4d8e1672afe679f110bc59028090`, checked out as
`2064993c5921c324a648eb8de678a2afa3abdad3`, and main. Both revisions together
account for 74 reconciled archives and 119,949,630 compressed bytes.
Archive readers reuse verified CAS objects, extract no payload files and
execute no new native tests or binaries.

### Incremental retained-window decoding

The [state-window decoder](streamed-state-window.md) consumes the bounded
`retained_window` value directly from the enclosing state-object decoder,
avoiding one complete array buffer and a second decoder. Standalone EOF
checks and the enclosing object's syntax checks remain separate. Array/null
shape, nil/empty distinction, duplicate known-field refusal, Unicode field
matching, the count guard before the next row and publication only on success
remain covered. Complete hash/signature/link/checkpoint validation and
anchor/profile/producer checks still precede retention resizing. File
encoding, schema versions 1/2/3, trust boundaries and proof acceptance rules
are unchanged. This is not fully streaming file loading or a signature cache.

The independent preceding parser is frozen at `8ada23c` with source hashes.
Local retained evidence spans 50 passed roots and 303 unique subtest
completions, including the unchanged 18-cell full-capacity model. The first
attempt remains FAILURE: a new schedule test requested 38 slots from a
32-header fixture. The fixture now contains 64 headers; that corrected root
and the previously unexecuted benchmark, bounded differential fuzz, standalone
window/state fuzz, vet and module checks passed. Successful model runs were
not repeated merely to repair the fixture. The final hosted root suites
executed the complete corrected source independently on each platform.

Three local Go 1.25.14 darwin/arm64 structural benchmark repeats at K=4096
record 16,407,048 B/op for the preceding parser and 8,020,048–8,020,053 B/op
for the incremental parser, about 51% fewer allocated bytes. These direct
`UnmarshalJSON` measurements exclude input reads, the complete loader's outer
syntax pass and cryptographic validation. They establish no complete-loader
RSS, end-to-end latency, whole-CI speedup or representative device budget.

The preceding [per-header ownership copies](owned-header-copies.md),
version 2 BatchEntry source-field policy, independent ABI vectors, original-node
positive bytes and version 1 compatibility remain covered by the fresh
source-specific suites. These observations do not establish selected-network
activation, complete SubmitBatch validation, executor authorization, state
transitions or consensus finality.

### Source and review scope

The frozen-to-current pair contains 459 changed tracked paths, 194 changed
selected inputs and 105 root-module Go paths: 46 implementation/driver files
and 59 test files. Root `go.mod` and `go.sum` are unchanged. The narrower
historical `da04d418`-to-current pair contains 186 tracked changes, 109
selected-input changes and 93 root-module Go paths: 43 implementation/driver
files and 50 tests. Counts use per-revision module ownership; all earlier
records keep their original pairs.

The direct preceding-runtime `762ae9a`-to-`fdd17be` pair contains seven changed
tracked paths, three selected inputs and three root-module Go paths: two
implementation files and one test file. Three documentation paths and the CI
workflow are outside the selected-input fingerprint. The table below uses exact
Git blob IDs; an em dash means the earlier path was absent.

| Path | Earlier blob | Selected baseline blob | Review impact |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | `f4179f78d34264ba8952e0f37d12feb13cd397c5` | `79b320fbd9c921533bb5fb9998b2332140e52538` | Adds native decoder controls and bounded structural allocation observations. |
| `docs/native-roadmap.md` | `0ec9c933e14f8022dd53a0a6552a845e972a10a2` | `1014a605472b2acc0d3ce4a8dc858dc5a4c3a2c6` | Source-specific evidence and scope; documentation supplies no new native execution or independent acceptance. |
| `docs/review-candidate-changes.md` | `94569b563b76bcb2388801354b3ff35faefeafd8` | `63e1b7a669e978a6176de3587305e35ea611f0d7` | Source-specific evidence and scope; documentation supplies no new native execution or independent acceptance. |
| `docs/streamed-state-window.md` | — | `fb302501f34777ef84efb27364aaa8c3be8af4d6` | Source-specific evidence and scope; documentation supplies no new native execution or independent acceptance. |
| `internal/verify/state_json.go` | `556f464d36daad239c7b87f8de55528a852e8367` | `a925ae01b696d5204a15d8c3aa0deecfec94c748` | Consumes the bounded window directly within the state-object decoder; duplicate and publish-on-success rules remain. |
| `internal/verify/state_window_json.go` | `a0225c884fa08377128277f122d4a21a24bf58fe` | `1d6a48f082834af93a24d1d1d7d441fdc77651ac` | Separates one bounded nested value from standalone EOF validation; header decoding and count guard remain. |
| `internal/verify/state_window_stream_test.go` | — | `c53574e3c125da6eebe58d748a7ae203bc72e954` | Frozen preceding parser, bounded differential fuzz, schema/order/count checks and signed resume controls. |

Review the complete current pair with explicit two-revision commands:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 fdd17be9d3c9a7b0a98068a72b44bb2b10eb253e
git diff 6ecc2310538d511e3b26bea4c658082853266a11 fdd17be9d3c9a7b0a98068a72b44bb2b10eb253e -- cmd internal tools go.mod go.sum
```

The second command includes nested modules and other material in those
directories; use the module filter below for the 105-path root Go scope.
The 727-input fingerprint below was independently recomputed from Git blobs.
Python, workflows and other excluded inputs require separate inspection.

This ledger update supplies no new native execution and does not advance the
frozen human-review candidate. Later documentation-only heads retain runtime
qualification at `fdd17be`; scope-only CI cannot qualify native execution.
All failed, interrupted and superseded observations retain their actual
outcomes; later successful CI does not rewrite them.

The [D0-D6 contract](typed-state-roadmap.md) still needs the independently
selected network/query/profile/anchor/schedule and actual consumer capture,
representative R1 data, independent review and authenticated distribution.
Production state proofs and irreversible settlement remain NO-GO.

### Earlier runtime selection: `762ae9a`

The runtime baseline selected by this ledger is
[`762ae9ac8c735cdf8747b7dd73824bb50c1514b4`](https://github.com/edgepillar/zenon-spv/tree/762ae9ac8c735cdf8747b7dd73824bb50c1514b4),
tree `1057d25af955a139e2f273b0bcfa54a8b46cdd55`, following the local merge of
[PR #339](https://github.com/edgepillar/zenon-spv/pull/339). Both author and
committer are `edgepillar`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41961563244)
passed all seven scheduled jobs on attempt 1. Reconciliation covers all 37
actual archive IDs and 59,973,765 archive bytes, including 21 ordinary
native binary bindings, source/build metadata, architecture checks and selected
61-scenario reports. The separate exporter/transport workflows did not run at
this runtime revision; earlier observations retain their original source pins.

The complete uncached root-suite receipts cover 16 root-module packages.
Linux and macOS each record 955 root and 6,247 subtest completions: 7,202
passing events and zero skips. Windows records 951 root and 6,330 subtest
completions: 7,265 passing events and 16 skip events. Completion counts include
skips. The selected Windows reports separately retain five skips; the two
traces' skip counts are not additive. The
[candidate CI](https://github.com/edgepillar/zenon-spv/actions/runs/41958417224)
has its own completed source/run query and qualification of 37 archives
(59,973,698 bytes). Equal file trees did not transfer qualification between
candidate checkout `fb8f19dc128aeb042d01260053e82ed5153111b7` and main.
Archive readers reuse verified CAS objects, extract no payload files and
execute no new native tests or binaries.

### Per-header ownership copies

The [detached header copier](owned-header-copies.md) uses one private allocation
for each complete key/signature pair. Its two fields are disjoint and
capacity-clipped; nil/empty shape, mutation and append isolation, independent
snapshots and captured context remain covered. It does not retain a complete
window's byte storage when a single key is kept. The exact preceding copier is
an independent test reference. Existing extension, persistence, concurrency and
full-capacity sequence controls remain required and unchanged.

Local selected race tests passed 34 roots and 224 subtest completions, including
the complete 18-cell full-capacity model. Bounded fuzzing, vet and module
verification also passed. Three small structural benchmark repeats record
2 to 1 allocations per complete 32/64-byte envelope, and 8,193 to 4,097 for a
K=4096 snapshot; bytes allocated per operation are unchanged. These are copy
observations, not lower RSS, whole-CI latency or representative device budgets.

The preceding runtime's [version 2 BatchEntry source-field policy](experimental-batch-entry-query.md#version-2-source-field-policy),
34 independent canonical ABI vectors, original-node positive bytes, version 1
wire compatibility and context namespaces remain unchanged. This copy helper
changes no header serialization, signature validation, producer authorization,
anchor/profile/schedule selection, retention policy, state-file encoding or
proof acceptance rule. The source-field subset still does not establish all
SubmitBatch validation, executor authorization, input accounting, state
transitions, registration, activation or consensus finality.

### Source and review scope

The frozen-to-current pair contains 455 changed tracked paths, 191 changed
selected inputs and 102 root-module Go paths: 44 implementation/driver files
and 58 test files. Root `go.mod` and `go.sum` are unchanged. The narrower
historical `da04d418`-to-current pair contains 182 tracked changes, 106
selected-input changes and 90 root-module Go paths: 41 implementation/driver
files and 49 tests. Counts use per-revision module ownership; all earlier
records keep their original pairs.

The direct preceding-runtime `143725d`-to-`762ae9a` pair contains seven changed
tracked paths, two selected inputs and two root-module Go paths (one
implementation file and one test file). Four documentation paths and the CI
workflow are outside the selected-input fingerprint. The table below uses exact
Git blob IDs; an em dash means the earlier path was absent.

| Path | Earlier blob | Selected baseline blob | Review impact |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | `cc564808ffba478c28a6df654fb1e2e1019da32f` | `f4179f78d34264ba8952e0f37d12feb13cd397c5` | Adds source-bound copy controls and bounded allocation observations on the native lanes. |
| `docs/native-roadmap.md` | `1071141ff08dd3063bf064a9d2d678eb48b8c69a` | `0ec9c933e14f8022dd53a0a6552a845e972a10a2` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `docs/owned-header-copies.md` | — | `61442ed304b5c5b803bfa3ed76ecb46eb12181c3` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `docs/retained-state-sequences.md` | `0f7bbf44f4bcced10706b9b28da7062870f920d8` | `5ae28e03f0d8833c3083783e8c9a8d26b6fb1a75` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `docs/review-candidate-changes.md` | `4b2bbcd334f026ef1ea58b8ae4e8d2cc54acaaf4` | `94569b563b76bcb2388801354b3ff35faefeafd8` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `internal/verify/owned_header_copy_test.go` | — | `e678a6731b1f1f04ecde70e0192a449dd42bf0f8` | Prior-copier comparison, shape/overlap/ownership, bounded fuzz and allocation controls. |
| `internal/verify/verified_state.go` | `d46adcd549fced047fabd27fefff61416cdb1601` | `8e3ac09b3177e8c1564802b83ea63383f612f3af` | One private capacity-clipped envelope allocation; validation and serialized bytes unchanged. |

Review the complete current pair with explicit two-revision commands:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 762ae9ac8c735cdf8747b7dd73824bb50c1514b4
git diff 6ecc2310538d511e3b26bea4c658082853266a11 762ae9ac8c735cdf8747b7dd73824bb50c1514b4 -- cmd internal tools go.mod go.sum
```

The second command includes nested modules and other material in those
directories; use the module filter below for the 102-path root Go scope.
The 726-input fingerprint below was independently recomputed from Git blobs.
Python, workflows and other excluded inputs require separate inspection.

This ledger update supplies no new native execution and does not advance the
frozen human-review candidate. Later documentation-only heads retain runtime
qualification at `762ae9a`; scope-only CI cannot qualify native execution.
All failed, interrupted and superseded observations retain their actual
outcomes; later successful CI does not rewrite them.

The [D0-D6 contract](typed-state-roadmap.md) still needs the independently
selected network/query/profile/anchor/schedule and actual consumer capture,
representative R1 data, independent review and authenticated distribution.
Production state proofs and irreversible settlement remain NO-GO.


### Earlier runtime selection: `143725d`

The runtime baseline selected by this ledger is
[`143725d9df7bd726d6bdd598466576b8bc7423a4`](https://github.com/edgepillar/zenon-spv/tree/143725d9df7bd726d6bdd598466576b8bc7423a4),
tree `51476602315de56d0e51b9bd13cdd8f2691bebfc`, following the local merge of
[PR #337](https://github.com/edgepillar/zenon-spv/pull/337). Both author and
committer are `edgepillar`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41948622040)
passed all seven scheduled jobs on attempt 1. Reconciliation covers all 37
actual archive IDs and 59,975,612 archive bytes, including 21 ordinary native
binary bindings, source/build metadata, architecture checks and selected
61-scenario reports. The separate exporter/transport workflows did not run at
this runtime revision; earlier observations retain their original source pins.

The complete uncached root-suite receipts cover 16 root-module packages.
Linux and macOS each record 950 root and 6,116 subtest completions: 7,066
passing events and zero skips. Windows records 946 root and 6,199 subtest
completions: 7,129 passing events and 16 skip events. Completion counts include
skips. The selected Windows reports separately retain five skips; the two
traces' skip counts are not additive. The
[candidate CI](https://github.com/edgepillar/zenon-spv/actions/runs/41945212880)
has its own completed source/run query and qualification of 37 archives
(59,975,518 bytes). Equal file trees did not transfer qualification between
candidate checkout `5fe021ff422878b2c84a7080763b62c5d8d56692` and main.
Each source's receipt controls refused all 110 changed source/run/step bindings.
Archive readers reuse verified CAS objects, extract no payload files and
execute no new native tests or binaries.

### Explicit BatchEntry source-field policy

[Query profile version 2](experimental-batch-entry-query.md#version-2-source-field-policy)
requires `source_rule: "zenon-phase1-batch-fields/v1"`. After canonical
membership and bounded strict ABI decoding, both the single-row and three-row
APIs check the pinned phase1 pillar-name rule (1 through 40 ASCII bytes),
asset-flow count/framing/token-ID encoding/order/nonzero amounts, and empty
proof data. Positive local caps remain mandatory. The three-row and entry
profile versions must agree; both version 2 contexts have separate namespace
bytes. Version 1 retains its original exact wire schema and context preimages.
The read-only CLI reports a mismatch as exit 1, `query/source_rule_mismatch`,
with a null result even when the configured headers and proof were valid.

The independent Python corpus supplies 34 canonical ABI vectors and
reconstructs the retained original three-row proof bytes before constructing
a separate negative mathematical tree. Positive original-node bytes remain
unchanged. The negative owned-state and compiled-CLI controls use public
synthetic unit signatures; they are not original-node or selected-network
execution. Trusted restart, mixed-version refusals, detached results and
legacy behavior remain covered. The generic ABI codec is unchanged.

This rule is a source-field subset at the pinned node revision. It does not
establish all SubmitBatch validation, executor authorization, input/deposit
accounting, state transitions, registration, activation or consensus finality.
The [D0-D6 contract](typed-state-roadmap.md) still needs the independently
selected network/query/profile/anchor/schedule and actual consumer capture,
representative R1 data, independent review and authenticated distribution.
Production state proofs and irreversible settlement remain NO-GO.

### Source and review scope

The frozen-to-current pair contains 453 changed tracked paths, 190 changed
selected inputs and 101 root-module Go paths: 44 implementation/driver files
and 57 test files. Root `go.mod` and `go.sum` are unchanged. The narrower
historical `da04d418`-to-current pair contains 179 tracked changes, 104
selected-input changes and 88 root-module Go paths: 40 implementation/driver
files and 48 tests. Counts use per-revision module ownership; all earlier
records keep their original pairs.

The direct preceding-runtime `4ae2914`-to-`143725d` pair contains 20 changed
tracked paths, 13 selected inputs and 11 root-module Go paths (seven
implementation files and four tests). Six other paths are documentation; the
independent Python generator is outside the selected-input fingerprint.
The table below uses exact Git blob IDs; an em dash means the earlier path
was absent.

| Path | Earlier blob | Selected baseline blob | Review impact |
| --- | --- | --- | --- |
| `cmd/zenon-spv/experimental_batch_context.go` | `a8cf0cfa3621c05068340b5708ee4c8dda7e4dc7` | `61435a6be6ab541aaee8489f680c58df6e225da8` | Maps source mismatch to exit 1 with a null consumer result. |
| `cmd/zenon-spv/experimental_batch_entry.go` | `01f08696622497a23f7fb88f243b926e64649da6` | `dbdeed18298704c39017360437f54e1a6e9d09c9` | Maps source mismatch to exit 1 with a null consumer result. |
| `docs/batch-entry-query-contract.md` | `b93c6eed4b3b4deeb114f4f41ab5f2cdbfe11f00` | `ab0201d023248f966970f7060015da770232b97e` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `docs/experimental-batch-context-query.md` | `79fd3520549847eae3517b8cae95d8c5f10e65ba` | `0eeaffe1c81e338c7db4a7c027d90e73f974bb03` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `docs/experimental-batch-entry-cli.md` | `f29ec185e4ffa83a3601ae0958be56e7e4381fe2` | `8df811e8ef1d476c729ace1b2f0aa29a9c4a4923` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `docs/experimental-batch-entry-query.md` | `c9731c674ef5ad713ab98a75e1f50e4e27d47488` | `68d127ecdc4156423f59a2d4f16aeee218eed839` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `docs/native-roadmap.md` | `5761ed0b743f02b46e2536f35ac96a0ec3111116` | `1071141ff08dd3063bf064a9d2d678eb48b8c69a` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `docs/review-candidate-changes.md` | `cc72202ff812930af51e2fb90db8a506a6f92048` | `4b2bbcd334f026ef1ea58b8ae4e8d2cc54acaaf4` | Source-specific scope and evidence; no new native execution or human acceptance. |
| `internal/conformance/cli_batch_context_test.go` | `549be3a6d020d3695cd4f067610da1f71c9d07d3` | `3da4d713005b08e5c6a5cdb34a04f90276e32e01` | Exercises opt-in policy, unchanged node bytes, synthetic rejection and legacy compatibility. |
| `internal/conformance/cli_batch_source_rule_test.go` | — | `ef0cfc8b136a97512d20cd55eaf4d4acfa9a3b78` | Exercises opt-in policy, unchanged node bytes, synthetic rejection and legacy compatibility. |
| `internal/conformance/cli_experimental_batch_positive_test.go` | `53f3bfd4527052302b6391e44943a366f8f8565f` | `374092dce1c9364b920fc19307c45175d9af41de` | Exercises opt-in policy, unchanged node bytes, synthetic rejection and legacy compatibility. |
| `internal/testdata/conformance/batch-entry-source-rule-invalid-context.json` | — | `93008a673839fcd90d054589dc17954cadb05f1b` | Independent ABI/proof vectors or synthetic negative workflow; no network acceptance. |
| `internal/testdata/conformance/batch-entry-source-rule.json` | — | `a46f2567322a66f44982c9fee9992caccbb67477` | Independent ABI/proof vectors or synthetic negative workflow; no network acceptance. |
| `internal/testdata/conformance/batch-entry-source-rule.py` | — | `7ba6578c64c78354dae0c2cdc54a40340f389edf` | Independent stdlib byte reproduction, outside the selected-input fingerprint. |
| `internal/verify/experimental_batch_context.go` | `cbcf864071244dc2ed3303898f2a7bda120ef2bb` | `c125a8acd6e70003ec5c02c613d8be653332debb` | Applies the selected rule after canonical membership and strict ABI decoding. |
| `internal/verify/experimental_batch_context_profile.go` | `0bdd8e5b6c7782540ba10ed8d8fe108104fa38f5` | `bb175da1d86f7122269bbbc9295a62ef799a2c0e` | Requires matching profile versions and a distinct v2 namespace. |
| `internal/verify/experimental_batch_entry.go` | `48fbc57a7a808705c2866cb6b2643fe0c0a1c0d0` | `b76e0d8fe29029683924e45297be56b22770acbf` | Applies the selected rule after canonical membership and strict ABI decoding. |
| `internal/verify/experimental_batch_entry_profile.go` | `76e5b8914b3c9b27e1575b344c946d3874a59ffb` | `64a4268df9645245fbe65b86aa9735b934c1d597` | Separates exact v1/v2 schemas, rules and context preimages. |
| `internal/verify/experimental_batch_entry_source_rule.go` | — | `db203cb0ac42f3fd5dbda25c4ded077dd8b40366` | Implements the selected bounded source-field subset. |
| `internal/verify/experimental_batch_entry_source_rule_test.go` | — | `5349648c1dcaa96a3aabb4518f694a99b8c94ae4` | Exercises opt-in policy, unchanged node bytes, synthetic rejection and legacy compatibility. |

Review the complete current pair with explicit two-revision commands:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 143725d9df7bd726d6bdd598466576b8bc7423a4
git diff 6ecc2310538d511e3b26bea4c658082853266a11 143725d9df7bd726d6bdd598466576b8bc7423a4 -- cmd internal tools go.mod go.sum
```

The second command includes nested modules and other material in those
directories; use the module filter below for the 101-path root Go scope.
The 725-input fingerprint below was independently recomputed from Git blobs.
Python, workflows and other excluded inputs require separate inspection.

This ledger update supplies no new native execution and does not advance the
frozen human-review candidate. Later documentation-only heads retain runtime
qualification at `143725d`; scope-only CI cannot qualify native execution.
All failed, interrupted and superseded observations retain their actual
outcomes; later successful CI does not rewrite them.


### Earlier runtime selection: `4ae2914`

The runtime baseline selected by this ledger is
[`4ae2914d6c3e07def37316a3a7f1e61ed86028cb`](https://github.com/edgepillar/zenon-spv/tree/4ae2914d6c3e07def37316a3a7f1e61ed86028cb),
tree `63e421a7c05abf340cbd070cc7d7c6db1f77c5aa`, following the local merge of
[PR #335](https://github.com/edgepillar/zenon-spv/pull/335). Both author and
committer are `edgepillar`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41928953290)
passed on attempt 1. Reconciliation covers all seven scheduled jobs, 37 actual
archive IDs and 59,966,795 archive bytes, including 21 ordinary native
executables, source/build metadata, architecture checks and the selected
61-scenario reports. The selected Windows reports retain five skips; Linux and
macOS have zero. The separate exporter/transport workflows did not run at this
revision: their earlier observations retain their original source pins.

The complete uncached root-suite receipts cover 16 root-module packages.
Linux and macOS each record 946 root and 6,040 subtest completions: 6,986
passing events and zero skips. Windows records 942 root and 6,123 subtest
completions: 7,049 passing events and 16 skip events. Root/subtest completion
counts include skips; they must not be read as additional passing counts.
These full-suite counts and the five selected Windows skips describe different
scopes. Both the PR source and the local main merge have their own completed
queries and artifact qualification; an equal tree did not transfer either result.
Each source's receipt controls refused all 110 changed source/run/step bindings.
The main reader reused ten verified archive objects and acquired the remaining
27 once. It extracts no payload files and executes no new native tests or binaries.

The experimental owned-v3, typed BatchEntry, three-witness and explicitly pinned
checkpoint/collector paths retain their existing
[experimental contract](experimental-batch-context-query.md). They do not yet
supply an independently selected real-network capture or state-transition proof.
The new native persistence encoder is a separate allocation improvement, with
the existing profile, signature, producer, context and atomic-file checks.

The frozen-to-current pair contains 447 changed tracked paths, 185 changed
selected inputs and 98 root-module Go paths: 43 implementation/driver files and
55 test files. Root `go.mod` and `go.sum` are unchanged. The narrower historical
`da04d418`-to-current pair contains 173 tracked changes, 99 selected-input
changes and 85 root-module Go paths: 39 implementation/driver files and 46 tests.
Counts use per-revision module ownership; the historical tables below retain
their original pairs.

### Changes since the preceding runtime selection

The direct `62524106`-to-`4ae2914` pair contains six tracked changes and three
selected-input changes, all three root-module Go paths: two implementation
files and one test file. The other three paths are documentation, including
the preceding ledger update. Blob IDs identify file bytes; an em dash means
the earlier path was absent.

| Path | Earlier blob | Selected baseline blob | Review impact |
| --- | --- | --- | --- |
| `internal/verify/state_encode.go` | — | `7178745f5bce70d88e4f6c1dd7024cc6558f0b58` | Reuses encoding/json for one metadata value or header, with bounded output buffering and short-write handling. |
| `internal/verify/state_encode_test.go` | — | `d4b7812b12373febad3cfd000c621782bb6db6dd` | Compares complete prior-format bytes, boundaries, failures and input ownership; retains paired local encoding observations. |
| `internal/verify/state_file.go` | `c5ec961b1aefcf280c5f29bb5cb3fe18a8add290` | `0708fb04d3a53c04b01aa28a2455c22c86de5f60` | Routes native saves through the new encoder within the existing validated atomic-write protocol. |

The [persistence record](owned-state-persistence.md) retains the local
byte-for-byte comparison, exact cap and short-write controls, and all 36
initial/revised encoding benchmark rows. At 4,096 synthetic headers, revised
encoding used 2,395,506 B/op versus 18,103,597-18,103,642 B/op; allocation count
increased to 24,598 from 20,526-20,527. This measures encoding to `io.Discard`,
not file latency, process RSS, representative R1 data or whole-CI acceleration.
The output buffer is capped at 32 KiB; an individual metadata value can require
a larger encoding buffer.

The local component phases completed 12 race-test roots, 89 subtest pass events,
18 benchmark rows, focused vet and module verification. The outer wrapper then
ended with actual exit -9 and incomplete output during cleanup; its FAILURE
record remains retained. Its approved temporary remainder was subsequently
removed with the test evidence preserved. A separate interrupted main CI
observer remains UNKNOWN; fresh completed queries and main qualification do
not rewrite that outcome. These records remain separate from the successful
hosted full suites.

Review the complete current pair with explicit two-revision commands:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 4ae2914d6c3e07def37316a3a7f1e61ed86028cb
git diff 6ecc2310538d511e3b26bea4c658082853266a11 4ae2914d6c3e07def37316a3a7f1e61ed86028cb -- cmd internal tools go.mod go.sum
```

The second command includes nested modules and other material in those
directories; apply the module filter defined below for the 98-path Go scope.
The 720 selected-input fingerprint is independently recomputed from Git blobs
in the table below. Python, workflow and other excluded inputs still require
their own inspection and exact-source evidence.

This ledger update supplies no new native execution and does not advance the
frozen human-review candidate. Later documentation-only heads retain runtime
qualification at `4ae2914`; scope-only CI cannot qualify native execution.
The [D0-D6 plan](typed-state-roadmap.md) still requires the independently selected
query/profile/anchor/schedule and actual network capture, representative R1 data,
independent review and authenticated distribution. Production state proofs and
irreversible settlement remain NO-GO.


### Earlier runtime selection: `62524106`

The runtime baseline selected by this ledger is
[`62524106cb363c51a1018f474693f46842eb6f32`](https://github.com/edgepillar/zenon-spv/tree/62524106cb363c51a1018f474693f46842eb6f32),
tree `fe67354c5d483aa7f3216462a73c7c87d953b153`, following the local merge of
[PR #333](https://github.com/edgepillar/zenon-spv/pull/333). Both author and
committer are `edgepillar`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41908988549)
passed on attempt 1. Reconciliation covers all seven scheduled jobs, 37 actual
archive IDs and 59,944,159 archive bytes, including 21 ordinary native
executables, source/build metadata, architecture checks and the selected
61-scenario reports. The selected Windows reports retain five skips; Linux and
macOS have zero. The separate exporter/transport workflows did not run at this
revision: their earlier observations retain their original source pins.

The complete uncached root-suite receipts cover 16 root-module packages.
Linux and macOS each record 942 root and 5,967 subtest completions: 6,909
passing events and zero skips. Windows records 938 root and 6,050 subtest
completions: 6,972 passing events and 16 skip events. Root/subtest completion
counts include skips; they must not be read as additional passing counts.
These full-suite counts and the five selected Windows skips describe different
scopes. The artifact reader extracts no payload files and executes no new native
tests or candidate binaries. It reused 25 verified archive objects and acquired
the remaining 12 once; every archive still received its own source/content checks.

Since the historical `da04d418` baseline, the source adds configured owned-v3
headers, immutable state/persistence, typed `BatchEntry` and three-witness
queries, explicitly hash-pinned trusted checkpoint reuse, and collection of
only the missing header suffix while retaining the original anchor. Their
[experimental contract](experimental-batch-context-query.md) retains locally
derived keys, header-bound roots and finite operator-selected producer schedules.
The pooled node-derived leaf values and separately signed synthetic header
fixtures are not one real network capture or a state-transition proof.

The frozen-to-current pair contains 445 changed tracked paths, 183 changed
selected inputs and 96 root-module Go paths: 42 implementation/driver files and
54 test files. Root `go.mod` and `go.sum` are unchanged. The narrower historical
`da04d418`-to-current pair contains 170 tracked changes, 97 selected-input
changes and 83 root-module Go paths: 38 implementation/driver files and 45 tests.
Counts use per-revision module ownership; the historical 18-path table below
describes only its original pair.

### Changes since the preceding runtime selection

The direct `e1e2fda4`-to-`62524106` pair contains 25 tracked changes and ten
selected-input changes, all ten of them root-module Go paths: four implementation
files and six test files. The following entry points describe that narrower pair;
they do not replace review of the complete frozen-to-current delta. Blob IDs
identify file bytes; an em dash means the earlier path was absent.

| Path | Earlier blob | Selected baseline blob | Review impact |
| --- | --- | --- | --- |
| `cmd/zenon-spv/experimental_batch_input.go` | `f2af375cf7f474b0192e673fc50592cfac7386c6` | `8ea02bcc7986a283eff04b2f7e040d3421273063` | Uses an opened regular-file size as a bounded allocation hint; EOF, growth and read-error checks remain required. |
| `cmd/zenon-spv/experimental_batch_read_test.go` | — | `5a98885e43b7b6765e09610139adfe2340211ca4` | Exercises read hints, allocation observations and exact bounded-input behavior. |
| `internal/conformance/cli_query_test.go` | `0f3e79d57e21daa044a5cf6074eb8aa874743646` | `f91fbddd35d6f851d852e3f61332b93797732869` | Routes unchanged-checkpoint guards through the bounded byte comparison. |
| `internal/conformance/cli_state_guard_test.go` | — | `df9b8f3997817d532e7147e0a113b571a5aab58d` | Checks exact bytes, EOF and read failures with a private comparison buffer; retains finite paired allocation observations. |
| `internal/proof/bundle_json.go` | `9f02e67a235c4de82abe30f31f1b0b18264070a3` | `7e9f01cf521a55cb75e922906ccea60f8bc1cc52` | Keeps the public syntax/nesting validation and shares already completed encoding/json validation only through private callbacks. |
| `internal/proof/bundle_syntax_test.go` | — | `683b131153010b56715239edd7f028c597c62b23` | Exercises direct/public decoding, encoding/json callbacks and malformed or over-limit JSON. |
| `internal/proof/serialize.go` | `dbd420e8a63fa56f04754c0883499f461889d1b2` | `0ac8bb2a11c437939e10ea34c1d212d9a306b390` | Uses the private checked-decoder path after bounded top-level JSON syntax validation. |
| `internal/verify/experimental_v3_profile_test.go` | `1ce5f0aaf28bc72bd080fa2fdad68cdb7edac949` | `8abb022c21233e0a543c0a48328eac212610afd5` | Preserves admission/refusal controls while checking retained-state behavior. |
| `internal/verify/experimental_v3_retention_test.go` | — | `f7640e354000774307b12b193ac75f8e1ad2b323` | Exercises header-tail ownership, old-handle independence, rejected input and finite retention allocations. |
| `internal/verify/experimental_v3_state.go` | `5d44e2e3f8fee00473159b21a22061dd9b4947f0` | `9874a3ad2c35e6e3ac853973f11467abb592b47e` | Validates every incoming header, then copies only the retained new tail into fresh owned storage. |

The other 15 paths cover Python consumer selection and its controls, CI scope
and workflow selection, and documentation. The
[selected consumer check](independent-consumer-checks.md) validates the complete
738-ID catalog but prepares only a requested finite case; the default full
enumeration remains unchanged. The
[recorded-oracle scope rule](ci-change-scope.md) can omit unchanged recorded
oracles for a finite reviewed native-v3 change; required native execution and
source-specific artifact checks remain separate. The bounded input, JSON syntax,
retention and test-guard observations have local resource scopes; none establishes
representative network budgets, whole-CI acceleration or independent acceptance.

Review the complete current pair with explicit two-revision commands:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 62524106cb363c51a1018f474693f46842eb6f32
git diff 6ecc2310538d511e3b26bea4c658082853266a11 62524106cb363c51a1018f474693f46842eb6f32 -- cmd internal tools go.mod go.sum
```

The second command includes nested modules and other material in those
directories; apply the module filter defined below for the 96-path Go scope.
The 718 selected-input fingerprint is independently recomputed from Git blobs
in the table below. Python, workflow and other excluded inputs still require
their own inspection and exact-source execution evidence.

This ledger update supplies no new native execution and does not advance the
frozen human-review candidate. Later documentation-only heads retain the runtime
qualification at `62524106`; their scope-only CI cannot qualify native execution.
The [D0-D6 plan](typed-state-roadmap.md) still requires the independently selected
query/profile/anchor/schedule and actual network capture, representative R1 data,
independent review and authenticated distribution. Production state proofs and
irreversible settlement remain NO-GO.

### Earlier runtime selection: `e1e2fda4`

The runtime baseline selected by this ledger is
[`e1e2fda4910d876588adb9badcb1c0d06c109ccd`](https://github.com/edgepillar/zenon-spv/tree/e1e2fda4910d876588adb9badcb1c0d06c109ccd),
tree `6fe6c917722a6b741b2a52808f0ed0f67d7afd57`, following the local merge of
[PR #325](https://github.com/edgepillar/zenon-spv/pull/325). Both author and
committer are `edgepillar`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41779740902)
passed on attempt 1. Reconciliation covers all seven scheduled jobs, 37 actual
archive IDs and 59,889,796 archive bytes, including 21 ordinary native
executables, source/build metadata, architecture checks and the selected
61-scenario reports. The selected Windows reports retain five skips; Linux and
macOS have zero. The separate exporter/transport workflows did not run at this
revision: their earlier observations retain their original source pins.

The complete uncached root-suite receipts cover 16 root-module packages.
Linux and macOS each have 928 passing roots, 5,714 passing subtest events and
6,642 total passing events, with zero skips. Windows has 924 passing roots,
5,797 passing subtest events, 6,705 total passing events and 16 skip events.
These full-suite counts and the five selected Windows skips describe different
scopes. The three-witness compiled consumer case has 25 passing child events on
each platform, 75 in total, zero skips and six executed binary bindings. These
events come from the same existing suite and candidate builds; the artifact
reader extracts no payload files or executes another candidate.

Since the historical `da04d418` baseline, the source adds configured owned-v3
headers, immutable state/persistence, typed `BatchEntry` and three-witness
queries, explicitly hash-pinned trusted checkpoint reuse, and collection of
only the missing header suffix while retaining the original anchor. Their
[experimental contract](experimental-batch-context-query.md) retains locally
derived keys, header-bound roots and finite operator-selected producer schedules.
The pooled node-derived leaf values and separately signed synthetic header
fixtures are not one real network capture or a state-transition proof.

The frozen-to-current pair contains 432 changed tracked paths, 176 changed
selected inputs and 89 root-module Go paths: 40 implementation/driver files and
49 test files. Root `go.mod` and `go.sum` are unchanged. The narrower historical
`da04d418`-to-current pair contains 157 tracked changes, 90 selected-input
changes and 76 root-module Go paths. Counts use per-revision module ownership;
the historical 18-path table below describes only its original pair.

Review the complete current pair with explicit two-revision commands:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 e1e2fda4910d876588adb9badcb1c0d06c109ccd
git diff 6ecc2310538d511e3b26bea4c658082853266a11 e1e2fda4910d876588adb9badcb1c0d06c109ccd -- cmd internal tools go.mod go.sum
```

The second command includes nested modules and other material in those
directories; apply the module filter defined below for the 89-path Go scope.
The selected-input fingerprint is independently recomputed from Git blobs in
the table below. Python, workflow and other excluded inputs still require
their own inspection and exact-source execution evidence.

This pointer repair supplies no new native execution and does not advance the
frozen human-review candidate. The [D0-D6 plan](typed-state-roadmap.md) still
requires the independently selected query/profile/anchor/schedule and actual
network capture, representative R1 data, independent review and authenticated
distribution. Production state proofs and irreversible settlement remain NO-GO.

The historical qualified development baseline is
[`879fbce33dd77f483f7aba18994fb037f248e842`](https://github.com/edgepillar/zenon-spv/tree/879fbce33dd77f483f7aba18994fb037f248e842),
tree `a8eb348464eb76eae080d3966ded6592ef078f9f`. Its
[main CI run](https://github.com/edgepillar/zenon-spv/actions/runs/40066341088)
and retained reconciliation cover 71 evidence families, nine archives, 21
ordinary executables and the same 59 scenarios per platform, with the platform
skip limits retained. The
[historical nine-file root-module ledger](https://github.com/edgepillar/zenon-spv/blob/d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff/docs/review-candidate-changes.md)
and original reports remain pinned to their original revisions.

The preceding baseline with full main/exporter/transport reconciliation is
[`d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff`](https://github.com/edgepillar/zenon-spv/tree/d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff),
tree `218a7ba87fd3be5be6c304573cc7e26da5ec7fdc`. Its own
[main CI](https://github.com/edgepillar/zenon-spv/actions/runs/40469107108),
[exporter CI](https://github.com/edgepillar/zenon-spv/actions/runs/40469107110)
and [transport CI](https://github.com/edgepillar/zenon-spv/actions/runs/40469107164)
passed at this exact main SHA. The separate reconciliation covers all 30 actual
artifact IDs across 12 jobs: 21 ordinary native executables, their source/build
metadata and scenario reports, the exporter and transport packages, inventory
reports, recorded selections and auxiliary reports. SHA-256 and declared byte
lengths match the selected artifact metadata. Five native Windows skips and one
exporter Windows interrupt skip remain explicit. The reader extracts no payload
files and runs no new native tests or binaries. Earlier successful runs were not
used as this revision's CI proof. This completed pipeline observation remains
pinned to its original revision.

The preceding development baseline with completed general runtime CI is
[`b6358c1943a0c2fbce5046c201f7d2e319b3089f`](https://github.com/edgepillar/zenon-spv/tree/b6358c1943a0c2fbce5046c201f7d2e319b3089f),
tree `303884b78e1ad68ad3bedc9f2403159116068fb8`. Its
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/40484050738)
passed at this exact main SHA. Its separate reconciliation covers all 28 actual
artifact IDs from seven general CI jobs, including 21 ordinary native
executables, paired pilot reports, inventory, recorded and auxiliary evidence,
the scope selection and scope-control reports. All 36 scope-control names match
the selected source on the three native platforms. Five native Windows skips
remain explicit. Declared lengths and SHA-256 values match the selected archive
metadata; the reader extracts no payload files and executes no new native tests
or binaries. This general workflow did not run the separate exporter/transport
workflows at the new revision; their preceding observations remain pinned above.
Earlier successful runs and equal source trees were not used as this revision's
CI proof. The frozen review candidate remains unchanged.

The preceding qualified retention baseline is
[`bc0be26d76dd07d297dfdf5b00768d23527e49f5`](https://github.com/edgepillar/zenon-spv/tree/bc0be26d76dd07d297dfdf5b00768d23527e49f5),
tree `e7cbe07015a7735997cb578fdee79fee274da4ca`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/40499229637)
and [transport main CI](https://github.com/edgepillar/zenon-spv/actions/runs/40499229396)
completed. Reconciliation covers all 34 actual artifact IDs across ten jobs:
31 general archives, including 21 native executables and their paired reports,
plus three transport packages. Source/build metadata, byte lengths, SHA-256,
architectures, actual steps and the five declared native Windows skips match.
The three new retention reports preserve all 17 new controls, 24 original test
roots and 252 root/proof cells on each reader platform. They check recorded
observations and perform no new node execution. The reader extracts no payload
files and reruns no tests or binaries. The exporter did not run at this revision;
its earlier observation remains separately pinned to `d85aff12` above.

The root-module Go delta and all 634 selected Go/module/JSON blobs remain equal
to `b6358c1`. The new Python/workflow inputs have their own source inspection,
control results and exact-source main qualification; equal Go inputs were not
used as the new revision's CI proof. A later documentation-only successful head
keeps this runtime-qualified baseline explicit and does not advance it. The
frozen human-review candidate and its original packet remain unchanged.

The preceding qualified development baseline selected by this ledger is
[`87677080c335444fb047c54c1b8d683cee436726`](https://github.com/edgepillar/zenon-spv/tree/87677080c335444fb047c54c1b8d683cee436726),
tree `5093fafa92f2b85555ce6ca0ca8dd49754b1f8ee`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/40556083707)
and [transport main CI](https://github.com/edgepillar/zenon-spv/actions/runs/40556083786)
passed on their first attempts. Reconciliation covers all 37 actual artifact IDs
and 93,591,632 archive bytes across ten jobs: 34 general archives, including 21
native executables and their paired reports, plus three transport packages.
Source/build metadata, byte lengths, SHA-256 values, architectures, actual steps,
scenario inventories and the five native Windows skips match. Linux and macOS
native reports contain zero skips. The new import-resource reports bind 19 new
controls, all 45 original controls and their selected child recipes on each
reader platform. The reader extracts no payload files and reruns no tests or
binaries. The exporter did not run at this revision; its earlier observation
remains pinned separately to `d85aff12` above.

All 634 selected Go/module/JSON blobs remain equal to `bc0be26`, including the
14-file root-module delta below. The nine changed paths since that baseline are
Python, workflow and documentation inputs with their own source and exact-main
qualification. Equal Go inputs were not used as the new revision's CI proof.
The canonical local merge has `edgepillar` as both author and committer.

The preceding candidate-stream development baseline was
[`1b8a33fd351ee5b7c697aac21940323ee1f81c74`](https://github.com/edgepillar/zenon-spv/tree/1b8a33fd351ee5b7c697aac21940323ee1f81c74),
tree `38d9c0b37554622454452c149d251dad99204978`. Its own
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/40648232108)
passed on its first attempt. Reconciliation covers all 34 actual artifact IDs
and 59,318,902 archive bytes across seven general jobs, including
21 ordinary native executables and their paired reports. Source/build metadata,
declared lengths and SHA-256 values, architectures and scenario inventories
match. Five native Windows skips remain explicit; Linux and macOS have zero.

The three native uploads each contain one stored `candidate-v1.tar.xz` member.
The source-checked writer and completed-stream readback passed on all three
platforms at this exact main SHA. A bounded independent standard-library TAR
pass also checks member hashes and architecture headers. The reader extracts no
payload files and executes no new native tests or binaries. The earlier Windows
readback failure at `517cd922` remains separate evidence; the correction pins
path and descriptor metadata to separate unchanged snapshots.

The 634 selected Go/module/JSON inputs differ from the preceding selected
`8767708` baseline because its source-enumeration test changed. The content total
is 34,948,765 bytes and the framed digest is
`2cc96345633910a132df1d72fe0c7d3b05b6917b8469c4c36277b1784fbee8e0`.
Python/workflow inputs have their own inspection and exact-source checks.
Neither a matching tree nor the preceding PR's CI was used as this main
revision's runtime proof. The local merge has `edgepillar` as both author and
committer. Separate exporter/transport workflows did not run at this revision;
their earlier observations remain pinned above.

In the preceding stream record, "current" meant the explicitly selected qualified
`1b8a33f` baseline. The following section selects its independently qualified
root-suite successor. The frozen human-review candidate and original packet
remain fixed.

## Historical complete-root-suite baseline

The qualified root-suite development baseline selected at PR #292 was
[`da04d4189017da7ddd2f56e82bd856875e272aed`](https://github.com/edgepillar/zenon-spv/tree/da04d4189017da7ddd2f56e82bd856875e272aed),
tree `d6b5513900b8dce954778160e7501611a6d563ee`. Its author and committer
are both `edgepillar`. It follows the canonical local merge of
[PR #292](https://github.com/edgepillar/zenon-spv/pull/292).

Its own [general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41341596977)
and [transport main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41341597164)
passed on attempt 1. Reconciliation covers all ten scheduled jobs, all 40 actual
archive IDs and 59,515,369 archive bytes: 37 general archives and three transport
archives. The candidate stream readers checked all 21 ordinary native
executables, paired reports, source/build metadata, architectures and the 59
selected scenarios per platform without extracting or executing another candidate.
Selected native Windows reports retain five skips; Linux and macOS have zero.

The new root-suite receipts separately bind all 16 root-module packages to the
actual uncached Go execution. Linux and macOS each report 5,002 passing test
events and zero skips. Windows reports 5,066 passes and 16 skips. These complete
suite counts and the selected native scenario skips have different scopes.

The pilot driver projects the existing selected report from that same complete
Go event stream. It rejects an unselected failure, incomplete stream/process,
source change or ambiguous test lifecycle, including genuine slash-labelled
`t.Run` names. Separate `root-suite-*` archives bind the small receipt and its
independent checker; the ordinary selected report and candidate format stay
compatible. Main's selected-report steps took 0 seconds on Linux and 1 second
on macOS/Windows at the recorded step granularity. The second selected-test
invocation is removed structurally; these observations do not establish a
controlled whole-CI or hardware speedup.

All 636 selected Go/module/JSON inputs were read independently from this exact
source. Their content total is 34,974,843 bytes and framed digest is
`91971f2505e3511263feee52fcdfe70b6fd29ef989351ce6926f819c7fff2328`.
Python/workflow inputs retain separate source and execution checks. The changed
non-Go controls include `tools/check-root-suite.py`,
`tools/check-root-suite_test.py` and `.github/workflows/ci.yml`; the Linux
pinned lint/schema/configuration steps now precede long controls and full tests.

The first source's slash-label refusal, the next source's late lint failure and
the interrupted local lint-cache attempt retain their original outcomes. They
are not relabelled as passing runs. The `1b8a33f` and all earlier qualified
records above remain source-specific. A documentation-only head after this
baseline supplies no new native execution. The original `6ecc231` review
selection, independent human acceptance, activation, production state proofs
and authenticated distribution remain separate gates.

## Identity migration and comparison scope

The identity-only history migration preserved the original upstream base,
original commits, old-to-new mapping and historical verification evidence.
The following pairs have exactly equal Git trees:

| Original revision | Identity-normalized counterpart | Equal tree |
| --- | --- | --- |
| `6ecc2310538d511e3b26bea4c658082853266a11` | `710627ae9589beca4a23400cc47fb038eb5495fd` | `76076d3b6669aa34e74dca30ed5cf38b683e085b` |
| `879fbce33dd77f483f7aba18994fb037f248e842` | `9d0e2708b638310315f72b1f113c9f32d4d44995` | `a8eb348464eb76eae080d3966ded6592ef078f9f` |

The counterparts are ancestors of the current development source. They provide
navigation through the recreated history; they do not acquire the original
revision's CI run, frozen packet or independent acceptance. The selected review
revision is still the original `6ecc2310538d511e3b26bea4c658082853266a11`.

Use an explicit two-revision `git diff` for the intended file comparison.
A three-dot comparison against the original commit can choose an earlier common
ancestor after the migration. The
[normalized ancestry comparison](https://github.com/edgepillar/zenon-spv/compare/710627ae9589beca4a23400cc47fb038eb5495fd...4ae2914d6c3e07def37316a3a7f1e61ed86028cb)
is useful for navigation with the tree-equivalence limit above.

## Historical root-module Go and module-file delta at PR #292

The exact frozen-to-`da04d418` diff contains 18 root-module Go files: eight
implementation/driver files and ten test files. Root `go.mod` and `go.sum`
are unchanged. This table excludes nested research modules, corpus JSON,
scripts, workflow and documentation changes; it is not the complete repository
diff. Git blob identifiers refer to file bytes, not commits or SHA-256 digests.
An em dash means the path was absent in the frozen revision.

| Path | Frozen blob | Current blob | Review impact |
| --- | --- | --- | --- |
| `internal/chain/candidate_v3.go` | — | `244d4f10a866f4e816e6cbd4126d7376649e4890` | Adds bounded, untrusted candidate-v3 decoding and projected hashing; it does not enable v3 admission. |
| `internal/chain/candidate_v3_test.go` | — | `61775c37e2c16829cee852bcc53857c7c72332ee` | Exercises candidate codec bounds and recorded byte comparisons. |
| `internal/conformance/cli_observer_resources_test.go` | `c5e2b9a6db8e4943de14cc01697496c3289d71ee` | `fc452734a47b650a2d7f425ee697f98825c77d3d` | Checks the fixed incomplete-output facts and their privacy limits in the compiled observer resource cases. |
| `internal/conformance/cli_observer_signal_test.go` | — | `f2dbd90b0c20e10ede2d444d86d6ae8774978a9c` | Adds controlled ordinary-observer interruption/termination checks and explicit Windows limits. |
| `internal/conformance/cli_observer_test.go` | `08d021d9f90ab6501485eaf7354dff2e42b27279` | `ee307107ced3bdf23b8b70de8b732373ffbdce85` | Preserves the four-field successful observation and validates the separate incomplete-output failure facts. |
| `internal/proof/candidate_smt.go` | — | `1c2bda904dc296e4e2e0413be5a24abf94339967` | Adds bounded sparse-proof reconstruction and locally derived balance keys; the supplied root remains unauthenticated. |
| `internal/proof/candidate_smt_test.go` | — | `06df103a34f30611057d800af9e7346c0d9efc6d` | Compares proof outcomes and exercises encoding/domain limits. |
| `internal/verify/owned_state_save_test.go` | — | `65c1897a318bcdc3a981527fb18d8f76b05d9d06` | Checks owned-state persistence, mutable-state rejection and source-bound cost observations. |
| `internal/verify/state_file.go` | `9d9a84d53d9a7114fd048b8fc5bb12bf8d58533a` | `13d6dcc859717ffd0c778770cb6872051bcbd4f4` | Splits validated-state writing from public mutable-state validation while retaining the bounded atomic writer. |
| `internal/verify/verified_state.go` | `8abedce5daa5370f39b3f907f3c3e8fec47111d5` | `d46adcd549fced047fabd27fefff61416cdb1601` | Saves privately owned validated immutable state without repeating window cryptography. |
| `tools/observe-block/main.go` | `e3bee10f7c9cf7c69df8c08af7324fe911bb4eb0` | `6a934863b5a3c35f4619a04ee7b610942cd204db` | Adds SIGTERM cancellation and an optional fixed incomplete-output observation; successful observations retain four fields. |
| `tools/observe-block/main_test.go` | `6d5b613c10d0f8629f48cc1f036e8abe9fbd7112` | `dcadcc711f6e8660db00748a4a4f87754676d80c` | Validates the fixed failure facts without exposing private child diagnostics. |
| `tools/observe-block/process.go` | `bd51c37e783b8317ab209196435d756bc88b2aaa` | `b30ec557dbdc268b1b0dd7dd5f2495a942a29202` | Records stdout/stderr EOF and wait-delay expiry only for incomplete output, preserving the original child wait result and existing completion gates. |
| `tools/observe-block/process_eof_test.go` | `bd74d74c6a52a75b05ca741797c0e6ce65c4055a` | `a52f8583d91d75b8f1632edb3d5488f1fb4dd7d2` | Checks EOF/wait-delay refusal facts and the unchanged successful observation shape. |
| `tools/offline-pilot/full_suite.go` | — | `431fa678fc25c44a7a0a9833ffc52a57384d730b` | Reads one bounded complete Go event stream, preserves all module/test outcomes and projects the selected report with an independent receipt. |
| `tools/offline-pilot/full_suite_test.go` | — | `600ab1987bd35faea98009be850a3eb9ace282da` | Checks actual process completion, slash-labelled test names, package inventory, selected/unselected failures, stream bounds and receipt ownership. |
| `tools/offline-pilot/main.go` | `3ba68015004d2b6ad4b19e2c44987f77e444a2bc` | `2e1605502907b2e27609f2f7ff4ed80a093e6d32` | Adds explicit complete-suite selection and receipt options while preserving default selected-only behavior and strict completion. |
| `tools/offline-pilot/source_directory_cli_test.go` | `a4e535f0c9f4ba4ec7412c04bc0cb093117e6118` | `0feeeae3d75c13c44e207b3605a3fbc494908bfe` | Reuses one parent-owned wide source fixture while fresh CLI processes observe each original bound; retains all six controls and explicit growth checks. |

The historical nine-file table stopped at `879fbce33dd77f483f7aba18994fb037f248e842`.
The intervening `1b8a33f` record contained 15 distinct root-module paths,
including the source-enumeration test change after `8767708`. That historical
root-suite delivery adds three more distinct paths in `tools/offline-pilot`:
`full_suite.go`, `full_suite_test.go` and the newly changed `main.go`.
All 18 paths for that pair are listed above; earlier table counts retain their own
revision pairs.

Review the complete pair with:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 da04d4189017da7ddd2f56e82bd856875e272aed
git diff 6ecc2310538d511e3b26bea4c658082853266a11 da04d4189017da7ddd2f56e82bd856875e272aed -- internal tools/observe-block tools/offline-pilot go.mod go.sum
```

The second command includes other material in those directories. The table's
root-module filter is defined below; the complete repository diff remains
necessary for research, corpus, workflow and script changes.

## Recomputable input fingerprints

The historical frozen-to-`da04d418` tracked-file delta contains 296 paths. The
input selector below changes at 91 paths for that pair. Neither number is the
18-file root-module
delta. Python helpers, workflow files, shell scripts and other excluded paths
remain outside the selected-input fingerprint and require their own inspection.

Select root `go.mod` and `go.sum`, plus tracked paths under `cmd/`, `internal/`
or `tools/` ending in `.go` or `.json`, or named `go.mod`/`go.sum`. This selector
includes nested research modules. Read each revision's Git blobs without using
the working copy. Sort the selected paths lexicographically. For each path,
append its UTF-8 byte length as an unsigned 64-bit big-endian integer, the path
bytes, its content length in the same integer encoding, and the raw content.
SHA-256 the resulting stream. Total content bytes below exclude the path and
length framing.

| Revision | Tracked files | Selected inputs | Content bytes | Framed-input SHA-256 |
| --- | ---: | ---: | ---: | --- |
| `6ecc2310538d511e3b26bea4c658082853266a11` | 892 | 555 | 30,804,645 | `f3893381b876e3c782dc05ec28d7f12e10b4a1aa6cb347c76095c9bd98ea08a6` |
| `879fbce33dd77f483f7aba18994fb037f248e842` | 1,081 | 611 | 34,769,782 | `e750a552b7cc1310c6b5862a692ca36e7519b9c379f871781b928d5ba4d2876b` |
| `d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff` | 1,141 | 634 | 34,948,025 | `46367e744b6c687ca3ebe3558df3d745963a322efb32fcbd651bad2098497da9` |
| `b6358c1943a0c2fbce5046c201f7d2e319b3089f` | 1,144 | 634 | 34,948,025 | `46367e744b6c687ca3ebe3558df3d745963a322efb32fcbd651bad2098497da9` |
| `bc0be26d76dd07d297dfdf5b00768d23527e49f5` | 1,148 | 634 | 34,948,025 | `46367e744b6c687ca3ebe3558df3d745963a322efb32fcbd651bad2098497da9` |
| `87677080c335444fb047c54c1b8d683cee436726` | 1,152 | 634 | 34,948,025 | `46367e744b6c687ca3ebe3558df3d745963a322efb32fcbd651bad2098497da9` |
| `1b8a33fd351ee5b7c697aac21940323ee1f81c74` | 1,158 | 634 | 34,948,765 | `2cc96345633910a132df1d72fe0c7d3b05b6917b8469c4c36277b1784fbee8e0` |
| `da04d4189017da7ddd2f56e82bd856875e272aed` | 1,162 | 636 | 34,974,843 | `91971f2505e3511263feee52fcdfe70b6fd29ef989351ce6926f819c7fff2328` |
| `e1e2fda4910d876588adb9badcb1c0d06c109ccd` | 1,288 | 714 | 35,742,217 | `f1e2db03cee2175bba53fb520eca844b63b7938bb919c863f9e8b862f47f4003` |
| `62524106cb363c51a1018f474693f46842eb6f32` | 1,293 | 718 | 35,773,059 | `23143e1325f6b86588ee9a03e8b9a6df8342d16ac78ff701c36d9f8eeffa28ce` |
| `4ae2914d6c3e07def37316a3a7f1e61ed86028cb` | 1,295 | 720 | 35,783,417 | `68187a1462190d5095bd547172668305b2f6965af2fc0dd6ecf0b0f7f3d53222` |
| `143725d9df7bd726d6bdd598466576b8bc7423a4` | 1,301 | 725 | 35,897,087 | `8a790a9158ff83890606c8317aac1728a4ff604c55a3a9a88b7cd8c00a0b280f` |
| `762ae9ac8c735cdf8747b7dd73824bb50c1514b4` | 1,303 | 726 | 35,905,702 | `19e3a45a6d55e9bfc591dbbd3bfd4dfa2cc1be40e47c4936bb37ed731b5add01` |
| `fdd17be9d3c9a7b0a98068a72b44bb2b10eb253e` | 1,305 | 727 | 35,919,134 | `60c9c9cbfb5d86d7acded963a8b81d4ce1ed4915ba6dec6bcbdf70aa08e4e012` |
| `2092095126ca6f3243b99b9d8b34c4661f5d6934` | 1,308 | 729 | 35,931,304 | `2a3a789e1567bf1a92ff1c0e9fbbd7de458716b0588724ee31dbc467afcb9398` |
| `5caa58d43a452714f044c081e00ec69388894c08` | 1,374 | 745 | 36,047,656 | `fd96e0ed20776a936b156be09f7a0ea6b058703e554f3d1ebbfa35334b2962eb` |
| `e143ade8507a45a1f125de7bc15b92541036ef85` | 1,384 | 747 | 36,055,705 | `074fa8d0cdb5c0dddd7d5fcb0c5945998d8ff400c67f56d7ca8da270fce24672` |

The historical frozen-to-`879fbce` comparison contains 204 tracked-file changes
and 59 selected-input changes. Those historical counts remain valid for that
pair and do not describe the current development source. The preceding
frozen-to-`d85aff12` pair contains 270 tracked-file changes and 87 selected-input
changes; its full pipeline observation remains separately pinned.
The frozen-to-`b6358c1` pair has 273 tracked-file changes and the same 87
selected-input changes; those earlier counts also remain specific to that pair.
The frozen-to-`bc0be26` pair retains its 277 tracked-file changes and the same
87 selected-input changes.
The frozen-to-`8767708` pair retains its 281 tracked-file changes and 87
selected-input changes. Those preceding counts and fingerprint remain specific
to that historical pair. The frozen-to-`1b8a33f` pair retains its 291
tracked-file changes and 88 selected-input changes.

For the root-module table and current counts, include an existing path only if
it is a root-module
`.go` file or a root module file in at least one compared revision. Determine
module ownership separately in each revision: exclude a Go file beneath a
directory containing that revision's nested `go.mod`. Test existence before
module ownership; a new nested module must not turn its new files into apparent
root-module additions in the other revision. There are six nested modules in
the frozen source and seven at both `5caa58d` and `e143ade`. The
`tools/ledger-export` module's ten Go files are outside the root-module table.

## CI infrastructure outside the Go input selector

The first four paths below changed between `d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff`
and the work-selection baseline `b6358c1943a0c2fbce5046c201f7d2e319b3089f`. They change no
root or nested Go/module/JSON input. The 634 selected Git blobs and their framed
input digest are unchanged; this source equality transfers no runtime execution,
CI run or review to a new revision. These Python/workflow inputs need their own
source inspection and actual control results.

| Path | Preceding blob | Selected blob | Review impact |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | `d2ccc9d73e4873c5310f34c4954d7815245ee605` | `f66609e77ac4cb1eba9ea2de4e4de7f107520803` | Adds the scope decision and small control reports while preserving the pre-existing runtime steps, commands, ordering and budgets. |
| `tools/check-ci-change-scope.py` | — | `839d77f8e6dd76760bd325a9f587cc48d0c4d4a5` | Binds selected parents and source bytes, observes a bounded raw Git diff and requires runtime work for code, modes, incomplete observations and empty diffs. |
| `tools/check-ci-change-scope_test.py` | — | `c3ac70887351b9aa102c6da5d0c451e64c172a64` | Exercises 36 controls, actual short owned processes and the workflow output guard; emits bounded source-bound control reports. |
| `docs/ci-change-scope.md` | — | `37272dc973321326873e813dcf86e85d8254acda` | Defines work-selection and skipped-job limits without claiming fresh runtime qualification for documentation. |

The following additional paths are selected at the preceding retention baseline
`bc0be26d76dd07d297dfdf5b00768d23527e49f5`. The preceding column is `b6358c1`;
the original scope helper and its 36 controls remain byte-identical. The three
new Python files are outside the Go input selector and require the separately
checked retention artifacts, not a transferred Go fingerprint.

| Path | Preceding blob | Selected blob | Review impact |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | `f66609e77ac4cb1eba9ea2de4e4de7f107520803` | `4678eb24ba4d1185b1ffbf9e4c303a5b9df04fb8` | Selects all original retention controls through an explicit leaf scope, adds its controls and three small result reports per platform; all other 29 recorded commands and native steps remain unchanged. |
| `tools/conformance_leaf_reuse.py` | — | `d8efa3c52a3ab481e6e1944ed6841e635028c0a4` | Reuses complete depth/path/value leaf commitments within a bounded serial scope while rebuilding node/edge maps and preserving original fallback behavior. |
| `tools/conformance_leaf_reuse_test.py` | — | `b6d81438b1c9612af84f2b4ec248ad8687f99a46` | Compares complete graph bytes, order, limits, independent results, errors, dependency/thread refusal and cleanup in 17 controls. |
| `tools/gen-state-root-vectors/run_retention_leaves.py` | — | `6b01cac08dc722f4538ea5ac658067f4fd72ec89` | Runs the complete pinned checker or its 24-root suite, binds the explicit scope and refuses a success record after a failed graph call. |
| `docs/retention-leaf-reuse.md` | — | `ea8be90804476539d503f903a9c5d9ef0e2a6d3c` | Separates finite oracle cost observations, logical cache payload, process RSS and the outstanding node/acceptance gates. |

The following import-resource paths are selected at qualified `8767708`. The
preceding column is `bc0be26`; these changes do not alter the 634 Go/module/JSON
inputs. Their actual platform reports are included in the 37-archive gate above.

| Path | Preceding blob | Selected blob | Review impact |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | `4678eb24ba4d1185b1ffbf9e4c303a5b9df04fb8` | `605ca54cb057203795d14c81444331371f4a2a0d` | Selects explicit import-resource child recipes and their controls and platform reports, preserving the native stages. |
| `tools/gen-state-root-vectors/import_resource_child_hex.py` | — | `6f58812273cc3b288a28be944d680d4bfc97329b` | Binds two fresh CLI slots to the existing source, exit and complete-console recipes with original fallback and restored local dispatch. |
| `tools/gen-state-root-vectors/import_resource_child_hex_test.py` | — | `7823cb1b61721eb7631caaf8d944b2b0f55b53dd` | Retains 19 controls for the selected source and child execution boundaries. |
| `tools/gen-state-root-vectors/run_import_resource_controls.py` | — | `b368eb3d774f85c2d6decccb565b42f566a2f0d4` | Runs either unchanged original suite and requires every original control and selected call in its complete report. |
| `docs/import-resource-child-hex.md` | — | `b166aaf78db6c67f139a3b438b653b0ffef4492f` | Separates finite checker-cost observations from node execution, representative R1 data and state-value acceptance. |

The following source-fixture and transport paths are selected at qualified
`1b8a33f`. The preceding column is `8767708`; the additional Go test change is in
the root-module table. These Python/workflow inputs are outside the selected
Go/module/JSON digest and require their own exact-source checks. The complete
17-path change from that preceding baseline also includes seven documentation
paths. Earlier local size observations keep their original source and scope.

| Path | Preceding blob | Selected blob | Review impact |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | `605ca54cb057203795d14c81444331371f4a2a0d` | `098e0450c7942d6f981747bc9cfa0c94325016e5` | Schedules stream/readback controls, canonical stream preparation and the single stored-member upload, with the existing native checks explicit. |
| `tools/candidate_stream.py` | — | `48143f9cd8441564df4416efa9ada441260777a5` | Defines bounded canonical TAR/XZ encoding and complete decoding within the existing payload limits. |
| `tools/candidate_stream_test.py` | — | `6003abccd9e2ec0b536282db8ff799a28c902090` | Checks complete and partial frames, bounds, metadata, and writer/decoder failure behavior. |
| `tools/check-candidate-archive.py` | `b213d1b0a0652d544916bb77e223683e108fbc3d` | `b2e5cd02c115ee8ad95bf7db0e20dce5275f92e6` | Accepts the checked stream envelope while retaining legacy ZIP support, archive digest and selected payload requirements. |
| `tools/check-scenario-inventory.py` | `a733a80eafa0ca351a5cf810aece6f9fea498edf` | `c920aa6232338496077668a578be425cf9f3dfaf` | Updates the archive-helper byte pin; a matching Go fingerprint does not replace the dependency check. |
| `tools/check-scenario-inventory_test.py` | `b920c5017c2988d8de997ef1a930d5c14f8b00c3` | `618bab811dc4f5d613bf8de79b7c3a769c7482c1` | Refuses same-size and length-changing pinned-helper changes before import. |
| `tools/check-source-candidate-stream.py` | — | `8eb1c6ec87afe46db881dcf189b837bb6d5d819c` | Binds readback to the selected checkout, full decode and separate unchanged path/descriptor snapshots. |
| `tools/check-source-candidate-stream_test.py` | — | `212ba3d54ff0a103f2cbaaaa05f4a77ef7f90990` | Checks source/delivery refusal, cross-API timestamps, pre-hash identity/type/size changes and all per-API metadata fields. |
| `tools/pack-candidate-stream.py` | — | `332b52a7cfbb2438e873de6c2f36667f80b4deb7` | Checks the exported directory and selected source before completing the stream. |

A later documentation-only workflow can deliberately produce no new native
executable. Inspect the actual selection and skipped job/step records and keep
the latest runtime-qualified revision explicit. A successful documentation
workflow does not update that runtime qualification.

## Acceptance boundaries

The development source extends the [candidate-v3 codec](candidate-v3-header-codec.md),
[sparse-proof primitive](candidate-smt-proof.md),
[owned-state save path](owned-state-persistence.md) and
[observer contract](block-observer.md) with the separately configured
[experimental typed-query path](experimental-batch-context-query.md).
Production state-value acceptance remains refused; synthetic/recorded fixture
results do not close the selected-network query or activation gates.
The [source scenario companion](scenario-inventory.md)
checks source/report correspondence; it does not transfer independent review
between revisions.

Before changing the selected review revision, reconcile the new source, actual
checkout, build metadata, binaries, reports, scenarios, skips and findings
disposition. Obtain independent human acceptance and authenticated distribution
separately. Keep the frozen packet, old-to-new identity mapping and historical
observations unchanged.
