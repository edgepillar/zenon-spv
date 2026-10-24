# Frozen review candidate and qualified baseline

The selected human-review candidate remains
[`6ecc2310538d511e3b26bea4c658082853266a11`](https://github.com/edgepillar/zenon-spv/tree/6ecc2310538d511e3b26bea4c658082853266a11).
Its selected [CI run](https://github.com/edgepillar/zenon-spv/actions/runs/39066131743)
and unsigned handoff have their own scope: 892 tracked files, 555 selected
Go/module/JSON inputs, 48 evidence families, nine archives, 21 ordinary
executables and 59 scenarios per platform. Five Windows skips remain explicit;
Linux and macOS have zero. This is mechanical qualification, not independent
human acceptance or authenticated distribution.

The separately qualified development baseline is
[`879fbce33dd77f483f7aba18994fb037f248e842`](https://github.com/edgepillar/zenon-spv/tree/879fbce33dd77f483f7aba18994fb037f248e842),
tree `a8eb348464eb76eae080d3966ded6592ef078f9f`. Its
[main CI run](https://github.com/edgepillar/zenon-spv/actions/runs/40066341088)
and retained reconciliation cover 71 evidence families, nine archives, 21
ordinary executables and the same 59 scenarios per platform, with the platform
skip limits retained. The new source-scenario companion checks source/report
correspondence; it does not transfer a review of the frozen candidate to this
different source.

## Complete root-module Go and module-file delta

The exact two-revision diff contains nine root-module Go files: five
application/primitive files and four test files. Root `go.mod` and `go.sum` are
unchanged. The table excludes nested research modules, corpus JSON, scripts,
workflow and documentation changes; it is not the complete repository diff.
Git blob identifiers below refer to file bytes, not commits or SHA-256 digests.
An em dash means the path was absent in the frozen revision.

| Path | Frozen blob | Baseline blob | Review impact |
| --- | --- | --- | --- |
| `internal/chain/candidate_v3.go` | — | `244d4f10a866f4e816e6cbd4126d7376649e4890` | Adds bounded, untrusted candidate-v3 decoding and projected hashing; it does not enable v3 admission. |
| `internal/chain/candidate_v3_test.go` | — | `61775c37e2c16829cee852bcc53857c7c72332ee` | Exercises candidate codec bounds and recorded byte comparisons. |
| `internal/conformance/cli_observer_signal_test.go` | — | `f2dbd90b0c20e10ede2d444d86d6ae8774978a9c` | Adds controlled ordinary-observer interruption/termination checks and explicit Windows limits. |
| `internal/proof/candidate_smt.go` | — | `1c2bda904dc296e4e2e0413be5a24abf94339967` | Adds bounded sparse-proof reconstruction and locally derived balance keys; the supplied root remains unauthenticated. |
| `internal/proof/candidate_smt_test.go` | — | `06df103a34f30611057d800af9e7346c0d9efc6d` | Compares proof outcomes and exercises encoding/domain limits. |
| `internal/verify/owned_state_save_test.go` | — | `65c1897a318bcdc3a981527fb18d8f76b05d9d06` | Checks owned-state persistence, mutable-state rejection and source-bound cost observations. |
| `internal/verify/state_file.go` | `9d9a84d53d9a7114fd048b8fc5bb12bf8d58533a` | `13d6dcc859717ffd0c778770cb6872051bcbd4f4` | Splits validated-state writing from public mutable-state validation while retaining the bounded atomic writer. |
| `internal/verify/verified_state.go` | `8abedce5daa5370f39b3f907f3c3e8fec47111d5` | `d46adcd549fced047fabd27fefff61416cdb1601` | Saves privately owned validated immutable state without repeating window cryptography. |
| `tools/observe-block/main.go` | `e3bee10f7c9cf7c69df8c08af7324fe911bb4eb0` | `4b41f17109e8c1416a0720ba1997dc1cb8377421` | Adds SIGTERM to the existing signal-cancellation context. |

Review the complete pair with:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 879fbce33dd77f483f7aba18994fb037f248e842
git diff 6ecc2310538d511e3b26bea4c658082853266a11 879fbce33dd77f483f7aba18994fb037f248e842 -- internal/chain/candidate_v3.go internal/chain/candidate_v3_test.go internal/conformance/cli_observer_signal_test.go internal/proof/candidate_smt.go internal/proof/candidate_smt_test.go internal/verify/owned_state_save_test.go internal/verify/state_file.go internal/verify/verified_state.go tools/observe-block/main.go go.mod go.sum
```

The [repository comparison](https://github.com/edgepillar/zenon-spv/compare/6ecc2310538d511e3b26bea4c658082853266a11...879fbce33dd77f483f7aba18994fb037f248e842)
also exposes changes outside this root-module table. Select a deliberate review
scope for those research, corpus, workflow and script changes rather than
describing every later change as documentation.

## Recomputable input fingerprints

The complete tracked-file delta contains 204 paths. The input selector below
changes at 59 paths. Neither number is the nine-file root-module delta, and the
selected-input counts do not cover every executable script or workflow.

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

For the nine-file table, select root-module `.go` files and the root module
files, excluding every nested directory containing its own `go.mod`. There
are six such nested modules at the baseline. The complete repository comparison
remains necessary for material outside either selector.

The baseline reuses the [candidate-v3 codec](candidate-v3-header-codec.md),
[sparse-proof primitive](candidate-smt-proof.md),
[owned-state save path](owned-state-persistence.md) and
[observer contract](block-observer.md). Runtime v3/state-value acceptance
remains refused. Before changing the selected review revision, reconcile the
new source, actual checkout, build metadata, binaries, reports, scenarios,
skips and findings disposition. Obtain independent human acceptance and
authenticated distribution separately. Keep the frozen packet and historical
observations unchanged.
