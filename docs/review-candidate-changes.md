# Frozen review candidate and development baselines

The selected human-review candidate remains
[`6ecc2310538d511e3b26bea4c658082853266a11`](https://github.com/edgepillar/zenon-spv/tree/6ecc2310538d511e3b26bea4c658082853266a11).
Its selected [CI run](https://github.com/edgepillar/zenon-spv/actions/runs/39066131743)
and unsigned handoff have their own scope: 892 tracked files, 555 selected
Go/module/JSON inputs, 48 evidence families, nine archives, 21 ordinary
executables and 59 scenarios per platform. Five Windows skips remain explicit;
Linux and macOS have zero. This is mechanical qualification, not independent
human acceptance or authenticated distribution.

The historical qualified development baseline is
[`879fbce33dd77f483f7aba18994fb037f248e842`](https://github.com/edgepillar/zenon-spv/tree/879fbce33dd77f483f7aba18994fb037f248e842),
tree `a8eb348464eb76eae080d3966ded6592ef078f9f`. Its
[main CI run](https://github.com/edgepillar/zenon-spv/actions/runs/40066341088)
and retained reconciliation cover 71 evidence families, nine archives, 21
ordinary executables and the same 59 scenarios per platform, with the platform
skip limits retained. The
[historical nine-file root-module ledger](https://github.com/edgepillar/zenon-spv/blob/d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff/docs/review-candidate-changes.md)
and original reports remain pinned to their original revisions.

The current separately qualified development baseline is
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
used as this revision's CI proof. The table below describes its source delta
without selecting it as a replacement for the frozen review candidate.

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
[normalized ancestry comparison](https://github.com/edgepillar/zenon-spv/compare/710627ae9589beca4a23400cc47fb038eb5495fd...d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff)
is useful for navigation with the tree-equivalence limit above.

## Complete current root-module Go and module-file delta

The exact frozen-to-current diff contains 14 root-module Go files: six
application/primitive files and eight test files. Root `go.mod` and `go.sum`
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

The historical nine-file table stopped at `879fbce33dd77f483f7aba18994fb037f248e842`.
Since that baseline, five additional root-module paths changed, and
`tools/observe-block/main.go` changed again. All six paths are included above;
the total current delta is 14 distinct paths.

Review the complete pair with:

```sh
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff
git diff 6ecc2310538d511e3b26bea4c658082853266a11 d85aff12dd0de8b2d1bd8db46e0e4e727c7e60ff -- internal tools/observe-block go.mod go.sum
```

The second command includes other material in those directories. The table's
root-module filter is defined below; the complete repository diff remains
necessary for research, corpus, workflow and script changes.

## Recomputable input fingerprints

The complete frozen-to-current tracked-file delta contains 270 paths. The input
selector below changes at 87 paths. Neither number is the 14-file root-module
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

The historical frozen-to-`879fbce` comparison contains 204 tracked-file changes
and 59 selected-input changes. Those historical counts remain valid for that
pair and do not describe the current development source.

For the root-module table, include an existing path only if it is a root-module
`.go` file or a root module file in at least one compared revision. Determine
module ownership separately in each revision: exclude a Go file beneath a
directory containing that revision's nested `go.mod`. Test existence before
module ownership; a new nested module must not turn its new files into apparent
root-module additions in the other revision. There are six nested modules in
the frozen and historical revisions, and seven in the current source. The new
`tools/ledger-export` module's ten Go files are outside the root-module table.

## Acceptance boundaries

The development source extends the [candidate-v3 codec](candidate-v3-header-codec.md),
[sparse-proof primitive](candidate-smt-proof.md),
[owned-state save path](owned-state-persistence.md) and
[observer contract](block-observer.md). Runtime v3/state-value acceptance
remains refused. The [source scenario companion](scenario-inventory.md)
checks source/report correspondence; it does not transfer independent review
between revisions.

Before changing the selected review revision, reconcile the new source, actual
checkout, build metadata, binaries, reports, scenarios, skips and findings
disposition. Obtain independent human acceptance and authenticated distribution
separately. Keep the frozen packet, old-to-new identity mapping and historical
observations unchanged.
