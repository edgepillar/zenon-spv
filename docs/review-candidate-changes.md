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

The latest qualified development baseline selected by this ledger is
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

In this ledger, "current" means the explicitly selected qualified `8767708`
baseline. Later [candidate-stream preparation](candidate-stream.md) has separate
source and qualification limits; its local observations do not advance this
baseline. The frozen human-review candidate and its original packet remain fixed.

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
[normalized ancestry comparison](https://github.com/edgepillar/zenon-spv/compare/710627ae9589beca4a23400cc47fb038eb5495fd...87677080c335444fb047c54c1b8d683cee436726)
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
git diff --name-status 6ecc2310538d511e3b26bea4c658082853266a11 87677080c335444fb047c54c1b8d683cee436726
git diff 6ecc2310538d511e3b26bea4c658082853266a11 87677080c335444fb047c54c1b8d683cee436726 -- internal tools/observe-block go.mod go.sum
```

The second command includes other material in those directories. The table's
root-module filter is defined below; the complete repository diff remains
necessary for research, corpus, workflow and script changes.

## Recomputable input fingerprints

The complete frozen-to-current tracked-file delta contains 281 paths. The input
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
| `b6358c1943a0c2fbce5046c201f7d2e319b3089f` | 1,144 | 634 | 34,948,025 | `46367e744b6c687ca3ebe3558df3d745963a322efb32fcbd651bad2098497da9` |
| `bc0be26d76dd07d297dfdf5b00768d23527e49f5` | 1,148 | 634 | 34,948,025 | `46367e744b6c687ca3ebe3558df3d745963a322efb32fcbd651bad2098497da9` |
| `87677080c335444fb047c54c1b8d683cee436726` | 1,152 | 634 | 34,948,025 | `46367e744b6c687ca3ebe3558df3d745963a322efb32fcbd651bad2098497da9` |

The historical frozen-to-`879fbce` comparison contains 204 tracked-file changes
and 59 selected-input changes. Those historical counts remain valid for that
pair and do not describe the current development source. The preceding
frozen-to-`d85aff12` pair contains 270 tracked-file changes and 87 selected-input
changes; its full pipeline observation remains separately pinned.
The frozen-to-`b6358c1` pair has 273 tracked-file changes and the same 87
selected-input changes; those earlier counts also remain specific to that pair.
The frozen-to-`bc0be26` pair retains its 277 tracked-file changes and the same
87 selected-input changes.

For the root-module table, include an existing path only if it is a root-module
`.go` file or a root module file in at least one compared revision. Determine
module ownership separately in each revision: exclude a Go file beneath a
directory containing that revision's nested `go.mod`. Test existence before
module ownership; a new nested module must not turn its new files into apparent
root-module additions in the other revision. There are six nested modules in
the frozen and historical revisions, and seven in the current source. The new
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

A later documentation-only workflow can deliberately produce no new native
executable. Inspect the actual selection and skipped job/step records and keep
the latest runtime-qualified revision explicit. A successful documentation
workflow does not update that runtime qualification.

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
