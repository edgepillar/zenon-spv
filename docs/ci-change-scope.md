# Documentation, portable leaves and native CI scope

The general workflow first selects the exact Git change scope with
`tools/check-ci-change-scope.py`. A nonempty diff containing only regular
`README.md` or Markdown files below `docs/` can skip the three native and three
recorded-oracle jobs. The small scope job still runs its controls and retains a
source-bound selection report. Other workflows retain their existing triggers.
The portable route selects the required three-platform workflows for a fixed set
of archive, export, inventory and devnet preparation files.
The native-v3 route below keeps all native jobs and selects only the unchanged
recorded-oracle job out of the execution plan.
Full-runtime jobs also retain small source-bound scope-control reports on all
three native platforms. These avoid downloading complete job logs just to
reconcile the new controls' actual test names and outcomes.

This is a work selection, not runtime qualification of the new revision. A
documentation-only successful workflow has no new native tests, binaries or
oracle completion. Keep the last runtime-qualified revision and its evidence
pinned when publishing documentation. The frozen human-review candidate also
keeps its original revision, CI and review scope.

## Conservative decisions

The selector checks the actual checkout, selected event and direct parent
identities. For a pull request, both selected base and feature must match the
test merge's ordered parents. A main push must name the preceding main commit
as a direct parent and use the actual checkout as its feature. Checkout depth
two normally supplies these objects; missing history requires runtime CI.

It reads an explicit two-tree raw diff with NUL framing, rename detection,
external diff and text conversion disabled. Only added, modified or deleted
mode-100644 Markdown files with ordinary ASCII path components are eligible.
Executable modes, links, Git submodules, type changes, unknown records, duplicate
paths and code outside the reviewed file sets require the full runtime jobs.
All workflow or selector/control changes require that full lane. Reserved
Windows names, trailing-dot components and case aliases
also require runtime CI. Empty diffs require runtime CI, including identity-only
history recreations. A rename is considered its actual deletion/addition pair;
both paths must qualify.

The native-v3 route does not change these native-runtime requirements. It has a
separate, conservative output for selecting recorded-oracle work.

The executing helper, controls and workflow must match the selected Git blobs,
allowing only recorded LF-to-CRLF checkout conversion. Git replacement objects
and optional locks are disabled for these reads. Output and source reads have
explicit caps; each Git process has a ten-second deadline. Reports retain the
actual exit, bounded captured prefixes' hashes, observed byte counts, EOF,
truncation, timeout and join observations. Diagnostics are hashed instead of
copied into public reports. Incomplete or failed observations select runtime
CI and retain their failure facts.

If the scope job fails, emits an unknown output or never selects a scope, the
runtime jobs are still required unless the workflow is cancelled. The workflow
publishes `run_runtime=false` only after a complete successful helper command and
strict report validation. Failed scope controls keep the overall workflow
failed even when the runtime jobs subsequently succeed.

The explicit [status check](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions)
preserves failure fallback while respecting workflow cancellation. A skipped
job's reported success does not mean its tests ran; inspect its actual job and
step records before describing qualification.

## Runtime evidence uploads

An individual artifact upload failure leaves subsequent independent checks and
uploads enabled in the native and recorded-oracle jobs. After a failed
upload, the same job waits ten seconds and makes one more upload from the
existing files. Both attempts use the same artifact name without overwrite.
The retry requires files and a completed upload receipt. An unresolved
failure still fails the job at its final upload check. A cancelled job
does not retry. Keep the original error and completed artifact IDs for
the specific run and attempt. The scope job keeps its full-runtime fallback.

If the service created the original artifact but did not acknowledge it,
the retry may report an artifact name conflict. The original is kept and
the job still reports the unresolved upload. A retry resends the artifact
within the job without rerunning any test or build.

On main at `d72d14fb0d4f3aa0bbad229ffe17fd5e31956c1c`, two macOS artifact
creation calls reported `ENOTFOUND` and six expected archives were missing.
The macOS root suite had completed before the upload failures. This is an
observed CI transport failure, separate from the subsequent unexecuted checks.
[Original main attempt](https://github.com/edgepillar/zenon-spv/actions/runs/44779488024/attempts/1)

On PR #428 at `fa2ffe0abd90e5ee7ee71cb6ce68029e59f3acd8`, the macOS
core Init and Stop archive was missing after the same DNS error. The
job continued through the remaining checks and was marked failed at the
upload gate. [Original PR attempt](https://github.com/edgepillar/zenon-spv/actions/runs/44852618386/attempts/1)

## Portable tool changes

The `PORTABLE_WORKFLOWS_ONLY` route selects the union of the three-platform
workflows required by modifications to the following existing mode-100644
files. Regular Markdown may accompany the changes.

| Directory | Reviewed files | Required workflow |
| --- | --- | --- |
| `tools/ledger-transport` | `archive_index.py`, `archive_index_test.py`, `archive_tail.py`, `archive_tail_test.py`, `transport_test.py`, `README.md`, `THIRD_PARTY_NOTICES` | `ledger-transport.yml` |
| `tools/ledger-transport` | `transport.py` | `ledger-transport.yml`, `ledger-export.yml` and `ledger-inventory.yml` |
| `tools/ledger-export` | `inventory_completed_export.py`, `inventory_completed_export_test.py`, `README.md` | `ledger-export.yml` |
| `tools/ledger-export` | `snapshot_projection.py` | `ledger-export.yml` and `ledger-inventory.yml` |
| `tools/ledger-inventory` | `churn.py`, `inventory_test.py`, `README.md` | `ledger-inventory.yml` |
| `tools/owned-devnet-query` | `engine_test.py`, `images_test.py`, `inputs.py`, `inputs_test.py`, `capture_test.py`, `review.py`, `review_test.py`, `README.md` | `owned-devnet-query.yml` |
| `tools/owned-devnet-query` | `engine.py`, `node_diagnostics.py`, `node_diagnostics_test.py`, `node_file_logs.py`, `node_file_logs_test.py` | `owned-devnet-query.yml` |
| `tools/gen-state-root-vectors` | `first-insertion-catchup_test.go.txt`, `first-insertion-cpu_test.go.txt`, `first-insertion-export_test.go.txt`, `qualify_first_insertion.py`, `qualify_first_insertion_test.py` | `first-insertion-catchup.yml` |

The compiled export controls and manifest-backed inventory replay also consume
`transport.py`. Inventory replay loads the shared snapshot projector. The core
`inventory.py` stays in the full-runtime closure because the exporter and
transport also consume it.
`ledger-inventory.yml` runs the existing Python controls on Linux, macOS and
Windows. Each platform uploads one report with actual test names, the exact
checkout, source tree, source byte digests and workflow attempt.
`docs/state-root-r1-intake.md` adds `ledger-transport.yml` when part of a portable
diff. `docs/first-insertion-catchup.md` adds `first-insertion-catchup.yml` in the
same way. The general `docs/native-roadmap.md` is an evidence metadata input, not a
transport execution dependency: its changes alone do not trigger that workflow
or add it to the portable workflow union. Transport code, the intake contract,
the inventory dependency, the transport workflow and license changes retain
their dedicated triggers. When transport work does run, its evidence still pins
the roadmap bytes at that exact checkout. The preparation workflow
runs its portable controls on these events. The separate manual fixture
experiment has its own dispatch and evidence requirements.

A pull request must have the selected base as the feature commit's sole parent
and identical feature and test-merge trees. A push must name its first parent
as the preceding main head. This binds the selected diff to the GitHub event
that triggers the required workflows. The 256-record limit includes Markdown.
Additions or deletions of the listed tool files, mode changes, a native change
in the same diff, and unknown or incomplete observations select the full lane.

The selector binds the exact workflow bytes in the selected base, checkout and
working file for each required workflow. One SHA-256 covers the remaining
non-document Git tree, including the general and dedicated workflows, the
dispatch controller, query profile, test driver, and all other dependencies.
It excludes only regular Markdown, the reviewed files in the table, and the
selector/control pair. An already integrated change to a reviewed file in one
group leaves the closure stable for an eligible change in another group.
The closure hashes the sorted raw `git ls-tree -r -z --full-tree` records with
their trailing NULs. The tree is capped at 2 MiB and 8,192 records.

Any new dependency across these workflows requires reviewing the path triggers,
workflow mapping and closure in full CI. Changes outside the reviewed set
invalidate the pin. Updating the policy itself selects full CI. The historical
archive, preparation and R1 routes keep their original v2, v4 and v5 reports.

The v6 report includes the event tree, selected paths, exact workflow union,
source and closure pins, and the complete Git command receipts. Before accepting
an eligible PR or main push, verify each required workflow's actual Linux,
macOS and Windows job and exact-source artifacts. Skipped general jobs produce
no native binary or oracle evidence. Keep their latest separately qualified
source revisions explicit.

### Portable closure refresh

The portable dependency tree at `f2d26c950b99a206c66eaf76a15577a997cbd6cc`
contains 1,204 records and 123,386 bytes. Its SHA-256 is
`7ba366cf846f7b08c96dd176421acee045d92e53e378176cf114361d6ecd6bda`.
Thirty dependency records changed since the previous pin, covering native
verification and tests, paired recorded-oracle jobs, and owned fixture evidence.
All four dedicated workflow byte pins match this tree. The selector update
requires full CI. An eligible reader edit still needs its three-platform
preparation run and exact-source artifacts.

The closed-opening diagnostic updates four records in the portable
dependency tree. The resulting tree at `4e0bd84583f69a9bbc11c9c0c73a5409dff888ac`
contains 1,204 records and 123,386 bytes with SHA-256
`0f591205a183a3decf1e4fb19fdcb950e6d80936a88f227311568bf96275dcae`.
The runner change selects full CI and includes the corresponding fingerprint
update for subsequent eligible edits.

### First-insertion catch-up controls

The five files are execution inputs to the dedicated workflow alone. It tests
the qualifier and runs the unsigned point-catch-up controls against the pinned
reference node on Linux, macOS and Windows. Its Linux job also compares CPU
limits. The pinned closure includes the shared `qualify_closed_parent_oracle.py`,
`.gitattributes`, and the workflow itself. A change to any of them selects the
full lane. The dedicated workflow's reports cover the runs and probes they record.

### Owned node diagnostic changes

The five additional files in the table implement the owned node engine and its
optional diagnostic readers, with their matching controls. Their callers are
the owned runner and retained-result reviewer. The general native and recorded
oracle entrypoints do not import them. The preparation workflow discovers all
owned `*_test.py` modules and pins every Python source before and after testing
on Linux, macOS and Windows. It keeps each platform's actual outcomes and skip
ledger; a successful selection report alone is insufficient.

This is an explicit existing-file set. The dispatch controller, command recorder,
RPC client, source intake, query checks, control driver and contract/profile JSON
remain outside it and inside the remaining-tree closure. Their changes, new
files, workflow changes, links, file-mode changes or mixed native changes require
the full runtime lane. Both the selector and executing workflow guard check the
same reviewed set and exact required preparation workflow.

The prior [diagnostic CI run](https://github.com/edgepillar/zenon-spv/actions/runs/43665684066)
at feature `73879611387ae4921de449a971e4b9321dd2f117` provides the cost motivation:
its seven general jobs used 6,140 summed runner-seconds and a 2,102-second
executed-job window, with 60,079,359 compressed artifact bytes. The macOS native
job took 2,089 seconds. These are that run's observations, excluding queue time;
they are not a controlled benchmark or a promise about a future selected route.
The policy change itself still requires full CI. A later eligible event needs
its own scope, skipped-job and three-platform preparation artifact qualification
before reporting measured savings.

No native executable or recorded-oracle completion is produced by skipped
general jobs. Keep their qualified revisions and original evidence explicit.
The manual fixture job is unchanged, does not run for an ordinary push or PR,
and still needs separate source-specific execution permission. This selection
does not satisfy an actual accepted-header/BatchEntry consumer gate, change
readiness or resource limits, or create network/state-value authority.

## Costs and verification limits

The selector writes only one small JSON report through the workflow's ordinary
temporary output redirection. It creates no Git checkout, database, large
fixture, archive or native binary. Bounded stream controls use short owned Python
processes. Local qualification uses the private task storage agreements.

The first helper/workflow change itself requires full runtime CI. The same
scope controls run in Linux, macOS Intel and Windows native jobs on that path.
A later real documentation-only PR and its main push must separately show the
scope decision, actual skipped job records and small artifact qualification
before claiming a measured reduction in native execution or archive transport.
No projected savings are representative node or consumer performance evidence.

### Planning-only transport trigger qualification

The trigger adjustment is qualified at
[`21a33fa66d52a26f16aad146f3277cf329bfed51`](https://github.com/edgepillar/zenon-spv/commit/21a33fa66d52a26f16aad146f3277cf329bfed51).
Its [PR general CI](https://github.com/edgepillar/zenon-spv/actions/runs/43491116602)
and [main general CI](https://github.com/edgepillar/zenon-spv/actions/runs/43499704633)
each passed all seven jobs, including the 64 scope controls on the native
platforms. Its [PR transport CI](https://github.com/edgepillar/zenon-spv/actions/runs/43491116626)
and [main transport CI](https://github.com/edgepillar/zenon-spv/actions/runs/43499705146)
each passed 81 controls on Linux, macOS Intel and Windows.

Reconciliation covers 43 archives and 21 native binary bindings per context:
44 primary archives in total, plus integrity/source readback of the remaining
42 supplemental archives. The new source revisions used their own runs;
unchanged native input bytes did not transfer earlier CI qualification.
The frozen human-review candidate and selected consumer pins remain separate.

This qualifies the policy implementation. A later planning-only update still
needs its actual source-bound scope report, provider job records and artifact
checks. A successful documentation-only run provides no new native binary or
selected-network consumer result.

### Earlier documentation route observations

The real [documentation PR #284](https://github.com/edgepillar/zenon-spv/pull/284)
and its actual main push now have separately reconciled scope decisions,
all six Git stdout hashes, provider-skipped job records and archive digests:

| Selected general run | Executed jobs | General archives | Archive bytes | Observed execution window, seconds |
| --- | ---: | ---: | ---: | ---: |
| [Full work-selection implementation](https://github.com/edgepillar/zenon-spv/actions/runs/40484050738) | 7 | 28 | 93,364,188 | 1,623 |
| [Documentation PR](https://github.com/edgepillar/zenon-spv/actions/runs/40489194703) | 1 | 1 | 2,834 | 12 |
| [Documentation main](https://github.com/edgepillar/zenon-spv/actions/runs/40491001414) | 1 | 1 | 2,801 | 9 |

The window spans the earliest started to latest completed executed job; it
excludes queue time. Each documentation run executed only Change scope and had
three provider-skipped group records with zero steps; these were not six expanded
matrix job executions. No native executable or Go/oracle job was produced by
that general workflow. The separately triggered transport workflow still ran on
all three platforms; all four actual archives per documentation context were
qualified. Their costs are outside this general-workflow table.

These are different observed work selections, not a controlled performance
benchmark, production resource budget or measured APFS reclaim. No protected
evidence was deleted. The documentation route itself confers no native runtime
qualification. That historical experiment kept
`bc0be26d76dd07d297dfdf5b00768d23527e49f5` as its then-qualified runtime baseline
in the [review ledger](review-candidate-changes.md). Its original records retain
that meaning.

The independent archive-route adoption is fully runtime-qualified at
[`722990a07f1523e792b917b83644bba40806aa6e`](https://github.com/edgepillar/zenon-spv/commit/722990a07f1523e792b917b83644bba40806aa6e),
through separate [PR CI](https://github.com/edgepillar/zenon-spv/actions/runs/41602430674)
and [main CI](https://github.com/edgepillar/zenon-spv/actions/runs/41606398665).
Each context passed all seven scheduled jobs, qualified all 37 archives and
21 native binary bindings, and reconciled four scope reports with 52 controls
each. These are mechanical source/runtime observations; independent review,
network activation and authenticated distribution remain separate gates.

Historical v2 route observations retain that source, run and attempt scope.
The three preparation jobs on PR #350's corrected revision used 59
runner-seconds and produced 6,264 archive bytes. That integration also ran
the full general workflow. [Preparation run](https://github.com/edgepillar/zenon-spv/actions/runs/42569815072)
and [general CI](https://github.com/edgepillar/zenon-spv/actions/runs/42569815071)
retain the original job and artifact records.

Measure v6 on an eligible PR and its main push after qualifying the policy.
The closure pin selects work. The actual runs establish cost and completion.

## Native v3 leaves and recorded oracles

`NATIVE_RUNTIME_ONLY` can select the three recorded-oracle jobs out only for
mode-100644 **modifications** to these ten existing files below
`internal/verify/`, optionally mixed with regular documentation changes:

- `experimental_v3_state.go`, `experimental_v3_profile.go`,
  `experimental_v3_file.go` and `experimental_v3_checkpoint.go`;
- their four matching `_test.go` files, plus `experimental_v3_workflow_test.go`
  and `experimental_v3_retention_test.go`.

This does not classify the whole Go directory. Added/deleted files, other Go
files, Python controls, JSON data, modules, workflows, modes and mixed portable
changes require both native and recorded-oracle jobs. The native jobs still run
the full root Go suite and their existing conformance, compiled consumer,
platform and artifact steps at the new source revision. The general workflow's
other triggers are unchanged.

The selected recorded-oracle job has 26 Python commands. Its source-bound
inventory includes the target-hex, complete-graph, child-resource and retention
wrappers. Those commands replay the research module's pinned original-node
bytes and synthetic recordings; they do not build or execute the ten native
v3 Go leaves. Research `go.mod`, Go harnesses and `.go.txt` files are distinct
inputs and remain inside the closure, along with all Python helpers and data.
Independent byte checks in the native job are not moved out or skipped.

The new `oracle_closure` SHA-256 covers every Git tree record except regular
documentation, these ten leaves and the selector/control pair. It includes the
general workflow, other workflows, all other native sources, research sources,
wrappers and fixtures. The same bounded tree framing, modes, duplicate checks
and deterministic NUL-terminated record encoding used by the portable route
apply. The full closure must match one of the reviewed snapshots below.
Every other digest selects the complete lane until its dependencies are
reviewed. The report records the exact matching digest.

An eligible report uses `zenon-ci-change-scope/v3`, seven complete Git command
receipts, the exact source pins, reviewed modified paths and closure facts. It
keeps `run_runtime=true` and selects `run_recorded_oracles=false`. Existing v1
and v2 report schemas retain their original meaning. The actual workflow output
guard validates the v3 decision before writing the separate literal output.
Unknown, failed, absent or incomplete scope observations keep both lanes
required; controls also exercise that guard and verify the native job conditions.

Skipping the recorded job supplies no new oracle execution or oracle artifact.
Retain the last source-pinned oracle completion separately and qualify every
new native source/run/platform artifact. The selector and workflow change
itself requires the full seven-job lane. A later actual eligible PR and main
push need separate reconciliation of source scope, skipped provider records,
native results and artifacts before claiming measured savings. Fewer selected
jobs are not a controlled wall-time benchmark, node resource measurement,
independent review or network/state-value acceptance.

### Closure refresh for the first-insertion and startup-diagnostic changes

The native closure advanced from `e9a047230298eb3e24579fd6162f413b7fc63c32`
to `ec2f07e4e5411cedfc74b9f77576b7f7550c00dd`. The 13 changed closure
records cover the dedicated first-insertion workflow and its five inputs,
the five owned devnet diagnostic files, the general scope validator's
first-insertion rules, and the line-ending attribute for the catch-up
document. The recorded-oracle job definition is byte-identical across
those revisions. The refreshed digest is
`4bac97b17356cfa3dfebe40e4598cc57c095c529ba7b140214a6b23795ee3745`
over 1,211 records and 123,968 bytes. These paths remain part of the closure.

[PR #420's general CI](https://github.com/edgepillar/zenon-spv/actions/runs/44684143424)
ran all three recorded-oracle jobs, using 2,096 runner-seconds, after its
v3 test-only change encountered the prior closure pin. The same Git tree
projects to the native-only route with the refreshed pin. The pin update
itself runs full CI. Future native-only events must establish their own
job selection and platform evidence before any measured savings are reported.

### Paired owned-input renewal

The explicit owned-input renewal request schedules the closed-parent workflow
at the same source as the existing general workflow. The request remains a
runtime dependency. It is outside both narrow change-scope file sets, so a
renewal runs the complete general lane and has its own original CI artifacts.

Relative to `ec2f07e4e5411cedfc74b9f77576b7f7550c00dd`, the two edited
workflow files, the renewal request and the two retention selector files
change five records in both closures. The portable closure contains 1,195
records and 122,422 bytes with digest
`dbbb683a47ad61c72568b1abca132c962ac6dc9e123e2b9a025b2489a9d8c77c`. The
recorded-oracle closure contains 1,214 records and 124,260 bytes with digest
`4b6971bfb7c952a22ac77cd98ce4959081a46581cb3248f65878717716e88b59`.
The reviewed leaf sets and the recorded-oracle job definition retain the same
coverage.

### Renewed owned BatchEntry selection

The reviewed source closure moves from `58e03fa9ff58a752cfd1718245b31cba73dde473` to the
reference-gas contract that selects the renewed main Linux pair and the
bounded runner that preserves nonaccepting query evidence. This change runs
the full general and owned-preparation workflows. The independent native and
portable selection rules retain the same coverage.

The portable closure contains 1,196 records and 122,538 bytes
with digest `631cad1d5bd788a1a1da5828ee38a77d10cf47c1f489c180baaeea5046d2df8f`.
The recorded-oracle closure contains 1,215 records and 124,376 bytes
with digest `17d736f154163aaa5d018e640c4773f6c51f58ba261ee32803757f814dba40f7`.

The 30-second timeout applies to two installed Go `test2json` helpers used by
the offline pilot's native tests. In the initial Windows CI run for this PR,
both controls failed near their prior 10-second limit (10.64 and 10.32
seconds). The original failed roots and timings remain in the first attempt's
[general CI record](https://github.com/edgepillar/zenon-spv/actions/runs/44769740235).

### Reviewed closure snapshots after recorded-workspace pairing

Both reviewed closures contain 1,223 records and 125,224 bytes. Their full
general runs passed on Linux, macOS and Windows. The workflow definition and
26-command recorded-oracle inventory match across the two trees. The second
tree differs in the two retained-state sequence test files, which stay inside
the closure. The existing ten eligible native-v3 files remain the only
non-document changes that can select this route.

| Qualified tree | Closure SHA-256 | Full general run |
| --- | --- | --- |
| `d55cd7cbe3dae4847e080605ee1f6bd797dac416` | `ebfdc9d14c44b16951cc43293ec8f3d3daa8e2eb02c52b46a58fe328ee53d5de` | [Main c64f545](https://github.com/edgepillar/zenon-spv/actions/runs/45911169119) |
| `0682518f0118899d14f153bfd7c802a780c8745a` | `fb04292d178e007ad5b24c9a4a76578bf1c54dc8f6e0f021f774b6c5dc45a3bb` | [PR #439](https://github.com/edgepillar/zenon-spv/actions/runs/45914619049) |

The 77 dependency record changes since the earlier first-insertion review
include paired workspace and driver controls, the upload failure gate, native
and fixture code, and workflow inputs. The two full runs cover the current
recorded-oracle definition. Its three jobs used 1,506 summed runner-seconds
and 38,262 archive bytes in the main run, and 1,254 runner-seconds and 38,338
archive bytes in the PR run. Those observations are from different runners.
This selector update runs full CI. An eligible hosted event must separately
establish its own skipped-job records, native results and artifacts.

### Combined review of checkpoint and interrupted-capture changes

The integrated review includes the archived fixture evidence, the interrupted
capture reviewer and the trusted snapshot checkpoint commands. The new
closure digests cover their combined Git tree. The reviewed leaf sets and
the four dedicated workflow byte pins keep their existing coverage.

| Closure | Entries | Encoded bytes | SHA-256 |
| --- | ---: | ---: | --- |
| Native v3 | 1223 | 125224 | `0d2f615725b34825e58852c6d3aed63857aedd5a58d1ab975f5af377ef888078` |
| Portable tools | 1203 | 123290 | `a28a7e18658e52304a10557d9136d445bb6c4a7f5ed1808d525abd6209debd0e` |

The combined review changes source and selection policy, so it requires full
general CI and the applicable dedicated workflows. Later reviewed-leaf
changes use the narrower routes only when their exact source and workflow
pins match. Live typed consumption and representative snapshot data have
separate acceptance requirements.

### Ledger inventory workflow installation

The scope update integrates the qualified projected replay and installs its
Python workflow. The policy installation takes the full general lane. A later
eligible replay-only change selects the inventory workflow. A projector
change selects inventory and exporter controls together.

| Closure | Entries | Encoded bytes | SHA-256 |
| --- | ---: | ---: | --- |
| Native v3 | 1224 | 125316 | `f99b68899409e1ff66fcd900eb7b8482742c75e74d298a498ba7821f098fca3d` |
| Portable tools | 1201 | 123117 | `683a7b0b329fd788f1e8b55dcbc4625203fc8f2b5b32859368c555b6b2cb8998` |

### Manifest-backed replay

Inventory replay shares the transport checker. Changes to that checker select
all three portable consumers. The dependency and workflow update takes the
full lane and records the updated closures.

| Closure | Entries | Encoded bytes | SHA-256 |
| --- | ---: | ---: | --- |
| Native v3 | 1224 | 125316 | `4a9f1a1917f1a4f3b609e855c6a65f011421da57624fb22bf429ab971ca5680f` |
| Portable tools | 1201 | 123117 | `cbe59d89d51b8c3e36554507d1f9c72c1f8031627c9e86a51bab3a3747f479b1` |

### Configured header comparison for replay

The native verifier and its packaged control consume the original
manifest-backed replay report. The decoder and its control remain in both
dependency closures. The change takes the full general lane.

| Closure | Entries | Encoded bytes | SHA-256 |
| --- | ---: | ---: | --- |
| Native v3 | 1225 | 125415 | `bb2e1d38bee607318fece2a61ec5fcf5d033ea2fea20ee0a9cdfb9d36b06fb71` |
| Portable tools | 1202 | 123216 | `987c68d3024ab3006f490c1c8139f567d58d5e99d2d6ac09ebfd65b189caadb5` |
