# Documentation, portable leaves and native CI scope

The general workflow first selects the exact Git change scope with
`tools/check-ci-change-scope.py`. A nonempty diff containing only regular
`README.md` or Markdown files below `docs/` can skip the three native and three
recorded-oracle jobs. The small scope job still runs its controls and retains a
source-bound selection report. Other workflows retain their existing triggers.
The portable route selects the required three-platform workflows for a fixed set
of archive, export and devnet preparation files.
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

## Portable tool changes

The `PORTABLE_WORKFLOWS_ONLY` route selects the union of the three-platform
workflows required by modifications to the following existing mode-100644
files. Regular Markdown may accompany the changes.

| Directory | Reviewed files | Required workflow |
| --- | --- | --- |
| `tools/ledger-transport` | `archive_index.py`, `archive_index_test.py`, `archive_tail.py`, `archive_tail_test.py`, `transport_test.py`, `README.md`, `THIRD_PARTY_NOTICES` | `ledger-transport.yml` |
| `tools/ledger-transport` | `transport.py` | `ledger-transport.yml` and `ledger-export.yml` |
| `tools/ledger-export` | `inventory_completed_export.py`, `inventory_completed_export_test.py`, `README.md` | `ledger-export.yml` |
| `tools/owned-devnet-query` | `engine_test.py`, `images_test.py`, `inputs.py`, `inputs_test.py`, `capture_test.py`, `review.py`, `review_test.py`, `README.md` | `owned-devnet-query.yml` |

The compiled export controls also consume `transport.py`.
`docs/state-root-r1-intake.md` adds `ledger-transport.yml` when part of a portable
diff. The general `docs/native-roadmap.md` is an evidence metadata input, not a
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

The selected recorded-oracle job has 33 Python commands. Its source-bound
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
apply. A changed dependency, new file or unexpected mode changes the pin and
restores the complete lane until an explicit dependency review. The v3 pin
remains at its separately reviewed dependency snapshot.

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
