# Documentation, archive leaves and native CI scope

The general workflow first selects the exact Git change scope with
`tools/check-ci-change-scope.py`. A nonempty diff containing only regular
`README.md` or Markdown files below `docs/` can skip the three native and three
recorded-oracle jobs. The small scope job still runs its controls and retains a
source-bound selection report. Other workflows retain their existing triggers.
One additional, explicitly bounded route selects the independent archive tools
described below. It still requires their separate three-platform workflow.
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
paths and code outside the exact archive set require the full runtime jobs.
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

## Independent archive leaves

A diff can select `PORTABLE_ARCHIVE_ONLY` only for mode-100644 **modifications**
to the following existing files, optionally mixed with the regular documentation
changes above:

- `tools/ledger-transport/archive_index.py` and `archive_index_test.py`;
- `tools/ledger-transport/archive_tail.py` and `archive_tail_test.py`;
- that directory's `README.md` and `THIRD_PARTY_NOTICES`.

Additions, deletions, executable/link modes, aliases and any other code path keep
the full lane. The raw `transport.py`/`transport_test.py`, inventory and exporter
paths are excluded: the Go exporter's actual compiled-process controls consume
the raw stream tool. Directory-wide tooling classification would hide that
dependency.

The exact `ledger-transport.yml` Git bytes must match the selected checkout,
working file, selected base and the pinned, three-platform workflow. The selector
also reads a bounded complete `git ls-tree -r -z --full-tree` at the selected
checkout. A SHA-256 pins all remaining runtime dependency records, including
the general workflow. Only regular documentation, the six reviewed leaves and
the selector/control source pair are excluded. Sort the retained raw records
lexicographically and hash their concatenation, with each record's trailing NUL.
The tree observation is capped at 2 MiB / 8,192 entries; unknown or incomplete
observations require runtime CI.

This closure pin prevents a later Go, Python, workflow, data, mode or new-file
dependency change from silently inheriting the shortcut. Such a change disables
the archive route until a fresh dependency review explicitly updates the pin.
Updating the selector itself selects full runtime CI. The pin selects work; it
does not transfer runtime, release or protocol authority from another revision.

This route emits `zenon-ci-change-scope/v2`, nine complete Git command receipts,
the additional workflow source pin, closure facts and `required_workflows`.
Existing documentation and ordinary runtime decisions retain their v1 shape;
historical reports and their outcomes are unchanged. An unsuccessful v2
observation still selects the full lane and retains its refusal facts.

`required_workflows` declares work, not completion. Before accepting this scoped
delivery, reconcile the actual separate ledger-transport run, all three platform
jobs, its source/run/platform-bound archives and actual controls. The general
workflow alone cannot establish their success. Its skipped native/oracle groups
produce no new Go tests, binaries, native runtime qualification or review.
Keep the latest separately qualified native revision explicit.

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

Keep that full-runtime revision pinned when a later eligible archive change
selects v2. Its skipped groups supply no new native execution or binary, and its
separate portable workflow still needs actual three-platform qualification.
Record each real route observation against its own source, run and attempt;
the closure pin alone does not establish completion or savings.

## Native v3 leaves and recorded oracles

`NATIVE_RUNTIME_ONLY` can select the three recorded-oracle jobs out only for
mode-100644 **modifications** to these ten existing files below
`internal/verify/`, optionally mixed with regular documentation changes:

- `experimental_v3_state.go`, `experimental_v3_profile.go`,
  `experimental_v3_file.go` and `experimental_v3_checkpoint.go`;
- their four matching `_test.go` files, plus `experimental_v3_workflow_test.go`
  and `experimental_v3_retention_test.go`.

This does not classify the whole Go directory. Added/deleted files, other Go
files, Python controls, JSON data, modules, workflows, modes and mixed archive
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
and deterministic NUL-terminated record encoding used by the archive route
apply. A changed dependency, new file or unexpected mode changes the pin and
restores the complete lane until an explicit dependency review. The older
archive closure pin is preserved; this change does not silently refresh it.

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
