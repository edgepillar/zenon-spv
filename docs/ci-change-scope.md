# Documentation changes and CI scope

The general workflow first selects the exact Git change scope with
`tools/check-ci-change-scope.py`. A nonempty diff containing only regular
`README.md` or Markdown files below `docs/` can skip the three native and three
recorded-oracle jobs. The small scope job still runs its controls and retains a
source-bound selection report. Other workflows retain their existing triggers.
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
paths, non-Markdown files and all changes to code or workflows require the full
runtime jobs. Reserved Windows names, trailing-dot components and case aliases
also require runtime CI. Empty diffs require runtime CI, including identity-only
history recreations. A rename is considered its actual deletion/addition pair;
both paths must qualify.

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
qualification. The later runtime-qualified baseline is explicitly pinned to
`bc0be26d76dd07d297dfdf5b00768d23527e49f5` in the
[review ledger](review-candidate-changes.md); documentation heads do not advance it.
