# Reusing complete-suite source enumeration evidence

The compiled source-enumeration test builds an ordinary `offline-pilot` binary
and exercises six actual directory/preflight cases. Its wide fixture grows to
32,769 empty files. The complete root-module suite already runs this test.
Repeating it in a later CI step builds and populates the fixture again.

The ordinary-parent macOS and Windows lanes now request the fixed
`compiled-source-enumeration/v1` root group during the existing complete suite.
Their named control step independently checks that evidence instead of starting
another Go test process. Linux retains its separate ordinary-parent control:
its complete suite uses race/coverage instrumentation, so the parent execution
is a distinct observation. No complete-suite arguments, packages, model cells,
cryptographic checks, consumer scenarios or benchmarks are removed.

This is an opt-in `zenon-root-suite/v4` receipt. Without `--suite-root-group`,
the producer keeps its v3 shape; the verifier still supports v1/v2/v3. A caller
cannot request arbitrary roots, group names or dynamic labels. The one compiled
group requires `TestCompiledPilotSourceEnumeration` in the root module's
`tools/offline-pilot` package, a passed root, six passed subtest completions and
zero skipped/failed children. Missing roots, incorrect counts, unfinished
children, incomplete streams and failed processes cannot satisfy the group.

The group lives inside the receipt that binds the exact source inputs, complete
Go event-stream digest/byte count, selected report digest, package inventory,
process outcome, deadlines and parent instrumentation. It preserves no subtest
labels, diagnostics, private paths or additional timestamps. The Python checker
validates the fixed identities and integer-only counts independently, including
their relationship to the full-suite totals and selected scenarios. Requesting
`--require-source-root-group` refuses older receipts rather than inferring a
specific root's execution from aggregate counts or a compiled file.

The prior qualified runtime `fdd17be9d3c9a7b0a98068a72b44bb2b10eb253e`,
[run 41971763273](https://github.com/edgepillar/zenon-spv/actions/runs/41971763273),
recorded 11 seconds for the dedicated macOS control and 44 seconds for Windows;
Linux recorded one second. These are historical job-step durations, including
setup and scheduling. They are not a controlled prediction of elapsed-time
savings. Each new native revision avoids two duplicate Go processes and two
large directory fixtures on the ordinary-parent lanes. Hosted CI must still
qualify the actual source, receipts, artifacts and unchanged real test.

Local collector controls cover synthetic lifecycle mutations and a small actual
Go JSON-event fixture. That helper models one root and six subtests; it does not
run the real directory-enumeration workload or establish its source provenance.
The complete hosted suites run the unchanged real enumeration test. Existing
platform skips outside this fixed portable group remain explicit.

Consistent unsigned receipts do not authenticate execution by themselves. This
change establishes no real-network acceptance, canonicality, consensus finality,
activation, state-value proof, representative R1 budget, independent review or
authenticated distribution.
