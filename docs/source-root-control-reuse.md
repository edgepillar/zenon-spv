# Reusing complete-suite source enumeration evidence

The compiled source-enumeration test builds an ordinary `offline-pilot` binary
and exercises six actual directory/preflight cases. Its wide fixture grows to
32,769 empty files. The complete root-module suite already runs this test.
Repeating it in a later CI step builds and populates the fixture again.

The ordinary-parent macOS and Windows lanes request
`compiled-native-observers/v3` in the existing complete suite. The independent
receipt checker requires the group before uploading the checked receipt.
Each root must pass with its complete fixed subtest inventory.

| Source package | Test root | Passed subtests |
| --- | --- | ---: |
| `internal/conformance` | `TestCompiledAdvancingBlockObserver` | 9 |
| `internal/conformance` | `TestCompiledNodeAccountBasicObserver` | 58 |
| `internal/conformance` | `TestCompiledNodeAccountReceiveObserver` | 52 |
| `tools/offline-pilot` | `TestCompiledPilotSourceEnumeration` | 6 |
| `internal/conformance` | `TestCompiledNodeAccountPoWObserver` | 134 |
| `internal/conformance` | `TestCompiledVerifierSelectionGuards` | 0 |
| `internal/conformance` | `TestCompiledVerifierSyntaxPrivacy` | 0 |
| `internal/conformance` | `TestCompiledCollectorSyntaxPrivacy` | 0 |
| `internal/conformance` | `TestCompiledMaintainerSyntaxPrivacy` | 0 |

The group replaces the separate ordinary-parent invocations of its nine roots
on macOS and Windows. Linux runs its ordinary-parent controls alongside its
race/coverage suite. Dedicated persistence and grouped build steps still emit
their detailed reports. Complete-suite packages,
timeouts, independent byte checks, benchmarks and consumer builds are exercised
under their original settings.

The version 2 group retains the original 523-byte PoW observer summary from
its running root in the complete event stream. It requires one exact report
and 134 passing subtests. The checker independently verifies the compact JSON
digest and records it in the checked receipt. In the baseline run, the removed
duplicate steps took 20 seconds on macOS and 13 seconds on Windows. These are
observed step durations on that revision. [Baseline CI](https://github.com/edgepillar/zenon-spv/actions/runs/44795262864)

The version 3 group also retains the four compiled CLI control reports. The
complete event stream must contain one report for each named root. The Go
collector assembles split lines within each report's exact byte bound and
checks the original payload digest. The Python checker checks independent
canonical JSON digests. All 414 refusal records and the help and configuration
counts are retained in the existing receipt. The checked receipt lists their
digests. The four separate steps took 22 seconds on macOS and 10 seconds on
Windows on the preceding revision. [Baseline CI](https://github.com/edgepillar/zenon-spv/actions/runs/44830506683)

The opt-in `zenon-root-suite/v4` schema supports these fixed groups.
Historical `compiled-source-enumeration/v1` receipts keep their original
one-root contract. `compiled-native-observers/v1` retains its four-root
contract and `compiled-native-observers/v2` retains its five-root contract
and PoW report. The default producer emits v3 and the verifier also supports v1 and
v2. Each group requires the exact package, root, child count and passed outcome,
with zero skipped, failed or unfinished children.

The group lives inside the receipt that binds the exact source inputs, complete
Go event-stream digest/byte count, selected report digest, package inventory,
process outcome, deadlines and parent instrumentation. The fixed roots,
counts and selected PoW summary contain public evidence fields. The Python
checker validates the fixed identities and integer-only counts independently, including
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

The baseline native jobs spent 27 seconds on the three affected macOS steps
and 18 seconds on Windows. Those totals include the two ordinary advancing unit
controls that still run separately. Runner timing varies with caches and load.
[Baseline CI run](https://github.com/edgepillar/zenon-spv/actions/runs/42773701808)

Local collector controls cover both group shapes, fixed root identity and
subtest counts. The complete hosted suites exercise the real enumeration,
advancing and node-derived account observer tests and bind their outcomes to
the actual platform and source.

Consistent unsigned receipts do not authenticate execution by themselves. This
change establishes no real-network acceptance, canonicality, consensus finality,
activation, state-value proof, representative R1 budget, independent review or
authenticated distribution.
