# Observer resource records in the complete suite

Root-suite receipt version 3 preserves the existing source, execution, package,
count, stream-digest and timing fields, and adds `observer_resources`. The
independent receipt checker continues to accept unchanged version 1/2 receipts.
Historical reports are never rewritten or relabelled as version 3.

The full unfiltered root-module test run already executes
`TestCompiledBlockObserverResources`. Its source-owned numeric records are now
retained in the receipt, rather than requiring a second ordinary-parent run on
macOS and Windows to keep their values visible. Linux retains its separate
ordinary-parent invocation: its complete suite enables the race detector, while
compiled observer/verifier/consumer children remain ordinary builds.

A complete supported workload has capacities 256 and 4,096, 16 targets,
concurrency 1 and 4, and all 21 rounds. It retains 84 ordered group records and
210 outer-process observations, including their 420 verifier/consumer records.
No round is retried, dropped as an outlier, or sorted into another process slot.
Builds, fixture construction and preservation checks remain outside the group
timer. Parent instrumentation and the native accounting source remain part of
the report's measurement scope.

Collection selects only the known package/root and exact numeric success/failure
schemas. Each record is bounded to 16 KiB and aggregate recognized records to
256 KiB, with four known workload identities, 84 successful groups and at most
four failure contexts. Split test2json output is reassembled only for those
active workloads. Missing, duplicate, reordered, malformed, truncated or
over-budget records cannot appear complete. Arbitrary diagnostics, input paths
and test labels are not copied into the receipt.

Failures preserve actual recorded groups and fixed failure context. A passed
resource root does not override a failed/incomplete suite or process. The
checker requires complete resource observations as well as all existing source,
execution, count, timing and selected-report checks before accepting version 3.
Its output summarizes counts and binds the full receipt digest instead of
copying every observation again.

Native waited-process memory counters are not simultaneous process-tree peak
memory. Unix accounting may include inherited data from reaped descendants;
Windows uses its peak-working-set counter. These synthetic retained-window
observations do not establish representative R1 hardware budgets, live-network
activation, consensus finality or state-value acceptance. Unsigned reports still
require actual source-specific native CI and artifact qualification.
