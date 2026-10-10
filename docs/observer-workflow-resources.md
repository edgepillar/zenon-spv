# Complete observer workflow resource observations

`TestCompiledBlockObserverResources` measures the ordinary
`observe-block -> zenon-spv -> consume-query-report` workflow with complete
retained windows and shared read-only inputs. Native CI preserves every round
in the `Complete observer workflow resource observations` step. These are
synthetic local-file workloads with explicit trust inputs. They do not contact
an RPC, qualify representative application traffic or set production budgets.

Run from the repository root with the Go toolchain and dependencies available:

```sh
go test -v -count=1 -timeout 10m -run '^TestCompiledBlockObserverResources$' ./internal/conformance
```

## Fixed workload

The four workloads select K=256/4096 retained headers, 16 distinct commitment
targets, depth W=6 and concurrency one/four. Each runs 21 sequential groups
of fresh observer processes. A start barrier releases each group's workers;
process observations retain launch-slot order rather than completion order.
This is 84 groups, 210 observers, 420 verifier/consumer completions and 3,360
matched target rows per complete native run. Failures stop the test and are
not retried; earlier round records and the actual test failure stay in its log.
No warmup or slow observation is discarded.

A failed invocation also records `offline-observer-workflow-resource-failure`
with the round, launch slot, actual outer exit, helper-failure flag, outer output
sizes and available numeric child metadata. Application categories are restricted
to a fixed vocabulary; unknown text becomes `unknown`, and an undecodable
summary provides no child-completion claims. Raw summaries, paths, helper errors
and diagnostics are omitted. This context supports investigation and does not
qualify, retry or replace the failed workload.

The selected targets and 1,000-member flat content list reuse the pinned
node-derived content-scaling corpus. Full retained header windows, confirming
heights, anchor, profile and producer schedule are synthetic stress inputs.
They are generated before measurement, using the existing retained-capacity
fixture. Each window is fully populated. The proof bundle repeats the complete
content list for every target, as the wire format requires. It contains no
header extension. Expectations select the exact target batch, context and tip
from the fixture before the candidate query runs.

Each observer hashes the selected binaries, reads its selected expectations,
resumes and validates the saved state, verifies all 16 retained commitments,
stages the bounded report, invokes the consumer and removes its private files.
The required guarantee is `CONTENT_INCLUSION`; explicit anchor, persisted-state,
depth, profile and schedule trust allowances remain. Every observer and child
must finish successfully, with the complete batch matched and no diagnostics.
All original input bytes remain unchanged after every group. Concurrent
observers share the protected input files and private parent directory, while
the application creates a separate private run directory for each invocation.
No state writer lock, state advancement, signing or network call occurs.

## Recorded values and timing

Each `offline-observer-workflow-resource` record contains a fixed workload ID,
zero-based round, capacity, target count, concurrency, encoded input sizes,
group elapsed nanoseconds and ordered process observations. Each observation
contains the actual observer exit, whole invocation elapsed time, native waited
memory value/source, application elapsed time, matched count and the two
children's actual exits, elapsed times and output byte counts. Raw identities,
paths, pins, endpoints and verifier reports are omitted.

The group timer starts immediately before releasing the workers and stops
after all workers join. Individual outer-process timing includes launch and
wait, while the application and child timers have their existing boundaries.
Compilation, fixture generation, initial state saving and post-run input and
cleanup checks are outside the group timer. OS caches are uncontrolled. Input
checks and earlier rounds may warm files; no cold-cache or causal speedup claim
is made. The `--timeout 30s` flag retains its per-child meaning, and the test
helper bounds each whole invocation by one minute. Those timeouts protect the
experiment; they are not application service-level targets.

## Memory interpretation and acceptance gates

`waited_peak_bytes` is the existing native counter attached to the waited
observer process, with source `process_rusage` on Linux/macOS or
`windows_peak_working_set` on Windows. Other platforms record null and
`unavailable`. It is not Go allocation volume or simultaneous process-tree
memory, and the per-observer values must not be summed into a group peak.

Unix exit accounting can incorporate reaped descendants. In the pinned
[Linux exit implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c)
and [resource implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/sys.c),
the waited child's `RUSAGE_BOTH` includes the maximum of its own and inherited
child maxima. The pinned [Darwin exit implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/kern/kern_exit.c)
also folds child accounting into the exit record. These source examples explain
why this workload does not label Unix values as observer-only RSS. They do not
pin the hosted runner's kernel. Windows queries the retained observer handle's
peak working set; that counter does not include child working sets. Cross-OS
values therefore have different scopes, and no recursive peak is claimed.

The native logs bind observations to each job's exact checked-out source and
ordinary compiled binaries. They are unsigned engineering evidence, not
authenticated release artifacts. Earlier raw staging allocation comparisons,
consumer-only measurements and historical fixed-capture observer measurements
keep their original source and workload pins. This run does not retarget or
compare their performance.

Independent consumer selection, representative traffic, target hardware,
concurrency and accepted latency/memory budgets remain external inputs. Network
trust authentication, activation, elections, canonicality, finality, freshness,
independent review and authenticated distribution stay separate. Production v3
and state-value proof acceptance remain disabled.
