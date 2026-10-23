# Repeated core shutdown preserves the completed result

The experimental successor serializes Zenon.Stop() callers and returns the
first completed result, including the original error object. The preceding
complete-cleanup runtime panicked when a second call closed the protocol
manager's already-closed channel. That second call never reached the worker.

This is a finite keyless component experiment based on
digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b.
It extends the [close-error cleanup experiment](core-stop-error-cleanup.md);
the upstream repository is unchanged.

## Actual observations

Two ordinary builds and six fresh processes ran on Darwin ARM64 with Go 1.25.14
and CGO enabled. Each initialized real chain, cache, consensus and core managers
from the selected unsigned source genesis. No comparison process called
Zenon.Start().

| Owned handle state before the first Stop | First error leaves, both variants | Preceding second call | Successor second call |
| --- | ---: | --- | --- |
| Healthy | 0 | Protocol channel panic | Completed success retained |
| Cache handle already closed | 1 | Protocol channel panic | Completed error retained |
| Cache and final database already closed | 2 | Protocol channel panic | Both completed error leaves retained |

The probe recovers and reports each API panic. Its zero process exit records a
complete observation; it does not turn a captured API panic into successful
shutdown. The complete source-genesis root, value, proof, readiness and
same-height foreign-hash refusal match the independent witness before Stop,
after Stop and after the repeat: 18 query observations, six ready results and
12 stopped results. Expected roots, values, proofs and Stop outcomes are never
supplied to the comparison child.

The native suite passed 58 root tests, 71 pass results and zero skips,
including the preceding 53 roots and five new roots. The new tests check
constructor and initialized shutdown, exact error identity across repeated
calls, two controlled eight-caller Stop groups and a deliberately preclosed
real protocol channel. A panicked first Stop remains a panic; later callers
receive ErrStopIncomplete without retrying partially stopped managers or
reporting success. Explicit caller teardown closes that control's remaining
owned managers.

Go race instrumentation passed the five new roots and nine results with no
skips or race diagnostics. Its package time was approximately 276
seconds; repeated full source-genesis initialization dominates this selected
run. These are controlled Stop-only callers. Concurrent Init/Start/Stop,
restart of the same stopped core, full-node startup and hardware failure are
not qualified.

## Source and resource boundaries

| View | Git tree | Files |
| --- | --- | ---: |
| Preceding runtime | 053c87e5bc4addd1bb70a467cb34facd439e66bc | 471 |
| Successor runtime | 0581880cedda66b02cbc40bd54babd19c29340ce | 471 |
| Preceding comparison | 1cc7576633b1d4d1cf6d5521f6c83b73b67c4b26 | 480 |
| Successor comparison and native tests | 0d58b9c95014ea7868e7ad85df63e1a24f24dffd | 482 |

Only zenon/zenon.go changes in the runtime. A mutex protects Stop state.
Completion is recorded only after every normal cleanup return has been joined;
the original panic is not swallowed. Other runtime method bodies are unchanged.

The existing original source and SHA-256/Go-sum-verified dependency inputs were
reused. No external dependency transport or unchanged native experiment was
repeated. Each variant used one private build cache and retained one compiled
probe object. Sources, output, complete command receipts and expected queries
remain referenced; declared disposable generated namespaces were removed only
after durable child completion and process checks. Logical/block counters do
not establish physical APFS reclaim or byte-for-byte reproduction of database
housekeeping files.

The preparation recipe retains the 10 GiB free-space floor plus expected
allocations and reservations, a 2 GiB expected allocation and a 3 GiB task quota.
Full race reproduction should allow at least 600 seconds: the recorded
276-second test execution leaves little margin under a 300-second command cap.
For unchanged inputs, reuse this retained capture. For a focused future change,
select the relevant roots rather than repeating every genesis-heavy test.
Keep full native regressions when a runtime change justifies them.

## Portable checks and reproduction

prepare_core_repeat_stop.py provides plan, prepare and verify for the pinned
original node source and a new owned workspace. It never downloads or executes
a backend. The preceding view includes the repeated-call probe; the successor
also includes the prior test-only diagnostic handler and five new native roots.
Run the returned finite arguments through the approved task storage manager
with explicit allocation, output and time limits.

check_core_repeat_stop.py validates the immutable captured streams, command
completion, exact source views and native inventories against the independent
model. Its portable controls test wrong roots, lost errors, false readiness,
changed panic origin, incomplete output, missing native passes and false
acceptance claims. Portable Linux/macOS/Windows CI checks recorded evidence;
it does not rerun this Darwin reference backend.

The frozen independent-review candidate
6ecc2310538d511e3b26bea4c658082853266a11 is unchanged. Profile agreement,
authenticated activation, independent consumer acceptance and authenticated
distribution remain open. This work does not establish canonicality, consensus
finality or header-bound state-value acceptance. The consumer result remains
REFUSED.
