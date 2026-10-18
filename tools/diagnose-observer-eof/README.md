# Bounded observer EOF diagnostic

This is a separately selected diagnostic overlay for the Windows resource
failure in [main run 39087919873](https://github.com/edgepillar/zenon-spv/actions/runs/39087919873).
The selected base is `cc8c73fa75eced453ede7e6f8467042b3f8e14ed`.
The ordinary observer refused `K4096_T16_C4`, round 3, slot 0, with
`output_incomplete`. Its verifier exited 0 and the consumer was not started.
That log does not identify which stream missed EOF or the original `Cmd.Run`
error. A byte count and exit 0 do not establish complete delivery.

`prepare.py` pins the complete bytes of five affected source files and verifies
every whole-file patch inverse. It writes seven overlay files into fresh,
caller-owned scratch. It does not edit the selected source files, change the
production CLI, download dependencies, build executables or run a command.
The manifest binds affected files; it is not an independent authentication of
the whole checkout. The workflow separately records its selected commit/tree.

The instrumented observer records only fixed error classifications, numeric
timings/counters and booleans after `Cmd.Run` joins its stream-copy goroutines:

- The original error, exact `ErrWaitDelay` identity and normalized error.
- Each stream's copy entry/completion, read calls, terminal read, actual EOF,
  copy error and elapsed time.
- Context cancellation, output caps and destination failure flags.

No errors, child bytes, paths, arguments, endpoints or credentials are formatted
into these diagnostic fields. All joined slots are logged before the existing
validator stops at its first failed round. Output completion, caps, cancellation,
nonzero exits, target checks, cleanup checks and their precedence are unchanged.
Instrumentation affects timing and binary identity. These are not ordinary
release binaries and an instrumented pass cannot qualify the failed main run.

The dedicated branch workflow runs one generation with Go 1.25.14 on Windows
amd64. It selects K=4096, 16 targets, four concurrent invocations and 21 rounds.
The observer's 30-second deadline, one-second pipe wait and 4 MiB report bound
are unchanged. There is no rerun, filtering, timeout increase or acceptance of
an exit code in place of real EOF. Failure retains its actual result. Completing
the selected workload without a failure is `NOT_REPRODUCED`, not a repair or a
root-cause finding. This workflow does not change the ordinary CI workflow.

The first diagnostic generation, [39091079408](https://github.com/edgepillar/zenon-spv/actions/runs/39091079408),
remains failed. All twelve selected Go test groups emitted PASS, but `go test`
then exited 1 because Windows refused removal of its implicit test executable.
The resource phase was **NOT_RUN**. This is not a passing command or a resource
reproduction. The specific lock holder is unknown. The revised Windows harness
compiles one explicit control image, records its digest, runs it once, and records
its actual exit separately from bounded removal of that exact owned image.
Access denial is retained until removal succeeds or the five-second cleanup
limit fails with the workspace held. This does not increase the observer's
one-second pipe wait or alter any test assertion. A subsequent source-bound
generation is the first execution of the selected resource phase, not a retry
or replacement of an observed resource sample.

For local controls, select an approved managed task's scratch parent and an
explicit compiler. The runner requires 10 GiB free plus 1 GiB expected allocation,
creates private temporary build/module caches, streams each command once with
4 MiB stdout and 1 MiB stderr caps, and cleans only its own new workspace after
settled commands. Unsettled stream copies retain scratch for inspection. The
outer approved task manager must still enforce the declared local task quota;
this runner is not a storage manager or an OS-enforced disk quota.

```sh
python -B tools/diagnose-observer-eof/run.py \
  --source-root "$SELECTED_SOURCE" --scratch-parent "$OWNED_TASK_SCRATCH" \
  --go "$SELECTED_GO" --controls-only
```

The complete capped job log is the diagnostic record; no executable ZIP,
recursive scratch archive or second stdout copy is produced. Preserve actual
exit/completeness receipts with the source, workflow run/attempt and platform.
This tooling neither changes protocol trust inputs nor enables state-value
proofs, canonicality, finality, wallets, signing, transactions or a live node.
