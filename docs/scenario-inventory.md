# Source-selected offline scenario coverage

An internally consistent candidate archive can omit a scenario that its reviewer
expected. The existing archive checker requires its two resource scenarios and
checks all recorded payload relationships; it does not independently select the
entire test inventory. That documented scope remains unchanged.

The separate `tools/check-scenario-inventory.py` companion compares an
already retained offline report with `tools/offline-pilot/manifest.go` in a
separately selected source checkout. It requires the exact scenario ID, package
and root-test selection, and each source-declared minimum command record.
Missing, extra or reassigned scenarios fail. One case's binary record cannot
satisfy a different case's requirement.

## Select inputs

Select the source repository, full checkout revision, target OS/architecture and
validated report independently. The source checkout must be clean and its HEAD
must match the selected revision. The companion reproduces the existing bounded
Go/module/JSON fingerprint, including the scenario source, before and after
checking. It does not take expected scenario identities from the report.

First run the existing complete export or archive validator and retain its
selected report and digest. The report digest binds the bytes supplied here; it
does not authenticate test execution or the source's origin. Keep source/report
parents protected and stable throughout use.

    python3 -I -B tools/check-scenario-inventory.py \
      --source "$REVIEWED_CHECKOUT" \
      --expect-revision "$SELECTED_CHECKOUT_REVISION" \
      --report "$VALIDATED_OFFLINE_REPORT" \
      --expect-report-sha256 "$SELECTED_REPORT_SHA256" \
      --expect-os "$SELECTED_OS" \
      --expect-architecture "$SELECTED_ARCHITECTURE" \
      --require-skip-ledger

Use the selected native Python executable on Windows. The auditing tool and
reviewed source checkout may be in different directories. A retained protected
report can be read directly; no candidate ZIP, executable rebuild or extraction
of binary payloads is needed.

## What the result means

A zero exit and complete `consistent` result establish agreement of the
reported selection with the selected source. The result carries source, report
and scenario-file digests, coverage counts and explicit skip coverage.

The fields `candidate_payloads_validated`, `test_execution_authenticated`
and `network_or_state_value_acceptance` remain false. They describe this
invocation: the companion does not replace complete candidate validation,
authenticate a claimed test run, qualify a network/profile or accept state
values. Independent human review and authenticated distribution remain separate.

With `--require-skip-ledger`, the report needs complete schema-2 skip
accounting. Without it, historical schema-1 reports retain explicit unknown
coverage. A present schema-2 ledger must still be complete, as in the candidate
validator. Native platform names never supply missing skip reasons.

## Bounds and source format

The report is at most 4 MiB and the literal scenario source at most 64 KiB.
Regular-file reads retain descriptor identity/size checks, exact-length reads,
real EOF and successful close. Report parsing reuses the pinned candidate
validator's JSON bounds and field/resource/skip rules. These are read and parser
bounds, not a whole-process memory budget or filesystem ownership authentication.

The source parser accepts the selected positional literal registry, nil or
literal command lists, comments and ordinary whitespace. It checks the complete
declaration shape and constants/corpus tail. Computed entries, duplicate IDs or
test bindings, changed declarations and extra Go statements are rejected rather
than silently ignored. It never evaluates Go code. A future source format needs
an explicit parser review.

The original archive/export validators and historical captures remain byte
identical. Their full source and payload checks remain required. CI configuration
runs this companion after full export validation and requires both results before
candidate upload; observing the exact run is still necessary.

The portable controls use regular temporary files and opaque byte fixtures.
They cover the documented omission boundary, changed selections, command
requirements, source/report drift, bounded reads, failures, privacy and output
completion. Synthetic controls are not native execution or live-chain evidence.
