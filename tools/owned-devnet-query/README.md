# Owned devnet BatchEntry experiment

The manual workflow selects one chain-69, domain-1, batch-0 experiment on a
fresh GitHub-hosted Ubuntu runner. A dispatch requires the reviewed runner
commit, the SHA-256 of one reviewed contract and an affirmative fixture input. Its
runtime action starts the owned services, configures the selected public
fixture and submits the pinned upstream deposit flow. Preparation controls run
separately on Linux, macOS and Windows.

`contract.json` preserves the original source cohort and inputs. The separate
`reference-gas-contract.json` selects the matching new source and qualified
Linux consumer/oracle pair; see the
[reference-gas contract](../../docs/reference-gas-owned-contract.md).
The acknowledged digest selects exactly one of these reviewed files before
transport or engine contact. Neither file migrates the other's context pins.
Each contract selects the source cohort, previously qualified Linux inputs,
query identity, six-service scope and resource budget. `model.py` checks those
inputs and models explicit dispatch metadata and container ownership. A matching
contract digest is configuration identity, not operator authorization.

`sources.py` prepares only fresh checkouts of the four selected repositories. It
checks the fetched revision and bounded regular-file tree before checkout, then
checks every tracked Git blob, selected SHA-256 and file identity. It uses the
original `ZENO_DEVNET_SRC` layout and checks both locked TypeScript Git dependency
pins. It does not install packages or execute their scripts. Existing checkouts
and inherited credentials, Git configuration and debug options are not adopted.

`process.py` captures bounded POSIX commands with actual exit and completeness
receipts. Its command directory is new and exclusive. It signals only the process
group it created; container lifecycle requires the separate immutable-ID journal.
It does not cover session-escaping descendants, hostile same-user writers or
power loss.

`inputs.py` reads an original selected ZIP in place, checks its SHA-256 and byte
count, and writes only the selected regular binaries into a new directory. For
the consumer it streams one bounded XZ/TAR payload, separately checks compressed
and decoded digests, and requires the complete expected member set. Neither the
inner XZ nor a decoded TAR is written to disk. The parent oracle uses a bounded
plain ZIP. There are no hard links, existing-directory adoption or cleanup calls.
Partial outputs remain non-executable. Enabling execution is a separate action
after complete verification, and no binary is executed by this module.

The CLI-input codec's maximum original ZIP and expanded content sizes are each 64 MiB;
ZIP members are limited to 128 and the XZ decoder has a 128 MiB memory ceiling.
These are codec limits, not an aggregate OS-enforced resource quota. The caller
must separately establish fresh workspace ownership, free-space admission,
actual transport completion and exact source/run/attempt/artifact binding.
Archive equality is not authenticated distribution or a new CI qualification.

`artifacts.py` binds both required artifacts to completed source/workflow/run/
attempt metadata before downloading either archive. An input observed expired
or mismatched stops the workspace before archive transport. Each transfer
holds its artifact lease and streams stdout directly into the one original ZIP,
with the selected size and SHA-256 checked against the actual result. A verified
in-memory hit rechecks original file identities and binary contents. Incomplete
or failed attempts are terminal for that workspace. This step does not qualify
a new CI run or enable binary execution.

On fresh intake, the ZIP and Node archive readers perform their existing
pre-extraction SHA-256 scan on the recorded stdout descriptor. The recorder
holds and checks the file identity around that scan and extraction. The
compressed, decoded and selected-binary checks retain their separate pins.

`node_toolchain.py` separately handles the official Node 22.23.0 Linux x64 input.
It checks the original SHA-256/31,048,380-byte input, the decoded TAR digest and
the 4,690-file selected manifest. The selected Node/npm/header files total
194,624,701 bytes; the decoded-content ceiling is 256 MiB. Inspection writes no
extracted file. Materialization creates regular files only, followed by regular
npm/npx wrappers after complete verification. Native execution remains a separate
action; a matching ELF header or vendor archive does not prove native execution.

`packages.py` is the later native preparation step. It checks the enabled
toolchain and source snapshots, observes actual Node/npm versions, and runs
`npm ci` with required upstream preparation scripts. Cache, temporary data,
node-gyp data, logs and Git/npm configuration stay under its new private task
directory. It checks the installed Git dependency identities and selected built
entrypoints, without claiming an independently reproduced whole dependency tree.
The local package controls execute no package script.

`engine.py` implements the causal container lifecycle, for use by the future
explicitly dispatched controller. It checks a fresh Linux/amd64 engine and fixed
project absence, records complete create-returned IDs, checks configured limits,
and stops only those owned IDs. Builder closure precedes runtime creation.
The runner pins the selected runtime files before package scripts or image
builds and checks them again before creating the runtime layout.
The source-flow gate refuses extra containers before upstream discovery helpers
can act. Graceful RPC closure remains bound to the same recorded volume and its
`nom` subdirectory. Volume/image/network removal is not performed. Configured
limits and synthetic lifecycle controls are not measured runtime enforcement.
The image builder reuses the two selected runtime images across the six services.
It binds the derived recipes to source bytes and observes the loaded image IDs.
The controller samples free space and retained evidence during work and reserves
five minutes for owned process closure. The 19 GiB admission requirement includes
a 10 GiB free-space floor, 8 GiB expected allocation and 1 GiB margin.

The Linux preparation job samples the runner's free space, available memory
and effective CPU count before Python setup or tests. It uses the same
`ubuntu-24.04` label and the experiment's admission thresholds. The separate
`owned-devnet-host-admission-<attempt>` artifact binds the sample to its
source revision, contract, run and attempt. Its outcome records
`MEETS_THRESHOLDS`, `REFUSED` or `UNAVAILABLE`. The experiment repeats
admission on its own workspace and checks the engine filesystem separately.

The controller observes the selected H1 and the H2-to-H3 transition before
configuration. After the fixture deposit it selects H and waits for one successor.
It stops the producers and clients, records the RPC frontier, and uses the
qualified `fetch-bundle` binary to collect the exact header range and three proofs.
It requires the same frontier before closing the RPC node.

The closed-ledger phase checks the complete stopped container roster and the
original RPC volume. The narrow privileged supervisor binds that volume's
`nom` directory read-only in private mount and network namespaces. Each call
runs the pinned oracle from a verified executable descriptor for at most 64
targets. The supervisor revokes the child on control-pipe EOF and has a separate
100-second outer deadline. Oracle reports bind every parent, proof block and slot
to the captured range. H2 is the scoped trust anchor. The observed v3 range
supplies the schedule entries.

The offline `zenon-spv` consumer receives the independently encoded header
and query context pins. The controller checks the complete header acceptance
record, the detached context settings and the configured anchor, profile and
producer-schedule trust list. It refuses a checkpoint input or output on this
anchor-replay path. It then compares the exact H and tip, all three proofs and
typed rows, selected source semantics and all 17 stored BatchEntry fields from
the frontier DTO. It records a gateway mismatch separately.

The workflow retains a file manifest, actual command receipts, and the selected
header, oracle, provider and consumer evidence. The original downloads remain
single files in the transport directory. The upload selects evidence by name
and digest. The fresh runner owns the disposal boundary.

Post-stop inspections retain a separate `owned-devnet-stop-state/v1` diagnostic
before the existing stopped-container checks run. It binds the owned ID, service,
inspection command and original stdout digest to allowlisted typed state fields:
running/restarting/dead/OOM/paused flags, PID, exit code and a known status.
Missing or invalid fields are listed without coercion. An engine error is
classified as empty/nonempty/missing/invalid; its text, mounts, labels and other
inspect values are not exported. Normal work and cleanup keep separate records.
A diagnostic does not establish closure. The
[builder-only shutdown policy](../../docs/owned-builder-shutdown.md) accepts
exit 0 or 1 for the cache builder under strict owned/quiescent-state checks;
the six runtime services retain their original zero-exit requirement. The
post-stop and final builder observations must agree before non-force removal.
The image report records the observed exit code and establishes no ledger closure.
Only the declared service names and bounded command-number filenames enter the
upload. Completed per-image reports also survive a later builder-close refusal.

The [first authorized attempt](../../docs/owned-devnet-attempt-2026-11-13.md)
stopped at builder closure before node startup. Its original artifact preserves
the failed result; these additional diagnostics cannot reconstruct missing state
from that historical run. A new execution requires a new exact-source approval.

### Review a retained result

Before downloading, select the runner revision, attempt-1 run ID, artifact ID
and local contract SHA-256 independently of the result ZIP. Retain the GitHub
Actions responses for `runs/<run-id>/attempts/1`,
`runs/<run-id>/attempts/1/jobs?per_page=10` and `artifacts/<artifact-id>` under
`repos/edgepillar/zenon-spv/actions/`. Use an authenticated read-only acquisition
and keep its command receipts with the three original JSON responses.

```sh
python3 -I -B tools/owned-devnet-query/review.py select-hosted \
  --run-metadata "$RUN_METADATA" --jobs-metadata "$JOBS_METADATA" \
  --artifact-metadata "$ARTIFACT_METADATA" --expect-artifact-id "$ARTIFACT_ID" \
  --expect-source-revision "$RUNNER_SHA" --expect-contract-sha256 "$CONTRACT_SHA256" \
  --expect-run-id "$RUN_ID"
```

`SELECTED_HOSTED_RESULT` binds the supplied run, completed experiment job,
upload step and artifact metadata. The report records the three JSON pins,
the reported conclusions and the selected archive byte count and SHA-256.
Selection can succeed for a failed experiment with a retained upload. It uses
up to 128 KiB per JSON input and performs no network calls. Authenticity of
the JSON depends on its acquisition. The expected contract pin selects the
local contract for the later archive review.

Use the selected byte count and SHA-256 to fetch or reuse one original result
ZIP under the artifact lease. Review the ZIP and the retained metadata together
with the same runner revision, run ID and contract pin.

```sh
python3 -I -B tools/owned-devnet-query/review.py review-hosted \
  --run-metadata "$RUN_METADATA" --jobs-metadata "$JOBS_METADATA" \
  --artifact-metadata "$ARTIFACT_METADATA" --expect-artifact-id "$ARTIFACT_ID" \
  --expect-source-revision "$RUNNER_SHA" --expect-contract-sha256 "$CONTRACT_SHA256" \
  --expect-run-id "$RUN_ID" --archive "$RESULT_ZIP"
```

Exit 0 reports `HOSTED_RECORDED_CONSUMER_BYTES_MATCH` when the supplied run
concludes successfully and the archive's consumer comparison passes. Exit 1
retains both the hosted and archive outcomes for a nonaccepting run, including
when the archive passes its own comparison. Exit 2 reports a refusal, including
a reported success or failure of the execution step that conflicts with the
archived terminal outcome. The combined review binds the supplied metadata to
the exact original ZIP and rechecks the recorded result without another download.

An independently pinned ZIP can also be inspected on its own.

```sh
python3 -I -B tools/owned-devnet-query/review.py \
  --archive "$RESULT_ZIP" --expect-archive-bytes "$ARCHIVE_BYTES" \
  --expect-archive-sha256 "$ARCHIVE_SHA256" --expect-source-revision "$RUNNER_SHA" \
  --expect-contract-sha256 "$CONTRACT_SHA256" --expect-run-id "$RUN_ID"
```

The reader checks the archive framing, exact indexed file set and all member
digests in place. For a recorded successful consumer, it checks the selected
binary transport receipts, the H2/H3 boundary, the captured H/hash and tip,
the reported closed RPC container and oracle receipts, and the derived query
inputs. It recomputes the three membership proofs, decodes the typed rows and
compares the 17 stored fields with the recorded gateway response and CLI result.

Exit 0 reports `RECORDED_CONSUMER_BYTES_MATCH`. This is agreement among the
retained records and independently recomputed bytes. The original run identity,
native signature verification, producer authority and any selected-network
acceptance retain their own evidence requirements. Exit 1 reports an intact
archive with a recorded failure, refusal or unknown outcome. Exit 2 reports a
refused or incomplete inspection.

The reader opens only the original ZIP and the local contract/profile files.
The limits are 2,048 ZIP members, a 512 KiB index, 2 MiB per indexed file and
64 MiB expanded in total. It streams the remaining indexed members in 64 KiB
blocks. Review creates zero extracted bytes and reuses the original recorded
consumer output. Preserve the original archive and run metadata as evidence.

The regular-file controls can be run with Python's standard library:

```sh
python3 -I -B tools/owned-devnet-query/reference_gas_test.py
python3 -I -B tools/owned-devnet-query/model_test.py
python3 -I -B tools/owned-devnet-query/process_test.py
python3 -I -B tools/owned-devnet-query/inputs_test.py
python3 -I -B tools/owned-devnet-query/artifacts_test.py
python3 -I -B tools/owned-devnet-query/sources_test.py
python3 -I -B tools/owned-devnet-query/node_toolchain_test.py
python3 -I -B tools/owned-devnet-query/packages_test.py
python3 -I -B tools/owned-devnet-query/engine_test.py
python3 -I -B tools/owned-devnet-query/images_test.py
python3 -I -B tools/owned-devnet-query/budget_test.py
python3 -I -B tools/owned-devnet-query/query_checks_test.py
python3 -I -B tools/owned-devnet-query/capture_test.py
python3 -I -B tools/owned-devnet-query/review_test.py
```

Use the approved task-storage manager for local qualification, with its owned
scratch directory supplied as `TMPDIR`. The tests use synthetic archives,
regular temporary files and benign child processes with anonymous pipes. They
create no on-disk FIFO, symlink or socket fixtures. POSIX process-group tests
report their unsupported Windows cases explicitly. Runtime and privileged-reader
qualification require an actual completed manual experiment on the selected
source.

The complete artifact controls include local child-process responses and regular
file replacement/lease counterexamples. A local monitor interruption is preserved
as FAILURE/UNKNOWN; individual observed cases do not qualify the complete suite.
`artifacts_test.py --metadata-only` selects three pure metadata roots for local
use; its receipt explicitly says that the transport suite was not executed. Keep
complete-suite execution in hosted CI. Do not run real source checkouts inside
managed foreground scratch: Git trees are intentionally protected by its observer.

The selected source contract and its maintainer review are documented in
[the query contract](../../docs/batch-entry-query-contract.md). The finite
producer schedule still requires parent-snapshot provenance; the producer in a
provider's header does not authorize itself. Real v3-transition capture and an
accepted-header-root-bound three-row query remain open. Production acceptance,
authenticated election, consensus finality and funds release are not established.
