# Owned devnet BatchEntry experiment

The manual workflow selects one chain-69, domain-1, batch-0 experiment on a
fresh GitHub-hosted Ubuntu runner. A dispatch requires the reviewed runner
commit, the SHA-256 of one reviewed contract and an affirmative fixture input. Its
runtime action starts the owned services, configures the selected public
fixture and submits the pinned upstream deposit flow. Preparation controls run
separately on Linux, macOS and Windows.

The original and reference-gas contracts preserve their historical input pins.
`reference-gas-renewal-1-contract.json` selects the renewed Linux pair for the
same reference-gas query. The acknowledged digest selects an exact reviewed
contract before transport or engine contact. The renewal carries the same
node, header, query profile and context requirements. See the
[reference-gas contract](../../docs/reference-gas-owned-contract.md).
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

The runner checks this metadata before preparing the node. The pinned Go node
and executor recipes build from their source contexts. After the H1/H2/H3
opening passes validation, the runner verifies the consumer and parent-oracle
archives, installs the host Node.js toolchain and prepares the locked npm
packages. It rechecks the runtime files after package scripts and before
fixture configuration. A refusal before the opening reaches none of these
archive transfers, the Node.js extraction or `npm ci`.

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

Before enabling execution, the installer inventories and hashes every selected
file. It enables each executable through its checked file descriptor and
rehashes it after the mode change. The final inventory also checks that the
other files kept their identity, permissions and metadata from the first scan.
The owned runner requests this transition during intake, so that first scan also
serves as the installed-file verification. The complete archive and selected
manifest are checked before any execution permission is enabled.
Each separate verification still reads and hashes the complete installation.

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

The reviewed reference-gas configuration flow has a 660-second command
deadline. The pinned CLI waits for height 11, sends setup commands serially
and waits 14 momentums before reading and confirming challenged settings. The
configuration allowance adds two nominal ten-second momentums for each of up
to 12 send/receive steps to the 420-second setup budget. The deposit flow has
a 900-second deadline, including the pinned flow's 480-second finalized-receipt
wait. The original devnet cohort uses a 420-second deadline per command. Both
flows operate within the shared time and disk budget and cleanup reserve. Each
phase runs once.

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

The [second authorized attempt](../../docs/owned-devnet-startup-attempt-2026-11-13.md)
built both images, closed the owned builder and started four node containers, then
failed on the first loopback RPC read with exit 56 and zero response bytes. It
reached no signed fixture operation or consumer acceptance. Startup waits now
admit only completed, quiescent curl exits 7, 28 or 56 with zero stdout bytes.
They retain each failed command and the existing time, attempt and shared RPC-call
bounds. Partial responses, invalid RPC data, incomplete captures and failures
outside startup remain terminal. This behavior does not establish the cause of
the recorded receive failure or authorize another signed attempt.

The [third authorized attempt](../../docs/owned-devnet-readiness-attempt-2026-11-14.md)
recovered from that empty receive failure, then refused at the unchanged
readiness deadline after 29 completed frontier commands. It reached no signed
fixture step. Its original archive has response pins without the raw frontier
bytes, so the exact stalled height cannot be independently recovered from it.

Subsequent captures retain the original `rpc-NN.frontier.json` stdout only
after successful envelope and selected-chain/header parsing. The existing
128 KiB response cap, shared 96-call bound and total evidence bound still apply.
The final index includes these checked responses and their paired
`rpc-NN.request.json` records even after a later refusal;
failed or invalid response files, stderr, service logs and private configuration
remain outside this extension. The reader checks each response against its
successful complete/quiescent command, started record, exact frontier request,
response ID and chain. It reports candidate observations with
`accepted_header_authority: false`. These bytes cannot supply the anchor,
producer schedule, accepted StateRoot or a completed consumer result.
Older archives without these optional files keep their existing report shape.
Only requests paired with a validated frontier response are selected. Unrelated
request files and failed-response bodies are not added to the export. The
recorder-to-index-to-reader control checks this exact selection in memory,
without writing a second ZIP to disk.

### Check the opening proof before fixture setup

After validating the opening sequence, the runner derives the selected
BatchEntry key from the pinned profile and requests one bounded
`ledger.getProof` at the candidate H3. It checks the canonical proof against
the StateRoot in that candidate header and requires absence for the selected
BatchEntry before fixture setup. A valid membership proof yields
`opening_batch_already_present` and retains the bound reply for offline review.
An unavailable reply, incorrect root or malformed proof also stops preparation
before binary downloads, package installation or fixture signing.

The shared budget allows the extra read within the existing 96 calls. The
successful path reserves up to 90 calls for the three readiness waits, one for
the opening, one for this proof, two for query selection and two for the
frontier around final collection. A checked reply and its paired request are
retained once. The selected node's exact `trie: no such version` reply is
also retained when it refuses this read. Archive review checks the original
reply, paired request, completed command and terminal refusal. This reply
records an unavailable tree version for the requested height. The original
node returned the same error in an isolated retained-history test.
[Recorded pruning control](../../docs/first-insertion-catchup.md#pruned-versions-and-retained-absence-at-the-rpc-boundary)

Archive review recomputes the opening proof from the retained bytes and
selected profile. After the absence check passes, the runner uses the host OpenSSL
Ed25519 verifier to check the H2 and H3 signatures over their recomputed
32-byte hashes. Both commands must complete successfully before input
downloads, package installation or fixture setup. Their small input files
are staged in the runner's private scratch directory and removed after the
checks. The archive binds a successful report to the original opening reply
and the two completed command receipts.

These checks establish signature validity for the observed candidate bytes.
The actual BatchEntry query still needs the selected producer schedule, the
accepted header and all three membership proofs at the query height.

### Capture the node's sync state after a startup refusal

Only an initial selected-height `owned_rpc_readiness_deadline` permits one
`stats.syncInfo` read from the same fixed owned RPC endpoint. The initial
selected-height wait allows 180 seconds and up to 30 reads. The runner schedules
the reads at roughly 6.17-second intervals measured from the start of the
window and skips fully elapsed slots after a local stall. Response and capture
time count toward each interval. The final slot starts one second before the
deadline. Each read uses the lesser of five seconds and the remaining time as
its HTTP limit and retains the two-second command capture allowance.
A response that finishes at or after the readiness deadline stays a candidate
observation. Gateway and later height waits allow 90 seconds and up to 30 reads
with the usual three-second interval. All phases share the 96-call budget.

The [recorded chain-69 attempt](https://github.com/edgepillar/zenon-spv/actions/runs/43653383092/attempts/1)
returned H2 on its final regular readiness read and on the later diagnostic.
Its terminal result remains a refusal at the H3 readiness boundary. The
diagnostic applies only after an initial deadline refusal.

The response cap is 8 KiB, with the existing five-second HTTP / seven-second
command limits and a fresh budget guard. Only the three bounded integer fields
`state`, `currentHeight` and `targetHeight` are allowed. Peer IDs, addresses,
service logs and private configuration are not requested by this extension.

`startup-sync.json` records the original trigger and the diagnostic's own
`OBSERVED`, `FAILURE`, `UNKNOWN`, `REFUSED` or `NOT_ATTEMPTED` outcome. An exhausted
call budget or refused budget guard starts no diagnostic command. Only a checked
response is exported as `rpc-NN.sync-info.json`, alongside its exact request,
started record and successful complete/quiescent receipt. Failed, invalid and
partial response bodies remain excluded; their actual command receipts and the
fixed non-sensitive request are retained when available. A missing command
receipt supplies no invented exit or completion result.

The reader replays the request, receipt, envelope and DTO checks for an observed
response. It exposes unavailable/interrupted outcomes separately, preserving the
recorded exit and completeness. A refused DTO's excluded body is not independently
revalidated. The original readiness refusal remains non-accepting; an interrupted
controller remains `UNKNOWN`. A node reporting `SyncDone` or a higher current
height supplies no accepted header, anchor, producer schedule, StateRoot,
canonicality or completed consumer. Older archives without this optional record
keep their report shape. See the [source and scope record](../../docs/owned-startup-sync-diagnostic.md).

An observed sync response also permits one next candidate frontier read, with a
fresh budget check, the existing 128 KiB bound and the same shared 96-call cap.
Its optional `startup-post-sync-frontier.json` summary binds the two sequential
request IDs. Validated frontier bytes and their exact request are retained;
failed or partial bodies are excluded. The reader reports
`post_sync_frontier_diagnostic` with false header authority and an explicit
`atomic_with_sync_observation: false`. The initial refusal still ends execution,
even when this later candidate has reached the requested height. A shared-call
or budget refusal launches no follow-up command.

The [source-b8bae80 attempt](../../docs/owned-devnet-sync-attempt-2026-11-14.md)
captured `SyncDone` at reported height two after 29 H1 frontier responses. The
follow-up read addresses its missing candidate hash; the original archive keeps
its original bytes and report shape.

The [source-f09006d attempt](../../docs/owned-devnet-startup-nodes-2026-11-14.md)
retained both reads: `SyncDone` at current/target height one, followed by another
v1 H1 frontier. It reached no fixture configuration or native consumer result.
Its after-stop nonzero exits cannot establish when or why a producer stopped.

### Compare the primary pillar and RPC frontiers after refusal

An observed post-sync RPC frontier permits a read of the primary pillar's
already published loopback port 35991, followed by another read of the RPC
port 35997. The controller reserves two slots in the shared 96-call budget,
checks resources before each read and uses the existing 128 KiB response
bound and five-second Curl deadline. Each request is a
\`ledger.getFrontierMomentum\` call with empty parameters. A failed or invalid
pillar read stops the pair. The original readiness refusal ends execution.

The optional \`startup-peer-frontiers.json\` report identifies the preceding
RPC request and the two ordered role-specific observations. The reader
rechecks the exact requests, command receipts, response envelopes and
candidate headers. When the RPC candidate changes across the two reads, the
report records that movement. When the two RPC identifiers agree, it can
distinguish a matching pillar candidate, a height difference or a different
hash at the same height. Partial pairs retain their individual outcomes.
The reads are sequential candidate observations. Producer authorization,
peer receipt and the reason for a readiness refusal require separate evidence.

### Observe owned node state before cleanup

After that same initial readiness refusal, `startup-node-diagnostics.json`
optionally records a fresh engine identity probe and the four owned nodes'
state and bounded log summaries. There are at most nine read-only Docker
commands, each limited to five seconds and the existing resource guard. Logs
require the owned container identity, expected image and configured limits.
Each log command selects 128 tail lines and caps stdout/stderr at 32 KiB each.

Only bounded typed state, fixed event counters and allowlisted relative
source-file/line pairs enter the public summary. Raw inspection/log streams,
arbitrary panic messages, arguments, peer addresses and private configuration
remain outside the index. Actual failures and incomplete capture keep their
own receipt fields; the first readiness refusal remains non-accepting.

The reader binds the command and stream pins, requires successful original
start/completion records for observed phases, checks command ordering before
cleanup and refuses raw streams in this extension's index. Its result explicitly
marks the summaries as diagnostic assertions: excluded raw text is not
independently replayed. The observation is sequential, supplies no accepted
header authority and never retries readiness or advances to configuration.
Command records without the optional summary, or alongside a claim that no
diagnostic was attempted, are refused rather than silently ignored.
Archives without this optional summary preserve their existing report shape.

### Read the node's actual log files

The [whole-file v1 record](../../docs/owned-startup-file-logs.md) explains the
node's file handlers. The [bounded-tail follow-up](../../docs/owned-startup-log-tails.md)
records the source-7cb3fdd attempt: an eventual candidate H2, two late-broadcast
messages and incomplete coverage when run logs exceeded the old file caps.

The optional `startup-file-logs.json` v4 report selects the same two fixed paths
from each previously inspected owned node. Error files use the bounded whole-file
reader so a small file's first complete record is retained. A run file in a
positively observed running, unpaused, non-restarting and non-dead container uses an exact
`docker container exec <owned-id> /bin/busybox tail -c 32768 -- <fixed-path>`
command. Other validated run-file state summaries select the original bounded
`docker container cp <owned-id>:<fixed-path> -` reader because exec requires
a running container. There are at most eight file commands. There is no shell,
follow mode, configurable path, new mount or host
destination. Applet availability is checked by the actual command outcome.

Each command keeps its five-second deadline and fresh resource guard. Tail stdout
is capped at 32 KiB and stderr at 4 KiB, independent of the full log's size.
No TAR is transported for a tail. The first line and any unfinished final
line are discarded conservatively, even when the file fits. Window byte
accounting, a raw-window pin, bounded classifications and allowlisted source
coordinates are exported; raw text and arbitrary reasons stay outside the index.
An error file's classified window starts at byte zero and discards an unfinished
final line. Its window accounting and content pin are separate from the TAR
transport pin; no raw TAR or text enters the public index.
Per-file counts describe selected complete records, never whole-file coverage
or proof that no error occurred. The two configured handlers can duplicate errors.

The whole-file method retains the original 64 KiB TAR transport bound and
32 KiB decoded-file bound; it refuses a larger file without extracting it.
It does not promise a recent window for stopped nodes. The selected method is
recorded per file and bound to its fixed kind and prior owned inspection. An intervening exit
keeps the first failure; there is no second read, restart or unpause. See the
[state-selection record](../../docs/owned-stopped-node-file-logs.md) and
[small-error follow-up](../../docs/owned-small-error-file-logs.md) for the limits,
the observed single-record omission and the distinction between controls and real execution.

The reader binds a tail's window pin directly to the complete command stdout pin,
the prior owned inspection, role/kind and command order before cleanup. Nonzero,
incomplete or unavailable reads supply no parsed data. The v1 whole-file, v2 tail
and v3 state-selected readers retain their original bounds, method rules and report shapes.
No format independently replays omitted text or supplies header authority.
The startup log reader uses the same scope after the initial readiness refusal.
Another signed fixture requires separate source-specific authorization.

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

With a version-2 or version-3 terminal record, a successful consumer comparison or a
closed-run gateway mismatch also requires the opening BatchEntry proof, the
H2/H3 signature command receipts and the successful configuration and deposit
command receipts. The reader checks the fixture receipt bindings, exit codes
and bounded stream digests. Fixture streams stay out of the archive.
Version 3 requires an opening absence proof before a completed comparison.
It also binds a present opening proof to a refusal before signature checks and
fixture commands. The reader reviews prior versions under their recorded rules
and verifies the stages reached by each early failure.

If the version-3 native command ended with incomplete output after a closed
capture, `recorded_interrupted_capture` rechecks the retained input pins,
parent-slot schedule, context and all three proofs against the same captured
root. It checks the typed rows against the selected descriptor and preserves
the actual CLI exit. Missing or invalid membership leaves the proof check
unverified. The review streams the original archive and keeps the run's
`UNKNOWN` terminal and review exit 1. Accepted header authority and the
completed gateway comparison still require the native consumer result.

When a version-3 fixture configuration or deposit command times out, the reader
can expose the actual exit and elapsed time from its bound start and completion
receipts. A deposit timeout also requires the successful configuration receipt.
Transaction submission stays unverified when the command output is incomplete.

Add `--include-resources` to either archive review command to compare retained
command durations with sampled runner disk use. The optional `setup_commands`
field reports the node image build, executor image build and npm installation
where start and completion receipts are available. The `fixture_commands` field
reports configuration and deposit. Each command observation preserves the actual
exit and output completeness, with its completion digest. The reviewer checks
the command start bindings and disk sample arithmetic. Missing observations
remain absent. Command times describe individual subprocesses. The sampled disk
peak describes the runner as a whole. The review reads the original archive in
place and preserves its terminal outcome. Existing calls without this option
keep the same output and exit codes.

After a configuration or deposit timeout with a quiescent process group, the
reviewed reference-gas runner can retain the opening producer-slot observation.
Configuration requires the three owned producers and the RPC node. Deposit
also requires the executor and gateway. The runner stops all selected services
except the RPC node, captures one bounded RPC frontier, then closes the RPC
node. The pinned read-only oracle makes one in-place ledger read for the exact
H2 and H3 hashes and binds the captured frontier separately. The diagnostic
uses a 120-second work deadline within the original budget and retains the
existing cleanup reserve.

After a deposit timeout, the runner can also read the selected BatchEntry
at the immediate v3 parent of the frozen frontier. The target must come
after the opening block and link to the frontier's parent hash. The
runner verifies the bounded proof against that header's StateRoot.
If the BatchEntry is present, it also tries the domain record and domain
config proofs under the same root. A complete set is checked against the
selected ABI and source rules. An absent BatchEntry or unavailable
companion proof still yields the verified BatchEntry observation.
After all three proofs pass, one bounded frontier batch read can compare
all 17 stored fields with the proven BatchEntry. The comparison records
either a match or a mismatch. The `isFinalized` value remains the frontier
DTO's unauthenticated hint. An unavailable or malformed DTO leaves the
three-proof observation intact. The version-2 diagnostic includes the
comparison and its exact request and response. Version 1 remains readable.
The proof and gateway observation uses at most five additional RPC reads
within the original diagnostic deadline. It runs after producers and clients
have stopped.

The selected responses are retained with their request and command
receipts only after the owned services close and the opening oracle
reports the same frozen frontier. The archive reader rechecks the header
link, derives the keys locally and checks the proofs and any complete
typed context.

Three checked witnesses can support a native replay. One more bounded read
gets the header range from the opening anchor through the same frozen
frontier. After the RPC node closes, the read-only oracle calculates the
finite producer schedule for that range. The compiled CLI checks the
configured headers and consumes the typed query using the same witnesses.
The temporary provider document is rebuilt from the recorded responses and
linked by its byte length and SHA-256 digest. The archive keeps the original
inputs, schedule and completed CLI output for an independent recheck.

The replay's version-2 record references the verified H2/H3 request and output
from the opening authorization. Later reads start at H4 under the same closed
ledger and frozen frontier. Archive review checks that the full schedule uses
the exact opening references, then verifies the later requests and outputs in
order. The opening remains reviewable if a later read fails. The earlier replay
formats with a separate full-range oracle read remain readable.

A version-2 observation supplies the gateway response for comparison. If
that read yields no usable response, the replay uses the three proofs
with gateway comparison disabled. The archive retains the exact attempted
gateway request and reports zero compared fields and a null match. This
mode uses the same deadline and six-read ceiling. A completed typed result
in this mode leaves the required gateway comparison open.

The native replay is supplemental to the original timeout. Its comparison
is recorded separately and the terminal outcome remains `UNKNOWN`.

Archive review binds the oracle, original receipts, stopped service set,
frontier and both historical parent slots to the recorded timeout stage. The
terminal outcome remains UNKNOWN. Header acceptance and transaction submission
require their own evidence.

For the reviewed reference-gas devnet source, a timeout can retain
`fixture-configure-progress.json` or `fixture-deposit-progress.json`. The
configuration report records an ordered subsequence because the pinned CLI
can skip settings already present. The deposit report records the ordered
prefix of its fixed steps. Both use recognized, complete lines and retain the
stdout pin. Raw stdout and stderr stay private. An empty list means the runner
captured no recognized labels. A null list means the captured stdout was
unavailable for validation. The archive reviewer binds the diagnostic to the
matching command receipt. The terminal outcome and transaction submission
status retain their existing evidence requirements.

Exit 0 reports `RECORDED_CONSUMER_BYTES_MATCH`. This is agreement among the
retained records and independently recomputed bytes. The original run identity,
native signature verification, producer authority and any selected-network
acceptance retain their own evidence requirements. Exit 1 reports an intact
archive with a recorded failure, refusal or unknown outcome. Exit 2 reports a
refused or incomplete inspection.

When a failed, refused or incomplete run retains the opening response, the
reader checks its completed command and start receipts and recomputes the
three linked header hashes. The report includes the independently checked
H1, H2 and H3 identities, versions, timestamps and advertised roots as a
candidate observation. It checks the exact request when the archive indexes
that request and returns a null request pin for historical response-only
records. The terminal outcome stays intact. Signature and producer
authorization still belong to the accepted-header path.

The runner retains the validated opening's request and response in the same
evidence index before transporting either query component. A refusal during
query-input preparation can therefore retain both records for offline review.

After the consumer runs, the controller can retain a complete exit-1 or exit-2
CLI report. It validates the fixed report schema, error category and header
diagnostic before selecting the original stdout. The reader binds those bytes
to the exact start and completion receipts and returns the recorded failure
with exit 1. The record describes the CLI outcome while the consumer
comparison remains empty.

A gateway-field refusal can follow a complete exit-0 CLI query. With confirmed
runtime closure, the reader reuses the verified opening and rechecks the
command receipts, three membership proofs, typed rows and 17 stored fields.
An independently reproduced mismatch adds `recorded_gateway_mismatch` to the
recorded refusal, still with exit 1. If closure remains unresolved, the reader
checks member digests and retains the opening observation and terminal outcome.

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
python3 -I -B tools/owned-devnet-query/fixture_progress_test.py
python3 -I -B tools/owned-devnet-query/review_test.py
python3 -I -B tools/owned-devnet-query/node_diagnostics_test.py
python3 -I -B tools/owned-devnet-query/node_file_logs_test.py
```

Use the approved task-storage manager for local qualification, with its owned
scratch directory supplied as `TMPDIR`. The tests use synthetic archives,
regular temporary files and benign child processes with anonymous pipes. They
also exercise system curl against a two-request synthetic TCP server on an
OS-selected loopback port, joining its owned thread before completion. It
contacts no node or external endpoint and creates no on-disk FIFO, symlink or
socket fixture. POSIX process-group tests
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
