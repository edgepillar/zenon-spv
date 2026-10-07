# Independent consumer decision checks

`tools/check-query-consumer.py` compares a trusted compiled Go query consumer
with a separately implemented Python reference. The reference uses Python JSON
decoding, explicit diagnostic field shapes and integer ranges, and Python
SHA3-256 over the published context encoding. It does not import a Go parser,
encoder, validation helper, result or target selector.

The complete corpus is selected before invoking the executable. Each case pins
the expected process status and exact fixed summary bytes. Both implementations
must agree with those decisions, not merely with each other. Inputs include
context schemas 1/2, commitment and segment batches of 1/2/256 targets, reversed
rows and uint64 identities above the JavaScript exact-number range. Controls
cover full target identity, missing/extra targets, per-row guarantees, explicit
trust allowances, context/tip mismatches, actual process failure, ambiguous JSON,
nullability, Unicode escapes, integer overflow and selected input boundaries.

The original 98 cases remain byte-for-byte pinned. An additional 640 cases use
32 deterministic programs: both commands, both context schemas and eight fixed
seeds. SHA256 with a versioned domain derives synthetic identities before either
implementation runs. Each program has two matching forms and 18 independently
specified refusals, giving 738 total comparisons (88 matches and 650 refusals).
The generator does not use a Python or Go decision to select an expected result,
discard a case or adjust inputs. This is a finite selection, not random fuzzing
or exhaustive coverage of all combinations.

Programs vary 1/3/17/64 targets, separate target/result ordering, uint64 identity
boundaries, segment positions that share an index but have distinct block
indices, context profiles/checkpoints/producer sources and guarantee/trust
sets. Equivalent wire forms change key order, whitespace, escaped keys and
Unicode spelling. Mutations affect the last row, target counts/duplicates,
tip/context pins, guarantees/trust, integer ranges and escaped duplicate keys.
Selected nonzero verifier-status inputs test failure precedence over malformed
JSON. These synthetic reports satisfy or violate the consumer diagnostic
contract; they are not evidence that the verifier or a real network produced
these contexts, guarantees or account blocks.

Run from a clean reviewed source checkout, with a trusted Go/Python toolchain:

```sh
python -I -B tools/check-query-consumer_test.py
go build -trimpath -o consume-query-report ./tools/consume-query-report
python -I -B tools/check-query-consumer.py --consumer ./consume-query-report \
  --source-revision "$(git rev-parse HEAD)"
```

On Windows, use the `.exe` executable path. The checker creates private temporary
regular files, captures each actual child status with a ten-second deadline,
checks exact stdout and empty stderr, verifies the input bytes remain unchanged,
and removes its files. The caller must trust the selected executable: this is
not an isolation mechanism for malicious binaries. The reference models bytes
and decisions; filesystem replacement, invocation ambiguity and process lifetime
remain covered by the existing native Go controls rather than this corpus.

The report includes caller-asserted source identity, oracle/executable byte
hashes, case identifiers and outcomes. It omits temporary paths, raw diagnostics
and selected input values. The selected executable bytes must remain unchanged.
CI runs the controls and compiled comparison on Linux, macOS Intel and Windows;
the source-bound report is preserved in each actual job log. The ordinary
candidate artifacts and offline reports continue through their existing checks.

Successful reports distinguish selected cases, reference comparisons, actual
consumer invocations, completed consumer comparisons, skipped cases and cases
excluded by an explicit selection. The default run selects all 738 and skips
none. A timeout is an attempted invocation without a completed comparison; a
wrong result is a completed comparison that fails the run. No success report is
emitted for a partial run. Failures expose only a synthetic case identifier,
a fixed failure stage and counters; child output and operational paths remain
private. Replay the exact selected case from the same source and executable:

```sh
python -I -B tools/check-query-consumer.py --consumer ./consume-query-report \
  --source-revision "$(git rev-parse HEAD)" \
  --case generated_segment_v2_seed000000ff_account_hash
```

A replay reports one selected comparison and 737 not selected, rather than
claiming a complete corpus run. Preserve a reproducible mismatch as a regression
case and investigate it; do not retry, remove or relabel failures to qualify an
unchanged candidate. The selected seeds/variant names, source and input hashes
make every generated case reproducible without saving raw operational inputs.

This finite synthetic corpus is compatibility evidence. Python/Go agreement
does not establish exhaustive parser equivalence, independent human review,
authenticated report delivery or trust sources, canonicality, consensus
finality, network activation, state-value proofs or a real consumer/network
pilot. The checker is not a public SDK or an accepting alternative consumer.
## Compiled node-derived workflow

`tools/check-node-query-consumer.py` connects the independent consumer oracle
to actual reports and process completions from a trusted compiled `zenon-spv`.
It uses the unchanged `contract-batches.json` and `delayed-inclusion.json`
corpora generated by pinned go-zenon commit
`3a4131e63881058b6ce2ee81d3a41d0033fafc99`. These are synthetic node-generated
chains, including signed account blocks and momentum headers. They are not
historical live-network observations or independent operator evidence.

Before running either executable, Python selects all targets, confirming
heights, verification tips, default policy limits, and explicit retention
settings from the pinned corpus and published settings. It computes context
schema 1 and 2 fingerprints with the existing independent SHA3 encoder. The
mixed v1/v2 program also supplies an explicit synthetic activation profile
and an independently encoded producer schedule. Their inclusion in a context
pin identifies the chosen inputs; it does not authenticate activation or an
elected producer. The runner never obtains its expected fingerprint or target
identity from `inspect-config`, Go helpers, candidate reports or peer agreement.

The complete finite matrix has **60 comparisons: 20 matches and 40 refusals**.
It executes **30 verifier processes**, including six explicit private state
creation/extension steps. Direct inclusion covers legacy and explicit K=16
retention; mixed-height inclusion covers K=16, W=6, two account segments and
three separate confirming momentums. Each accepting command is rerun in a new
process against persisted state. Reordered diagnostic rows still match;
changed expected targets/context, a missing row and an altered context field
refuse. A real failed context-pin process refuses both its own diagnostic and
an earlier ACCEPT report passed with that failed process's actual exit code.

At tip 5016, the 5011 targets lack W=6 subsequent headers. They become eligible
at 5017. At 5018, height 5003 is the oldest retained header and all six targets
remain queryable. At 5019, height 5003 is evicted: commitments at that height
refuse and dependent segment rows cannot bypass the refused parent. The
runner checks these selected per-row reasons as well as actual process exits.
Every query and consumer invocation must preserve state and configuration
bytes; only the six explicit private writer steps may advance state.

Run locally with binaries built from the selected checkout:

```sh
go build -mod=readonly -trimpath -o /tmp/node-reference-verifier ./cmd/zenon-spv
go build -mod=readonly -trimpath -o /tmp/node-reference-consumer ./tools/consume-query-report
python3 -I -B tools/check-node-query-consumer_test.py
python3 -I -B tools/check-node-query-consumer.py \
  --verifier /tmp/node-reference-verifier --consumer /tmp/node-reference-consumer \
  --source-revision "$(git rev-parse HEAD)"
```

Use an owned temporary directory for the binaries; Windows binaries require
the usual `.exe` suffix. The runner creates and removes its own private
temporary state, bundles and expectations. Its report contains fixed case
identifiers, counts and hashes, never raw child diagnostics or temporary paths.
It records both executable byte hashes and sizes. The source revision remains
caller asserted. Native CI runs this matrix against the ordinary binaries
already exported and checked by the offline pilot; qualification must also
bind the logged hashes to the actual exported artifact payloads.

The successful node workflow also records all 90 actual child completions:
30 verifier and 60 consumer processes. Each record contains only its fixed
case identifier, role, actual exit status, stdout/stderr byte counts and SHA-256
hashes. Completion is recorded before output checks, JSON parsing or file
rereads. A timeout or launch failure records an attempted, incomplete process
with no asserted exit status or completed output hashes.

After execution begins, malformed diagnostics and input, state, configuration
or final pin-read failures emit a structured refusal with the accumulated
counts and process records. A temporary-directory cleanup failure preserves
the primary refusal and records cleanup separately. Cleanup alone also refuses;
cancellation and unexpected programming errors retain their original exception.
Completed comparison counters do not assert a matching decision: a wrong
consumer result still fails without adding a successful case. Partial runs
never emit a successful qualification report. Raw child output, exception text,
arguments and temporary paths remain omitted from these records.

Twenty-two Python controls pin selected context/schedule bytes, preselection, delayed
target mapping, corpus corruption, actual process status, input mutation,
completed mismatches, incomplete child runs and evidence preservation across
malformed output, later I/O failures and cleanup. Every child has a 15-second
deadline and completed stdout must fit the consumer's 4 MiB report bound.
This is a trusted-binary conformance runner, not a malicious executable sandbox
or a claim that child output capture has a hard memory limit. It uses no RPC
or network collector and leaves the original 738 synthetic consumer cases
unchanged. Passing these checks adds no canonicality, consensus finality,
network activation, state-value proof or independent human review.
