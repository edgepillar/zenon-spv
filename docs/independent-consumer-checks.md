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
