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

This finite synthetic corpus is compatibility evidence. Python/Go agreement
does not establish exhaustive parser equivalence, independent human review,
authenticated report delivery or trust sources, canonicality, consensus
finality, network activation, state-value proofs or a real consumer/network
pilot. The checker is not a public SDK or an accepting alternative consumer.
