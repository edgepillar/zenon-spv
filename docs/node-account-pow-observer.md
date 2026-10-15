# Recorded account PoW observer boundaries

`TestCompiledNodeAccountPoWObserver` runs the ordinary collector, retained-state
verifier, query consumer and observer against the immutable account PoW corpus.
It extends the [runtime and RPC controls](node-account-pow-boundaries.md) through
the actual read-only command pipeline. It changes no verifier acceptance policy.

## Selected inputs and complete inventory

The test pins `node-account-pow.json` to SHA-256
`560ff77f5fe092e99222399309da164c0539dec749e95b0e1788cd52fe30716f`
and node revision `c64ed6279ff1d07335dab0ac36156dec8b5b71e9`.
All 64 recorded method observations remain unchanged. The original signed account
fixture independently supplies the consumer target, anchor, profile, producer
schedule, retained headers, commitment evidence and context fingerprint before
collection. These are synthetic trust selections, not authenticated network inputs.

| Controls | Count | Required result |
| --- | ---: | --- |
| Original signed send, one observation per node method | 2 | Collection, inclusion/signature verification and selected consumption succeed |
| Changed difficulty or nonce with the original claimed hash | 62 | Collection fails, emits no partial bundle and starts no verifier or consumer |
| Same changed inputs with a coherent claimed hash | 62 | Collection succeeds; the unchanged signature rejects; consumption never starts |
| Missing retained committing header or collected proof, for both original methods | 4 | Verification refuses and consumption never starts |
| Different independently selected consumer target or tip, for both original methods | 4 | Consumption fails with the selected target/report mismatch |

The complete inventory is 134 controls. Coherent-hash controls replace only the
wire object's claimed hash using `json.RawMessage`, preserving every unsigned
64-bit difficulty, nonce and original signature byte. They generate no signature,
nonce search or new reference-node observation. Node method results never select
the expected inclusion or consumer result.

Every invocation checks exact read-only loopback requests, actual child exits,
absence of later children after a failure, the complete eight-field public
summary, private-input redaction, unchanged selected input files, absence of state
writer locks and removal of raw private files. Negative signature results are
distinct from missing-evidence refusals. Resource counters must agree with which
children actually ran; they are not production resource thresholds.

## Build cost and qualification

One fresh grouped build creates the four ordinary executables in this test's
private directory. All 134 controls use those exact files. No cross-test executable
cache, reference-node build, corpus regeneration or extra resource producer is
introduced. The existing basic/receive observers, all runtime/RPC tests, full
native suites and all 59 offline pilot scenarios remain required.

The dedicated native CI command is:

```sh
go test -v -count=1 -run '^TestCompiledNodeAccountPoWObserver$' ./internal/conformance
```

Qualification must bind the exact published source, all three native-platform
logs and the ordinary binary artifacts. Local execution alone does not qualify
hosted CI or a whole-pipeline speedup.

## Claims that remain separate

A matching work probe or node method cannot authenticate the original signature,
provide missing commitments or choose the consumer's trust inputs. Accepted
inclusion/signature observations establish neither account-PoW validity, execution
eligibility, state transition, state-value proofs, canonicality, consensus finality
nor network activation. Real authenticated histories, independently selected
consumer/network inputs, human review and authenticated release distribution
remain separate acceptance gates. No wallet, signing, transaction, live RPC,
deployment or runtime policy change is part of this test.
