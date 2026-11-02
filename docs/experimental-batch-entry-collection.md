# Experimental BatchEntry candidate collection

The existing `fetch-bundle` binary has an explicit, read-only collection mode:

```text
fetch-bundle experimental-batch-entry --rpc <explicit-http-or-https-url> \
  --chain-id <selected-non-mainnet-chain> \
  --anchor-height <selected-anchor-height> --anchor-hash <selected-anchor-hash> \
  --height <selected-query-height> --header-hash <selected-query-header-hash> \
  --tip-height <selected-tip-height> --tip-hash <selected-tip-hash> \
  --domain-id <selected-uint32-domain> --batch-id <selected-uint64-batch> \
  [--compare-gateway] [--timeout <duration>]
```

It emits the version-1 provider document consumed by the separate
[offline BatchEntry query](experimental-batch-entry-cli.md). Collection success
means that the selected bounded reads completed and their transport shapes and
local identities matched. It accepts no signature, producer schedule, network
activation, state root, proof, typed row or finality claim. It writes no verifier
state and starts no wallet, signing, transaction or live deployment.

## Select the inputs before acquisition

Every endpoint, height, hash, chain, domain and batch is required explicitly.
Hashes must be nonzero, canonical lowercase 64-character hex. Domain and batch
remain native uint32 and uint64 values. Mainnet chain 1 is refused. Duplicate,
missing, malformed or positional arguments refuse before client construction.
The native command's RPC environment variables and defaults are not consulted.

Select the anchor, query and tip from the reviewed configuration and local
request. Collection does not choose the latest frontier, discover a trusted
checkpoint or construct a producer schedule. The independently selected
genesis, activation boundary, node revision, finite schedule, runtime identity,
policy and two context pins remain inputs to the offline verifier. Agreement
with these selectors does not authenticate how they were chosen.

The collected range is exactly `(anchor_height, tip_height]`. It must contain
the query height, remain contiguous, use the selected chain and link from the
selected anchor hash. Its query and tip hashes must match the local selection.
The existing v3 decoder checks each raw row's encoding and hash projection.
The original node data bytes and content order are retained; a data hash cannot
reconstruct those bytes. The collector does not verify header signatures or
producer authorization.

It derives the 35-byte Settlement `BatchEntry` storage key locally from the
fixed experimental Settlement address, domain and batch, and passes that full
key to `ledger.getProof(height, key)`. It does not send the already hashed
32-byte SMT path through another key hash. The returned `root`, `value` and
`proof` are bounded candidate data. In particular, the provider's root is not
verification authority.

With `--compare-gateway`, acquisition also reads
`embedded.settlement.getBatch(domain, batch)`, checks its selected IDs and
retains its exact DTO. Its `isFinalized` is still an untrusted frontier hint.
The offline query must also select `--compare-gateway`; only after proof
verification does it compare the stored fields. This read cannot establish
historical finality, Settlement-delay satisfaction, funds release or receive.

## Bounded reads and output

| Boundary | Limit |
| --- | ---: |
| Header range | At most 4,096 rows, paged at 1,024 per request |
| All complete header RPC responses combined | 8 MiB, including whitespace and envelopes |
| One momentum row / raw data / content entries | Existing 256 KiB / 16 KiB / 1,024 limits |
| Complete proof RPC response | 32 KiB |
| Complete optional gateway RPC response | 32 KiB |
| Complete emitted provider document | 8 MiB |
| Overall deadline | Default 30 seconds; explicitly positive and at most 10 minutes |

These are local unsupported-work boundaries, not protocol parameters or
representative hardware measurements. A range that fits its RPC budget can
still be refused when the complete provider document exceeds its own cap.
There is one deadline for the entire selected acquisition and no retry.

No provider document is returned on cancellation, an unavailable result, a
later-page error, identity mismatch, invalid response or any exceeded bound.
Unavailable witness data is not converted into typed absence or zero.
Diagnostics use fixed categories and omit supplied endpoints and raw causes.

| Exit | Meaning |
| --- | --- |
| 0 | Complete candidate document, or requested help |
| 1 | Acquisition failed; no candidate document |
| 64 | Invalid invocation; no RPC processing |
| 70 | Output failed or was short; any partial bytes are unusable |

Capture stdout with an explicit cap in registered disposable task scratch.
Check the actual exit and capture completeness before preserving the document
or supplying it to the offline query. File existence alone is not success:
shell redirection may create an empty file before acquisition begins. A short
or failed output write is not retried. Keep configuration and request inputs
separate from this provider document; do not derive their expected pins from
the collected candidate.

## Qualification boundary

The compiled regression collects existing recorded chain-100 public header
signatures through a loopback RPC fixture, then passes its candidate document
to the unchanged offline query. That query accepts the configured header
stage and rejects the deliberately incompatible witness. It performs no RPC
read and leaves all input files unchanged. Separate transport controls cover
pagination, complete byte caps, full-width selectors and unavailable results.

These controls establish the collection-to-refusal workflow, not a successful
selected-network state query. A matching positive `BatchEntry` witness bound
to an accepted header on the selected network remains missing. D0-D3,
representative R1 measurements, activation and release gates remain open.
Native v1/v2 inclusion and production state-value verification remain separate.
