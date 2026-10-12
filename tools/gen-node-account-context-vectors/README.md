# Actual node account context failure observations

This isolated module calls both `AccountBlock` and `AccountBlockTransaction`
at official node commit
[`c64ed6279ff1d07335dab0ac36156dec8b5b71e9`](https://github.com/zenon-network/go-zenon/blob/c64ed6279ff1d07335dab0ac36156dec8b5b71e9/verifier/account_block.go).
It exercises their shared `getContext` failure gate with synthetic recording
chain/store interfaces. The separate [transaction experiment](../gen-node-account-vectors/README.md)
returned opaque non-nil stores and did not execute this missing-account fallback.
The GPL node module remains separate from the MIT runtime. Executable build
information must match the selected module version/checksum with no replacement.

| Preserved input | SHA-256 |
| --- | --- |
| `account-segments.json` | `1faca6715c3865bae726a7a07f56ef2c43bd8a5a5c9816f618373312de43b048` |
| `node-account-context.json` | `5fa1dd0d1960d9d25ae1f1294d84e50034fb83fa5046f67fd7485b634aab18e7` |

The exact 50 calls select two existing first blocks, four context-shape profiles
and eight missing-account store profiles per block, plus one missing embedded
acknowledgement store. Each selection invokes both entry points independently.
Existing keys, signatures and claimed hashes remain. Shape mutations leave those
hash/signature claims unchanged; no signing or rehashing is performed.

All 38 returned errors and 12 selected programmatic nil-pointer panics are
retained. The missing-account fallback distinguishes a frontier at the required
previous height from an ahead frontier, a missing previous hash from a found
previous hash, and frontier errors from later lookup errors. It records every
lookup, address, complete identifier and hash in order. Embedded acknowledgement
lookup precedes account lookup; initial shape failures precede every lookup.

The nil global momentum, nil global account and nil returned frontier profiles
are synthetic interface/return-value faults. Their specific runtime panics do
not establish a remotely reachable input or a live-node vulnerability. Any other
panic, method call, error or validator success fails generation. Unimplemented
methods fail if reached; the experiment never reaches basic account checks,
transaction hash/signature checks, consensus or account execution. The returned
minimal frontier/lookup objects represent recording-store control inputs only.

The independent checker reconstructs all 50 complete account hash preimages,
wire fields, store plans, exact call traces and ordered errors from the selected
old input bytes and an independent finite inventory. Its corruption controls
include missing/reordered observations, lookup arguments, error precedence,
forged success, suppressed panic, nil/store changes and Boolean/float aliases.
No node, OpenSSL process, database, keys, signatures or network runs in the checker.
Native CI consumes this fixed corpus and retains its exact checkout-bound report
in the job log; the previous signature artifacts remain unchanged.

These failures cannot authenticate an anchor, context, producer schedule or
consumer target. Node missing-state errors are distinct from historical committed
account-header inclusion. Runtime validation, v3/state-value refusal, all prior
corpora and real consumer, network, independent-review and release gates remain
unchanged. Full account validation with actual store/consensus inputs is separate.

From this directory, with the selected dependency available:

```sh
GOWORK=off CGO_ENABLED=0 go build -mod=readonly -trimpath -o account-context-reference .
./account-context-reference ../../internal/testdata/conformance/account-segments.json > observations.json
```

From the repository root:

```sh
python -I -B tools/gen-node-account-context-vectors/check_test.py -v
python -I -B tools/gen-node-account-context-vectors/check.py
```
