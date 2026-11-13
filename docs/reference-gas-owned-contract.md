# Explicit reference-gas owned-query contract

The existing `tools/owned-devnet-query/contract.json` keeps its original bytes,
source cohort, prepared metadata and qualified inputs. The separate
[`reference-gas-contract.json`](../tools/owned-devnet-query/reference-gas-contract.json)
selects the new source cohort and matching Linux consumer/oracle artifacts.
This is preparation for the first actual chain-69 BatchEntry query, not a
record of that query or permission to start the owned fixture.

## Exact selection

| Input | Reference-gas selection |
| --- | --- |
| Contract format | `owned-devnet-batch-query-contract/v2` |
| Contract SHA-256 | `6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31` |
| Devnet | `cf1c9c0e0f0ca3b257bdbd019c5589c2c27f748f` |
| Node | `2835c436b197fece5c76adf4ba8dc1decca2e3ea` |
| Executor | `a14bf0e08dad8eabeb1a0e0add9bbaf1e2adac9f` |
| Contract SDK | `bc1548d75473797f24bb3eb79f5594969c596e39` |
| TypeScript client | `e9e02d8b12fa4053b8d19b1a4d6257d933bfdc0a` |
| TypeScript SDK | `75cd2565bd388c1df6b441bfcc1670e8da483c77` |
| Qualified consumer/oracle source | `7493c5929c7dbcfb29f94be521f7533d90a1a687` |
| Consumer run / artifact | `43355485323` / `14005638937`, attempt 1 |
| Closed-parent oracle run / artifact | `43355485426` / `14006370285`, attempt 1 |

The two selected artifacts come from the completed
[general main CI](https://github.com/edgepillar/zenon-spv/actions/runs/43355485323)
and [closed-parent main CI](https://github.com/edgepillar/zenon-spv/actions/runs/43355485426).
That source has its own ten-job, 22-selected-archive qualification. Its oracle
passed complete source-H1 controls and the compiled empty-request refusal on
Linux, macOS and Windows. This selection does not rerun those node builds or
turn them into positive selected-ledger or consumer evidence.

The new devnet changes only `package.json`, `package-lock.json` and `sources.txt`
relative to the original selected devnet. Their raw bytes were checked against
the three Git blobs in its retained tree. The new lockfile selects the updated
TypeScript SDK; the client is unchanged. The console remains outside this
six-service experiment. Node/executor source differences and original-source
conformance remain in the [source cohort record](reference-gas-source-cohort.md).

The original genesis bytes/H1, chain 69, H2 anchor height, source-conditioned H3
expectation, domain 1, batch 0, three proof keys and domain semantic expectations
remain explicit. Actual H2/hash, H2-to-H3 transition and finite producer
authorization still require the selected owned capture. No source expectation
is relabeled as an observed network transition.

## Metadata and context separation

The new descriptor is
[`prepared-devnet-reference-gas-consumer-selection.json`](../internal/testdata/conformance/prepared-devnet-reference-gas-consumer-selection.json),
SHA-256 `d77cca86d4624e691917ee0d2b94dc70c4bf0e29f87316ea89513c72209a6b48`.
Its matching
[`prepared-devnet-reference-gas-query-profile.json`](../internal/testdata/conformance/prepared-devnet-reference-gas-query-profile.json)
is SHA-256 `ff7706d01201c50c9f2401e59ab0f6e73e044b1977bbd4ccd111b6d1ce8acbb3`.
The runtime identity is the descriptor digest, including its canonical newline;
it does not authenticate runtime or STF execution.

The header's exact node selection determines its exact executor/Contract-SDK
pair in both the independent fingerprint framing and detached consumer-context
comparison. Unknown nodes have no original-cohort fallback. The changed source
and metadata identities produce separate context/request pins. An original
request, checkpoint, profile or artifact cannot be substituted into the new
selection. Proof/ABI limits, canonical rules, resource budgets and trust flags
retain their original meanings.

## Preparation and retained-input review

The model command is offline and reports `PLAN_ONLY`:

```sh
python3 -I -B tools/owned-devnet-query/model.py \
  --contract tools/owned-devnet-query/reference-gas-contract.json
```

Inspect an already retained, verified original Linux ZIP in place:

```sh
python3 -I -B tools/owned-devnet-query/inputs.py \
  --contract tools/owned-devnet-query/reference-gas-contract.json \
  --component consumer --archive "$SPV_ARTIFACT_ZIP"
```

Use `parent_oracle` for the other selected ZIP. These commands write no
extracted binaries. The compressed payload, decoded TAR and selected binaries
have separate pins in the contract. Keep the actual source/run/attempt/artifact
acquisition and qualification evidence; archive equality is not authenticated
distribution. Reuse verified retained inputs instead of downloading or copying
them again.

The retained-result `review.py` commands accept the same explicit `--contract`
option in addition to the separately expected contract digest. Their original
default remains `contract.json`, preserving original recorded-result review.
The three preparation jobs hash both contracts and both descriptor/profile
pairs. The Linux host sample uses the reference-gas contract's unchanged
19 GiB admission requirement; a configured budget is not measured enforcement.

For a future separately authorized dispatch, the existing acknowledged contract
digest selects exactly one of the two reviewed filenames before artifact
transport or engine contact. An unknown digest, a filename/cohort mismatch,
mixed source set, different artifact selection or expired input is refused.
There is no latest lookup, fallback or implicit reset of existing devnet data.
Preparing this contract does not dispatch a workflow, start services, execute
the deposit fixture, sign or submit a transaction.

The next exit remains the actual closed-ledger/header-bound three-row CLI
consumer and its retained hosted result. Representative R1 data, node recovery,
independent review and authenticated distribution keep their separate gates.
Production state proofs and irreversible settlement remain NO-GO.
