# Read one L2 storage path from a retained owned batch

The reader uses the Phase 1 WASM contract-storage path convention and accepts
one caller-selected contract ID and raw local key. It reviews the original
successful hosted batch archive before selecting its L2 `PostStateRoot`.
The L1 header height, hash and query context are explicit inputs. The
contract, source revision, run, attempt and original archive remain bound by
the existing hosted-result reader. The supplied Actions metadata must come
from a separately selected acquisition. [Phase 1 state model](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/phase-1/SPEC.md#13-state-model)

The L2 path is `SHA3-256(contract_id || local_key)`, with a 32-byte
contract ID and at most 32 bytes of local key. The verifier uses that
path directly. A recorded `zeno_getProof` result must name the same domain,
numeric batch, post-state root and single path. The reader checks the
canonical proof and preserves absent as JSON null and present-empty as
the empty hex string. Its local value ceiling is 4,096 bytes and the
recorded result ceiling is 64 KiB. Gateway `verified` is a provider field.
The proven batch supplies the post-state root. [Pinned gateway API](https://github.com/Zeno-L2/zeno-executor/blob/a14bf0e08dad8eabeb1a0e0add9bbaf1e2adac9f/docs/gateway-api.md)

## First recorded read

[Attempt 1](https://github.com/edgepillar/zenon-spv/actions/runs/46148797542/attempts/1)
records an accepted chain-69 BatchEntry for domain 1, batch 0 at L1
H126. That entry commits the zero L2 post-state root. The reader checked
absence at local key `0001` for the explicitly declared `11…11` contract-ID
probe. These bytes select a test path. The source did not identify them as
the deployed vault. The path was
`60b8073d7cee456c7eb5e738b72fc6c84227560337ee22a52ff7136bd6588789`.
The locally derived canonical proof was 99 bytes with SHA-256
`7dc70212489476ae922164f665ae58ceb9abc5a31d81eb148b665fce8dde34c8`.
The selected H126 read succeeded and changing the requested height to H127
refused to use the archive. The check reused the original ZIP and made zero
RPC requests. [Accepted BatchEntry record](typed-query-evidence-2026-11-27.md#successful-owned-batchentry-query-on-28-november)

Run the bounded reader with the retained original ZIP and metadata files:

```sh
python3 -I -B tools/owned-devnet-query/review_l2_storage.py \
  --archive "$ARCHIVE" --run-metadata "$RUN_METADATA" \
  --jobs-metadata "$JOBS_METADATA" --artifact-metadata "$ARTIFACT_METADATA" \
  --contract tools/owned-devnet-query/reference-gas-renewal-1-contract.json \
  --expect-source-revision c64f5453521f4f334bcb6205bbe00d9adfed3980 \
  --expect-contract-sha256 7af671795d7a9a97d57432ce1b38d490580340e7b844a083298dbcaf8a5c4fe0 \
  --expect-run-id 46148797542 --expect-artifact-id 15265652595 \
  --expect-height 126 \
  --expect-header-hash fe3bca70f680be2400fdf2082d7e9c314d11aafbcca7f36d98cf20ecf44a5a28 \
  --expect-query-context a77be5099b5e10d71da0a6f2b3625de7080ba9905c3a46d2dc0991adb65ee32b \
  --contract-id 1111111111111111111111111111111111111111111111111111111111111111 \
  --local-key-hex 0001 --empty-root
```

Use `--proof-result` with a separately retained one-path result object for a
gateway witness. The numeric batch and independently derived path are set in
the collection request. An unavailable or pruned witness remains a refusal.
The explicit `--empty-root` mode only accepts a proven zero commitment and
reports the proof origin as `local_empty_commitment`.

## Read the storage path in the native CLI

A caller with verified configuration and proofs from a different selected
batch can use the ordinary read-only three-row CLI. The two L2 file options
are paired and belong to the query command. Select the L1 request, both
context pins, and the contract ID and local key independently of the proof
provider. The storage request file contains exactly `contract_id` and
`local_key_hex`, both lowercase hex. The ID is 32 bytes and the local key
is at most 32 bytes. For a typed vault key, use the pinned vault interface
and its storage-key codec before preparing this file.

```sh
zenon-spv query-experimental-batch-context \
  --config "$CONFIG" --request "$L1_REQUEST" \
  --expect-header-context "$HEADER_CONTEXT" \
  --expect-query-context "$QUERY_CONTEXT" \
  --l2-storage-request "$L2_REQUEST" --l2-proof-result "$L2_WITNESS" \
  "$L1_PROVIDER"
```

The L2 witness file contains the result object from one numeric-batch
`zeno_getProof` read. The native CLI first verifies the three L1 rows with
the configured header and then checks the one path against the
`PostStateRoot` of that exact proven BatchEntry. The selected domain, batch,
root and locally derived path must match the result object. A successful
report adds `l2_storage` with the bound identity, presence, raw value and
proof digest. Present-empty is `""` and proven absence is `null`.
A JSON null witness is unavailable and returns exit 2. A mismatched identity
or invalid proof returns exit 1. These outcomes carry no typed result or L2
storage claim. The optional inputs are capped at 2 KiB and 64 KiB. This
path has the same experimental trust assumptions and performs zero RPC
requests. [Three-row CLI contract](experimental-batch-context-query.md)
[Gateway proof response](https://github.com/Zeno-L2/zeno-executor/blob/a14bf0e08dad8eabeb1a0e0add9bbaf1e2adac9f/internal/gateway/api.go#L517-L532)

The native replay used the original chain-69 L1 rows from attempt 1 and a
locally derived canonical L2 proof for the proven empty commitment. It
reproduced the original three-row result with all 17 gateway fields
matching. The compiled CLI accepted the selected probe's absence, rejected
the same proof with a different batch identity and refused a null witness.
The nonzero-batch membership and present-empty controls use independent
single-leaf byte oracles. A recorded positive vault witness remains a
separate input. [Chain-69 artifact](https://github.com/edgepillar/zenon-spv/actions/runs/46148797542/attempts/1)

## Collect and read one Phase 1 vault balance

Select the deployment independently of the gateway proof. This reader
uses the pinned SDK example vault interface. The operator supplies the
contract ID of a deployment with that interface and selects the L1
account and token before fetching proof bytes. The storage proof binds the
selected path to a root. Deployment provenance and the installed code's
interface are separate inputs.
[Pinned vault interface](https://github.com/Zeno-L2/zeno-contract-sdk-rs/blob/bc1548d75473797f24bb3eb79f5594969c596e39/examples/vault/artifacts/vault.interface.json)

Use this alternate storage request shape with the same
`--l2-storage-request` option. All values are lowercase hex with no
prefix. The contract ID, L1 account and ZTS identifier use 32, 20 and
10 bytes respectively.

```json
{
  "contract_id": "<64 hex digits>",
  "vault_balance": {
    "account_hex": "<40 hex digits>",
    "token_standard_hex": "<20 hex digits>"
  }
}
```

Select the same numeric domain and batch used by the L1 query. Collect
one candidate proof for the chosen path.

```sh
fetch-bundle experimental-vault-balance \
  --rpc "$ZENO_GATEWAY" --domain-id "$DOMAIN_ID" --batch-id "$BATCH_ID" \
  --contract-id "$CONTRACT_ID" --account-hex "$ACCOUNT_HEX" \
  --token-standard-hex "$TOKEN_STANDARD_HEX" > "$L2_WITNESS"
```

The collector derives the path and issues one bounded
`zeno_getProof(domainId, [path], batchId)` request. Use the witness file
after a successful process exit. An unavailable or pruned batch returns
exit 2 and supplies no witness. A response for a different batch, domain
or path is refused. In the offline CLI the accepted L1 `BatchEntry`
supplies the root, and the verifier derives the same path from the
separate request.
[Pinned gateway API](https://github.com/Zeno-L2/zeno-executor/blob/a14bf0e08dad8eabeb1a0e0add9bbaf1e2adac9f/docs/gateway-api.md)

The SDK maps the L1 account to
`SHA3-256("L1_CALLER:" || account)` and left-pads the ZTS with 22 zero
bytes to obtain the asset ID. The vault local key is
`SHA3-256(0x01 || caller_hash || asset_id)`. A successful typed report
adds `l2_storage.vault_balance`, which names the selected account, token,
interface digest and decimal `amount_base_units`. A present balance
requires exactly 32 bytes of big-endian unsigned value. A proven absent
leaf keeps `present: false` and `value_hex: null`, with a typed amount of
zero under the pinned vault interface. Missing witness bytes leave the
amount unavailable.
[Pinned caller codec](https://github.com/Zeno-L2/zeno-client-ts/blob/e9e02d8b12fa4053b8d19b1a4d6257d933bfdc0a/src/derive.ts#L21-L23)
[Pinned balance caller](https://github.com/Zeno-L2/zeno-devnet/blob/cf1c9c0e0f0ca3b257bdbd019c5589c2c27f748f/flows/lib.ts#L475-L480)

The compiled local check used the original H126 L1 evidence and a
locally generated empty-commitment proof served by a loopback gateway.
The collector and verifier matched the selected vault probe and returned
a typed zero for its proven absence. A changed token refused the
witness. A pruned batch supplied no proof. The present u256 control used
an independent single-leaf oracle, and a present-empty leaf refused the
vault value decoding.

The next consumer query is one vault balance stored in the contract's
`balances` mapping at an explicitly selected post-deposit batch. It needs
the exact vault ID from its deployment record, the local key derived under
the pinned vault interface, the selected batch's verified L1 commitment and
one matching gateway witness. The empty batch-0 result covers historical
absence at the probe path. Execution correctness, settlement, release and
spendability remain separate. [Pinned balance caller](https://github.com/Zeno-L2/zeno-devnet/blob/cf1c9c0e0f0ca3b257bdbd019c5589c2c27f748f/flows/lib.ts#L475-L480)
