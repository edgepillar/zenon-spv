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

The next consumer query is one vault balance stored in the contract's
`balances` mapping at an explicitly selected post-deposit batch. It needs
the exact vault ID from its deployment record, the local key derived under
the pinned vault interface, the selected batch's verified L1 commitment and
one matching gateway witness. The empty batch-0 result covers historical
absence at the probe path. Execution correctness, settlement, release and
spendability remain separate. [Pinned balance caller](https://github.com/Zeno-L2/zeno-devnet/blob/cf1c9c0e0f0ca3b257bdbd019c5589c2c27f748f/flows/lib.ts#L475-L480)
