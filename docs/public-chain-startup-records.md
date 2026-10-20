# Public Chain startup record identity

This finite M2 experiment extends the selected node at
[`9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/commit/9c71ae82fc983e16f914ae085d4034030c8ebe3b).
It uses ordinary Darwin ARM64 builds and real disk ledger, cache and state-tree
managers. Each case starts with its own unsigned source-genesis/A2 fixture and
already aligned cache/tree metadata. Only owned local fixture rows are altered.

The parent runtime tree is `cac9fa0446b0372ca37e9b15b0be2276f6d33cdf`.
The experimental candidate is `d56bf37a23ddf0ec0f8af2eca62be01bb6c54dbc`.
The [patch](../tools/gen-state-root-vectors/node-public-chain-startup-record-9c71-patch.json)
changes `chain/chain.go`: check manager availability, the ledger metadata's full
frontier identifier, the stored frontier's computed hash, and the configured
genesis's full identifier and computed hash before downstream initialization.
Missing records return errors. Existing decoder errors propagate. Start, Stop,
insert logic, disk format and the partial-SMT profile remain unchanged.

## Actual local observations

The [corpus](../tools/gen-state-root-vectors/testdata/native-public-chain-startup-record.json)
retains two complete ordinary processes, 75 events each, with 12 sequential cases
per process. Both processes exited zero; the observer records recovered API
panics separately. Four parent API panics become explicit candidate errors.
Five inconsistent parent records that returned Init success and tree readiness
are refused by the candidate.

| Owned fixture | Parent Init | Candidate Init |
| --- | --- | --- |
| Healthy A2 and clean manager reopen | Success, root available | Same result |
| Missing genesis row | Panic | Missing-genesis error |
| Genesis claims the expected hash at the wrong height | Success, ready | Genesis-identity error |
| Genesis timestamp changed under the original claimed hash | Success, ready | Genesis-body-hash error |
| Missing frontier row under nonempty ledger metadata | Error; consumes the configured genesis transaction's patch | Missing-frontier error; patch preserved |
| Frontier claims the wrong height | Success, ready | Frontier-identity error |
| Frontier claims the wrong hash | Success, ready | Frontier-identity error |
| Frontier timestamp changed under the original claimed hash | Success, ready | Frontier-body-hash error |
| Malformed genesis row | Decoder error | Decoder error |
| Malformed frontier row | Panic | Decoder error |
| Externally stopped ledger manager | Panic | Ledger-unavailable error |
| Externally stopped cache manager | Panic | Cache-unavailable error |

After each Stop, all three ordered raw KV images match their pre-Init images,
and the instance is unready. Only the healthy candidate case returns the
selected component root. The malformed rows are the declared `00ff` raw values;
this experiment does not cover every malformed protobuf, metadata corruption,
concurrent manager mutation, live reorg or full node startup.

Seventeen focused native test passes, with zero skips, cover empty-ledger first
initialization, genesis lookup error preservation, stopped-cache refusal before
genesis insertion, terminal Init refusal, the original Stop error controls and
the preceding rollback-target controls. The native race detector was not used.
No `Chain.Start`, full node service, network, signing or broadcast is invoked.

## Independent bytes and retained failures

The reader binds all 467 original source blobs and the exact runtime/entrypoint
trees: parent ordinary `1ec0bc16975ac70441d7cf5bbf964192de9e3c6e`, candidate
ordinary `3b48a658f6dbae71057bdd3c424018e0a0830749`, and candidate units
`81804b7564687d8fcb49cfb7c3575886206f7188`. The node's module files are unchanged.
The retained ordinary binaries' build inventories matched the 25 linked modules
against the selected source's own sums. Whole-module archive-graph qualification
remains open; no new source/dependency archive was downloaded for these runs.

Python independently computes both 160-byte v1 header preimages and the declared
changed-header hashes. Genesis's selected content digest is bound by its known
source identifier; this reader does not rebuild its complete content list or KV
projection. It also derives a one-row raw KV frame with a present empty value,
checks exact height-key bytes, and reconciles the mutation and closed-image pins.
Large KV-image digests are recorded observations. They do not reconstruct physical
LevelDB files or authenticate their origin, durable recovery or accepted history.

Two incomplete observer attempts remain recorded: one consumed a shared genesis
patch during fixture preparation; the next incorrectly assumed a failed Init
could not consume its configured transaction. The final observer uses a fresh
genesis per case and records consumption explicitly. An initial unit build had
an import cycle. Another attempt hit its 4 MiB capture cap and remains incomplete.
Their actual exits, completeness and protected outputs are retained.

The successful candidate ordinary phase came from the task whose later unit
build failed. Its successful phase is qualified separately; that original task
is still a failure. The corrected native unit run used its own exact source tree.
The already completed ordinary backend was not repeated for those unit fixes.

Compact headers, hashes and single-byte mutation deltas reduce complete ordinary
stdout to about 50 KiB per process. The final native unit stdout is 25,971 bytes.
Scoped fixture log suppression restores the previous handlers and leaves test
results and returned-error assertions intact. No capture cap or production
free-space floor was lowered. An incomplete-capture workspace remains held.

## Reproduction and portable controls

Use a new owned task, offline verified inputs and bounded foreground execution.
Reserve 2 GiB expected allocation in a configurable 3 GiB quota above the 10 GiB
floor and other reservations. Preserve actual failures before another attempt.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_public_chain_startup_record.py prepare \
  --node-source "$PINNED_COMPLETE_NODE_SOURCE" --workspace "$NEW_OWNED_WORKSPACE" \
  --go "$PINNED_GO" --variant candidate
```

The preparer returns build/case arguments and validates a fresh regular-file
inventory. `--unit-controls` includes the separately pinned focused tests. The
preparer does not compile, run a node, acquire dependencies or clean caller data.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_public_chain_startup_record_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_public_chain_startup_record_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_public_chain_startup_record.py
```

The CI steps replay source/recorded-byte controls on Linux, macOS Intel and
Windows; they do not execute these node managers on those platforms. Independent
review, node/client profile agreement, representative resource budgets and full
node recovery remain M2–M5 gates. Runtime v3/state-value acceptance and the
consumer result stay **REFUSED**. Storage tooling is outside this change.
