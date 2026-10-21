# Public cache-store identifier context

The selected experimental node returned a cache view for a different momentum
hash at the same stored height. The view reported the requested foreign
identifier, while the state-root API refused that identifier. The public Chain
successor resolves the requested height in its current ledger and compares the
complete hash/height before creating the height-indexed cache view.

This changes the experimental public Chain boundary. The lower cache storage
remains indexed by height. Plasma and fused-amount values are excluded from the
partial state commitment; they are not authenticated state-value proofs.

## Recorded comparison

The [source patch](../tools/gen-state-root-vectors/testdata/candidate-cache-store-context-patch.json)
extends digitalSloth/go-zenon at
[9c71ae82fc983e16f914ae085d4034030c8ebe3b](https://github.com/digitalSloth/go-zenon/commit/9c71ae82fc983e16f914ae085d4034030c8ebe3b)
and the prior experimental runtime d56bf37a23ddf0ec0f8af2eca62be01bb6c54dbc.
All previous Chain function bytes are preserved. The candidate source tree
69b0844bccc68273b2b367cda7706d933d45358f includes the new method and three
explicit unit sources. No data format, SMT profile or SPV runtime is changed.

One ordinary build per variant ran two sequential processes on Darwin ARM64
with Go 1.25.14: source-genesis initialization, followed by a fresh-process
reopen of the same closed stores. Each process queried the selected genesis
identifier, two same-height hash mutations and an unavailable next height.

| Observation | Baseline | Candidate |
| --- | ---: | ---: |
| Ordinary processes | 2 | 2 |
| Cache-context queries | 8 | 8 |
| Foreign identifiers receiving cache views | 4 | 0 |
| Foreign identifiers refused by the state-root API | 4 | 4 |

The ledger, cache and tree's complete closed logical key/value images matched
through reopen and across both variants. These are logical-image comparisons,
not physical database-byte or crash/power-loss qualification. The canonical
cache values in this fixture are zero; cache-value correctness and populated
account-block extraction remain open.

One separate ordinary Go test invocation retained all 17 prior Init/Stop and
rollback pass results and added 12 context controls: 23 root tests and 29 pass
results, with zero skips. Controlled in-memory ledger cases include historical
identifiers, branch replacement, rollback, missing rows, malformed/read-error
rows and a behind cache. They are unsigned component fixtures.

The [record](../tools/gen-state-root-vectors/testdata/native-cache-store-context.json)
keeps all 34 ordinary events as four exact, SHA-256-bound JSONL payloads.
The portable reader verifies each byte stream, complete source/build trees,
the unit inventory and all 16 queries. It executes no node, database, Go build
or resource observer. Its hashes and the private original capture do not
authenticate their own origin.

## Reproduction

    python -I -B tools/gen-state-root-vectors/prepare_cache_store_context_test.py -v
    python -I -B tools/gen-state-root-vectors/check_cache_store_context_test.py -v
    python -I -B tools/gen-state-root-vectors/check_cache_store_context.py \
      --source-revision "$SOURCE_REVISION"

For a new backend comparison, use approved task-managed scratch, the unchanged
pinned node source and checksum-verified dependencies. The preparer refuses
existing or linked destinations, verifies every source file and returns the
exact source/build/test/run recipe:

    python -I -B tools/gen-state-root-vectors/prepare_cache_store_context.py prepare \
      --node-source "$PINNED_NODE_SOURCE" --workspace "$NEW_OWNED_WORKSPACE" \
      --go "$PINNED_GO" --variant candidate

Keep the production free-space floor at 10 GiB plus the expected 2 GiB
allocation and other reservations. The suggested task quota is 3 GiB.
Use one private workspace for the candidate unit command and ordinary build
so their build cache is shared. Retain every actual attempt, exit, stream,
binary and source pin; reuse existing verified dependency objects. Close the
two processes and all managers before checking images and clearing only the
owned generated workspace.

## Remaining gates

Callers still own serialization with chain-history maintenance. Concurrent
history changes, corrupt-row body authentication, representative workloads,
full-node recovery and network validity remain unqualified. Current-ledger
identifier equality does not authenticate that ledger's authority.

This component comparison does not establish profile agreement, activation,
accepted-header binding, independent review or authenticated distribution.
The native verifier's state-value result remains REFUSED. The
[roadmap](native-roadmap.md) keeps M2 agreement and full-node qualification open
before the separate accepted-v3 balance flow.
