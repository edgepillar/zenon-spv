# Experimental ahead-tree startup quarantine

This is an optional research patch and a finite component comparison for M2.
It is not an accepted retained-version identity repair, node upgrade, enabled
state-root profile or production recovery procedure. The SPV runtime continues
refusing v3 and state-value claims.

## Concrete boundary

The pinned node can start with an A tree ahead of a selected B chain, truncate
by height and write B's frontier identifier while retaining A's root at the
selected height. A clean reopen preserves that mismatch. The
[original startup corpus](../tools/gen-state-root-vectors/README.md#separate-real-chain-component-startup-fixture)
remains unchanged.

The [experimental patch](../tools/gen-state-root-vectors/startup-quarantine-patch.json)
changes only the runtime body of `stateTree.Init` in a temporary node copy:

1. Clear readiness while initialization re-establishes its conditions.
2. If the stored tree is ahead of the selected chain, return an explicit error
   before catch-up or rollback. Keep the complete logical database unchanged.

The readiness reset also covers a reused component whose second initialization
fails at the existing equal-height hash check. The patch adds no persistent
metadata, data deletion, rebuild, migration or background work.

This deliberately refuses an A@3 to A@2 rollback whose selected state would
otherwise match. The current retained records provide heights and roots without
a sufficient per-version Momentum identity contract. An operator or maintainer
must choose and review a recovery policy separately. No automatic reset or
permission to remove an existing state-tree database is supplied.

## Source and compilation

The executed baseline is
[digitalSloth/go-zenon at 56ce2c384966f2f1940967257a0788d3998a5eef](https://github.com/digitalSloth/go-zenon/commit/56ce2c384966f2f1940967257a0788d3998a5eef).
All 394 original blobs are selected by the existing
[source manifest](../tools/gen-state-root-vectors/source-pins.json).
The patched runtime file has SHA-256
`5b629baefd0064543122d7fa653e86804ebbf07593a542dd0055dd5e39b6ddce`;
the derived 394-blob tree is
`c39bda7a640821c0a88adb99ecac9cc912dbbbba`.
It is an uncommitted experimental tree.

A fresh read of
[33d7d1ee1b6a915c40aea196e2a10f1e893d171f](https://github.com/digitalSloth/go-zenon/commit/33d7d1ee1b6a915c40aea196e2a10f1e893d171f)
found identical `chain/state_tree.go` and `common/trie/nodestore.go` bytes.
The complete `rpc/api/ledger.go` file differs. This comparison does not
qualify execution of that complete newer node revision.

The [preparation helper](../tools/gen-state-root-vectors/prepare_startup_quarantine.py)
refuses an existing destination, checks the complete original source, verifies
both full-file hashes and the exact inverse patch, and stages independent
source files. One tagged probe is added to the temporary chain package.
Explicit Go compiler overlays exclude the four existing upstream test files
and their unrelated test-package imports. Every upstream file remains
unchanged on disk. This is a component probe build, separate from the upstream
test suite. The overlay and selected build command are retained as inputs.

The frozen research module lock remains unchanged. Dependencies must already
be available through an explicitly selected offline source; acquisition and
quota-accounted process supervision are separate. The helper prints a build/run
plan and does not launch a node or execute the commands itself.

## Finite observations

The [Go probe](../tools/gen-state-root-vectors/startup_quarantine_probe_test.go)
uses the real chain constructor, initialization, state-tree and read methods.
Recording manager/cache/genesis inputs and unsigned serialized Momentums are
synthetic. The twelve cases preserve all ten original startup selections and
add two previously-ready component reinitializations.

Each source variant supplies 15 initialization phases and 90 selected read
observations. The comparison includes complete logical key/value records before
and after each phase and after clean close/reopen. The independent checker
constructs raw balance keys, hashes, canonical proofs, compressed leaf records,
refcounts, retained heights and full frontier bytes from its own selected state
machine.

The guarded variant refuses five ahead-tree phases, preserves their complete
logical database and stays not-ready across reopen. Previously-ready
reinitialization errors clear the readiness latch. Matching/equal/below-frontier
positive controls retain their expected results.

Low-level height-only reads remain unchanged. Even a ready matching tree can
return the same root/proof for a different hash at that height. This proposal
does not add authenticated retained-version history or repair the live reorg
path. The research comparison disposition remains `REFUSED`; no production
balance-proof consumer executes in this experiment.

A further source-derived limitation is an already relabelled database whose
stored frontier matches the selected height/hash while its root came from
another state. This guard cannot distinguish it using the existing metadata.
The finite experiment does not execute that cross-variant recovery scenario.
Existing databases require a separate independently reviewed recovery plan.

Local reproduction builds the baseline and patched probes once each and keeps
two complete generations per variant, without filtering failed outcomes.
Actual reference execution and its toolchain/platform scope are recorded
separately from the deterministic corpus. Native CI runs the offline checker
and adverse controls; it does not run the reference node or CGO experiment.

The recorded local execution used Go 1.25.14 on Darwin/arm64 with CGO enabled.
Its two generations contain 60 initialization phases, 360 read observations
and 172 complete logical snapshots in total. The 29 offline controls also check
provider substitution, closed qualification claims and preparation refusals.
An initial probe compile error occurred before component execution; its source,
actual exit and diagnostics remain retained separately. The corrected probe
then completed both generations for both source variants.

## Reproduction and acceptance

Use a complete pinned node snapshot and an explicitly owned new workspace:

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_startup_quarantine.py \
  --node-source NODE_SOURCE --workspace NEW_OWNED_WORKSPACE \
  --variant startup-quarantine --go SELECTED_GO_1_25
```

Inspect the returned source pins, compiler overlay and command arguments.
Run the returned commands only through the caller's approved bounded process
and storage supervisor, with private Go cache/module/temp directories and
offline dependencies. Preserve actual exits, complete streams, source and
binary hashes before interpretation. The baseline uses its own new workspace.

```sh
python3 -I -B tools/gen-state-root-vectors/check_startup_quarantine_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_startup_quarantine.py
```

This candidate needs independent node review and a decision about availability,
hash-bound retained metadata and recovery policy. Current complete-node
qualification, realistic retention/resource budgets, physical storage faults,
authenticated headers/profile/activation, accepted v3 balance binding and
authenticated distribution remain open. Synthetic roots, matching peers and
green CI do not establish canonicality, consensus finality or network activation.
No upstream repository, running node, wallet, signer, transaction or live
deployment is changed by the research tools.

