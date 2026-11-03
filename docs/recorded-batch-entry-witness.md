# Recorded BatchEntry header/witness workflow

One isolated original-node fixture supplies a matching stored BatchEntry,
signed v3 header, proof, raw momentum RPC rows and frontier gateway DTO.
The [record](../internal/testdata/conformance/batch-entry-node-header-witness.json)
feeds the existing exported query and compiled read-only collection/query workflow.

This closes a recorded-fixture integration gap. D0-D3 selected-network
acceptance, the chain-69 activation capture and a real selected-network
consumer remain open. The fixture selects no live trust inputs.

## Original capture

| Item | Recorded identity or observation |
| --- | --- |
| Node source | digitalSloth/go-zenon@938fca3b7787da86827a5eb63371509b36e14761 |
| Git tree | f3b7947d2267ebdb806f18ff0c02bba5bffae9c4 |
| Original source | All 484 regular files unchanged and checked against the retained Git-verified inventory |
| Added harness | [batch-entry-header-witness_test.go.txt](../tools/gen-state-root-vectors/batch-entry-header-witness_test.go.txt); 7,741 bytes; SHA-256 230ae18c289f5adcf9e195a2405bbefec56851ec7742956a00eb66348060a45a |
| Actual selected test | TestSPVBatchEntryHeaderWitnessCapture in ./vm/embedded/tests |
| Compiler/platform | Go 1.25.14, darwin/arm64, CGO enabled, system Clang |
| Result | Actual exit 0 and complete output; 34 used modules checked against original go.sum |
| Fixture | Chain 100, genesis 0385d849ee33b94c8783288c148e3ae741c2ecec98b08b3f59d6bcc219168fe5 |
| Fixture first incoming v3 | 31, from this fixture's separate activation sequence |
| Explicit fixture anchor | Height 76, hash af8fe904122a682a93d0a680b7c5057d52d38b3d237c58558d130ca49b0a2f28 |
| Query H | Height 78, hash 741f33c4d5689b4e8d27260bc42050e1c6c1213d519a9a93a307fe89f595612b |
| Selected tip T | Height 79, hash fb20809a49201f227be32f7c18e3f883df289282ac47e38d6c207c351f27d7d8 |
| Query | Fixed Settlement address, domain 1, batch 0 |
| Original execution record | SHA-256 9803750517e87d55c8a14c5b5eb06d6653bbf77d82d72c07cb61239d51f6adf5 |
| Original output | 42,933 bytes; SHA-256 d914355c15f183587139a1b8d43f39a095ae09639881195b53988bcfb35a3c3f |

The harness uses unchanged isolated contract helpers and public deterministic
test keypairs. It runs original contract storage, the maintained state tree,
producer, verifier, ABI and RPC methods in process. Consensus is mocked;
the finite SPV schedule is an explicit test assertion. No RPC/P2P service,
live wallet, transaction or deployment starts. This is an attestation-profile
fixture; its stored post-state commitment does not prove STF execution.

The original proof verifies under H's actual header root. The node ABI decoder
reads its stored value, an altered value fails membership, batch 1 supplies
a separate absence proof, and the exact H proof remains unchanged after T.
The gateway DTO is a frontier comparison, not historical authority.

The first attempt emitted a witness but failed the convenience helper's empty-log
assertion on additional activation diagnostics. Its actual exit 1, output and
execution record remain in the corpus. The corrected harness starts that
assertion after both activations, preserving operation checks and original source
bytes. Its success does not relabel the first attempt.

First-v3 height 31 belongs only to this fixture. It replaces neither the earlier
[chain-100 boundary capture](first-v3-node-boundary.md) nor the
[selected chain-69 source-genesis expectation](selected-devnet-genesis.md).

## Independent bytes and consumer execution

The standard-library [Python replay](../tools/gen-state-root-vectors/check_batch_entry_header_witness.py)
reconstructs three 208-byte header preimages, the full local 35-byte key and
single-hash path, inclusion and absence roots, and all 17 stored ABI fields.
Its root-first recursive proof fold is independent of the native verifier.
It also replays finite schedule, header-context, typed-context and query
fingerprints. Ed25519 verification belongs to the native workflow, not Python.

    python -I -B tools/gen-state-root-vectors/check_batch_entry_header_witness_test.py -v
    python -I -B tools/gen-state-root-vectors/check_batch_entry_header_witness.py
    go test -json -count=1 -run '^TestCompiledExperimentalBatchCandidateWorkflow$' ./internal/conformance

The compiled workflow retains its incompatible-witness control and reuses the
same two fresh executables for the positive subworkflow. A local fixture server
serves exactly the three selected reads; it is not an independent operator.
Collection success grants no proof authority. The offline CLI checks both
explicit pins and the separate request, then emits the same detached result
as the exported API. The API also rechecks a saved trusted fixture window.

Changed provider root/value/proof, local batch/header/tip identity, signature
and gateway field produce no row. Unavailable input and valid absence remain
distinct refusals. The gateway's unauthenticated frontier hint is not another
stored ABI field. Success keeps EXPERIMENTAL_CONFIGURED_HEADER_MEMBERSHIP scope,
read-only persistence, zero verifier RPC reads and no production guarantee.

The record's test_selection is an explicit synthetic test configuration.
Its settings and pins are not independently selected live trust. Do not extract
them as a live profile or let a provider generate real query configuration.

## Small CI replay receipts

CI runs the same 23 Python controls and independent byte replay through
[record-batch-entry-replay.py](../tools/record-batch-entry-replay.py). The wrapper
adds no node execution or Go build. Its separate in-memory regression controls
cover failure, error, skip, expected-failure, unexpected-success, class setup
and teardown errors, source changes, bounds and output completion.

The wrapper emits one JSON receipt of at most 32 KiB and caps diagnostics at
256 KiB. It names every selected and started root, records root outcomes and
separate subtest counts, and includes the mathematical summary. Six fixed
source/corpus/harness files have bounded byte counts and SHA-256 digests checked
before and after the run. The declared revision must still be bound to the
selected source by the qualifier; unchanged local bytes alone do not prove a
Git revision. Permitted Git/checkout line-ending relations are checked there.

The existing offline-pilot CI archive now carries this receipt beside its
unchanged pilot report. Early root-suite publication and the number of archives
remain unchanged. Qualification can consume the small receipt instead of
downloading three complete native-job logs. Existing logs, older archive shapes,
original-node evidence and failed attempts retain their original interpretation.
No historical evidence is deleted or relabelled.

    python -I -B tools/record-batch-entry-replay_test.py -v
    python -I -B tools/record-batch-entry-replay.py \
      --source-revision <full-checkout-revision> --expect-platform <os-architecture>

A successful receipt has exit 0 and status passed only when all 23 roots pass,
without skips or other exceptional outcomes, the mathematical replay matches and
the source remains unchanged. Failed controls retain a failed receipt and exit 1.
Invalid invocation exits 64; an operational or output failure exits 70. A partial
write or failed flush is unusable even if already written bytes include passed.
Input/operational diagnostics omit supplied argument values and private paths.

The receipt remains unsigned consistency data. Check the actual process exit,
complete output, exact source inputs, platform, selected CI revision and successful
job/step records before using it. It authenticates neither execution provenance
nor network trust. The selected-network and production gates above remain open.

## Reproduction and resources

Prepare a new task-owned isolated copy of the exact node and verified dependencies.
Exclusively add the harness as vm/embedded/tests/spv_batch_entry_header_witness_test.go,
refusing an existing destination. Keep original checkouts and live data separate.

    GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=1 \
      go test -mod=readonly -p 1 -json -count=1 -timeout=120s \
      -run '^TestSPVBatchEntryHeaderWitnessCapture$' ./vm/embedded/tests

The SPV_BATCH_ENTRY_HEADER_WITNESS marker contains the trace. Concatenate split
Go JSON output events before parsing it, and retain actual exits, completeness,
compiler and source/module identities. A new invocation is separate evidence;
a replay does not execute the original node again or qualify another platform.

The successful capture had a 512 MiB task budget. Its largest post-command
workspace observation was 297,289,013 bytes, about 283.5 MiB. That is not a
continuous peak or production hardware target. Verified source and read-only
local module inputs were reused without network transport. Fresh redundant
module ZIP copies were removed only after equality and h1 checks. Owned temporary
caches were closed and removed; physical APFS reclaim was not measured.

Unsigned digests preserve integrity references, not authenticated distribution
or a reviewed release. Full historical module-graph verification remains
NOT_ESTABLISHED. Canonicality, consensus finality, STF correctness, funds release,
receive, network activation and production readiness are not established.

