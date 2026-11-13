# Closed devnet parent-slot oracle preparation

This offline command is for the owned chain-69 experiment. Its complete-node
build and native controls have a separate qualification lane. For a selected
revision, require that lane's actual completed evidence before using its binary.
Passing source-H1 controls supplies neither an accepting SPV schedule nor a
selected-network consumer result.

The command reads an existing, consistent, closed raw ledger from the pinned
node at `2835c436b197fece5c76adf4ba8dc1decca2e3ea`. For a bounded, explicitly
selected header range it asks the original consensus implementation for each
producer at that header's exact parent snapshot. It does not copy the producer
field into its oracle result or replace the election with genesis membership.

This selects the [reference-gas source cohort](reference-gas-source-cohort.md)
for new oracle builds. The original node's slot recording and previously
qualified binaries retain their original source identities. The existing
owned-runner contract still selects those older binaries; adopting new oracle
and consumer artifacts together is a separate coherent contract update.

## Read path and allocation

The selected node already provides `db.NewReadOnlyLevelDBManager`, with
`ReadOnly: true` and `ErrorIfMissing: true`. Its offline prebuild path in
`app/action_state_tree.go` constructs `chain.NewChain(manager, nil, genesis, ... )`
without calling `Chain.Init`. This command uses that read-only construction
pattern for snapshot lookup and calls only `manager.Stop` when done.

It does not initialize a cache database, build an SMT, start chain/consensus
services, open a wallet or sign/submit anything. The election adapter uses its
existing ephemeral in-memory election-result cache. The caller must still
prove that the selected raw ledger is closed and consistent; read-only open is
not a liveness, provenance, snapshot-completeness or ownership attestation.

An owned stopped archive-node volume can therefore be bound read-only for this
phase, after all owned services stop. A second full ledger copy is unnecessary
for this proposed route. No existing node or unrelated volume may be stopped,
adopted or cleaned. Actual memory, time and disk measurements remain required;
the source construction alone does not establish a resource budget.

## Build input

Use a newly owned, verified copy of the exact node revision and original tree
`f89d645c7f5be85dfe10dc7a510d80df7965d22f`. Preserve all original source bytes.
Add only these files:

| Repository input | Added path in the owned node copy |
| --- | --- |
| `tools/gen-state-root-vectors/parent-schedule-adapter.go.txt` | `consensus/spv_parent_schedule_adapter.go` |
| `tools/gen-state-root-vectors/closed-devnet-parent-oracle.go.txt` | `cmd/spv-closed-parent-oracle/main.go` |
| `tools/gen-state-root-vectors/closed-devnet-parent-oracle_test.go.txt` | `cmd/spv-closed-parent-oracle/main_test.go` |
| `internal/testdata/conformance/selected-parent-slots.json` | `cmd/spv-closed-parent-oracle/testdata/source-h1-slots.json` |

The helper is temporary source instrumentation, not an upstream node API. Use
the pinned node's module graph and retain exact source/dependency, command,
platform, exit and stream-completeness bindings. Do not modify a deployed node
or the original SPV checkout. The compiled node helper must retain the node's
applicable license obligations if distributed.

Native qualification, before any real ledger use, includes:

```text
go test -mod=readonly -p=2 -tags devnet -trimpath -buildvcs=false -json -count=1 -timeout=90s ./cmd/spv-closed-parent-oracle
go build -mod=readonly -p=2 -tags devnet -trimpath -buildvcs=false -o <owned-output> ./cmd/spv-closed-parent-oracle
```

These commands are a reproduction recipe; a source recipe is not evidence of
execution. The harness includes request refusals and a real source H1 fixture: initialize
and close a newly owned ledger, reopen it through the read-only/no-Init path,
run the source slot lookups, compare their complete ordering/proof context with
the independently retained original-node trace, then compare all raw-ledger
file names and SHA-256 values before and after. It also exercises a refused
frontier and missing ledger. There are no FIFO, symlink or socket fixtures in
the new harness.
Its source-H1 controls do not qualify an evolving devnet or the full positive
command path; the latter still requires an actual closed selected ledger.

The retained original-node slot recording remains an independent comparison
input. New native execution must match its complete H1 ordering and proof
context while reporting the new node revision. Equal observations do not
transfer the original recording's execution identity to the new source.

## Hosted qualification lane

The path-scoped `closed-devnet-parent-oracle` workflow runs Linux, macOS and
Windows jobs separately from the ordinary SPV suite. The
`qualify_closed_parent_oracle.py` driver creates a new owned workspace and a
separate evidence directory. It fetches only the fixed node revision, checks
the complete original Git tree and every tracked file's blob identity, adds
the four declared inputs, then runs the selected native tests and builds one
ordinary command. A local line-ending setting applies only to that new node
copy; no existing checkout or global Git configuration is rewritten.
Before workspace creation the driver checks the helper's declared node pin
and the unchanged historical fixture digest. Staged ownership also pins the
exact node revision/tree; a foreign or missing pair is refused before any
native command.
The complete node dependency closure requires CGO. The lane selects
`CGO_ENABLED=1`, uses the runner's native gcc or clang, and retains the actual
compiler version output with the Go environment. It does not replace or patch
the node's secp256k1 implementation.

The driver verifies its stage context and directory identities before reuse.
It refuses pre-existing unrelated directories and does not place failure
packets inside them. After execution it rechecks original source bytes, node
revision/tree/index, the exact added-file set and the selected SPV input blobs.
Compiled/interpreted inputs must be exact; only workflow YAML may have a
separately recorded CRLF checkout spelling.

An exit-zero test command alone is insufficient. The driver checks the complete
Go JSON stream: all three selected roots and 25 named request subtests must run
and pass exactly once, without failures/skips or unfinished tests. One H1 trace
must name the selected node, match the original slot snapshot and report
unchanged raw-ledger files with no service, accepting-schedule or consumer
claim. Missing, repeated, foreign or post-terminal events refuse the build.
Long log lines are reassembled from bounded per-test Output fragments; another
test's or the package's output cannot complete the selected H1 trace.
The existing three native jobs remain the only node build lane; no second
cohort matrix or repeated node test is added.
After building, the driver executes the actual binary without request arguments.
It requires empty stdout, the fixed refusal diagnostic and a complete actual
exit of 1. That expected refusal keeps its nonzero exit in the command receipt;
it is not relabeled as an exit-zero command or a positive devnet query.

Native tests and the command build use the same `-trimpath -buildvcs=false`
settings so dependency compilation can share the same Go build-cache keys.
This removes an avoidable configuration mismatch; actual savings and peak
resource use require measurement and are not inferred from the flags.

### Local reference-gas observation

An actual Go 1.25.14 darwin/arm64 CGO execution completed all three roots and
25 request subtests with exit zero and complete output. The source-H1 reader
reported five raw-ledger files with unchanged names/content, and its six slot
lookups matched the retained original-node snapshot. All 484 original node
files and four helper inputs were rechecked after the command. Twenty-five
retained module ZIP/directory h1 pairs matched the selected node's go.sum;
the full historical module graph remains NOT_ESTABLISHED.

The exact native stdout is 31,304 bytes, SHA-256
`2bc6f7c947f2855b6df9aa8c36582b74752ee9c927d2e2034e9c688d82d18cbf`.
The surrounding local controller did not complete: its first reader mistook
a fragmented test2json log for one complete JSON value, and the storage
observer subsequently stopped it during cleanup. Its actual -9 exit and
incomplete output remain separate from the completed native command. The
observer's generic resource/refusal label does not establish a quota excess.
The corrected reader checks the retained native stream without rerunning the
node test. Regression controls include split markers/tokens, missing tails,
duplicate traces and output from another test or the package.

No standalone local binary result is claimed from that interrupted attempt.
The hosted lane must perform its own tests and command build with the common
compiler settings; local replay does not qualify a new CI revision or platform.

Each command has bounded stdout/stderr, actual exit and EOF/completeness
receipts. Failure and launch/timeout uncertainty are retained without invented
success. Each stream is stored once, and the final manifest refers to its
digest. Only the binary, source overlay/license notice and bounded evidence
directory are uploaded. Source workspaces, databases, module/build caches and
telemetry directories are not recursively packaged. This driver does not
delete historical data or adopt an existing workspace.

Admission requires a 10 GiB free-space floor, a 1 GiB expected allocation and
a further 1 GiB safety margin. This is an admission policy, not an OS disk
quota or a peak disk/RSS measurement. Go uses `-p=2` and `GOMAXPROCS=2`;
test execution has a 90-second package timeout, and the complete
job has a 15-minute bound. On command failure/timeout, only the created child
is stopped; Windows descendant cleanup is not claimed. A real fixture setup,
service start, live ledger read or transaction is outside this workflow.
An interrupted controller or job without completed receipts remains unknown;
partial output is not promoted to successful qualification.

## Explicit request

The command takes exactly one each of `--ledger`, `--genesis` and `--request`.
It reads no RPC and selects no endpoint. The genesis bytes must match the
source-pinned chain-69 genesis. The request is at most 32 KiB and uses exactly
this canonical field order/encoding plus one newline:

```json
{"expected_frontier":{"hash":"<64 lowercase nonzero hex>","height":123},"targets":[{"hash":"<64 lowercase nonzero hex>","height":122},{"hash":"<64 lowercase nonzero hex>","height":123}],"version":1}
```

The placeholder hashes above are illustrative, not accepted inputs. There
must be 1–64 targets with consecutive increasing heights of at least 2, no
target above the selected frontier, and complete exact hashes. Duplicate,
unknown, missing, null, noncanonical or trailing fields/documents are refused.
The request must be selected and preserved before oracle execution. The
source oracle does not authenticate the request's selection authority.

For every target the helper checks its stored identity, recomputed hash and
parent link, then selects that exact parent snapshot. The existing adapter
checks the slot, original consensus parameters, proof time and proof block.
The producing address comes from that source calculation and must match the
stored header's public-key-derived address. No partial row set is emitted
when one target fails. Header signatures remain for the SPV verifier to check.

## Output and trust boundary

Only after all rows, the unchanged frontier and successful manager close does
the helper emit its bounded JSON report (at most 256 KiB). It contains the
request SHA-256, source node revision, exact genesis/frontier, per-header
parent/hash/version/root/timestamp and original source slot details. Errors
return nonzero and a fixed diagnostic without private paths. Retain incomplete
stdout honestly when the invoking controller or output stream fails.

This report is source-derived diagnostic evidence. A node-revision label is
not binary authentication. The report makes no accepting schedule, signature
verification, authenticated election/fork choice, finality, activation,
state-value or production claim. The experiment must independently bind its
source/binary/capture provenance, select the finite schedule and explicit
anchor/profile, derive and pin the SPV contexts, and run the actual read-only
three-row consumer. A disagreement or missing snapshot cannot fall back to a
producer copied from a header or to genesis-set membership.

The [query contract](batch-entry-query-contract.md) and its real D2/D3 gates
remain open until that selected-network consumer path is executed and checked.
