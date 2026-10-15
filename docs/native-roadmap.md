# Native verifier roadmap

The initial product verifies Zenon headers and identified account-block
inclusion under explicitly sourced trust inputs, with bounded resources and
explicit unproven properties. It does not authorize irreversible asset release,
claim balances, or provide consensus finality. Reuse the current implementation;
Bitcoin SPV and Portal remain separate future decisions.

The operator workflow from [PR #62](https://github.com/edgepillar/zenon-spv/pull/62)
already supplies configuration inspection/pinning and synthetic native-platform
evidence. Those completed pieces are the baseline, not new roadmap work.

| Stage | Delivery and remaining acceptance gate |
| --- | --- |
| Verification contract | [Current contract](verification-contract.md) resolves header/PoW, flat content, identity and operator-schedule semantics. Historical review/vault wording does not add guarantees. |
| Retained availability | [K/W separation](retention-policy.md) supplies explicit bounded capacity, versioned context/state, migration and delayed-query tests. [Node-derived mixed-height fixtures](delayed-inclusion.md) cover delayed user/embedded segments across v1/v2 and compiled watch/restart/query flows. |
| Trust lifecycle | [Controlled renewal](trust-input-lifecycle.md) records origins, required pins, coverage and restart boundaries. Runtime never authenticates those origins or automatically renews them. |
| Read-only consumption | The [reference query consumer](query-report-consumer.md) checks actual process completion, the exact independently selected target batch, recomputed context digest/tip, each row's required guarantees and explicit trust allowances. The selected [block observer](block-observer.md) connects both compiled commands with explicit binary/context/trust inputs, bounded subprocess capture and private cleanup. Its explicit single-RPC mode adds pinned proof-only collection in the same invocation without state writes or implicit renewal. Native node-corpus and loopback tests exercise this application. Operator-trusted experiments and development can proceed without a second operator; independent network qualification, report-channel provenance and review remain separate gates. |
| Compatibility and resource evidence | Independent byte-level v1/v2 and mixed-height checks run in CI. [Populated capacity workloads](retained-capacity-benchmarks.md) exercise K=16/256/4096 with allocations, state size and operation latency. [Bounded state reads](state-read-allocations.md) reduce input-buffer allocation while preserving full validation. [Flat-content scaling](flat-content-resources.md) adds node-derived stress roots, repeated-list costs and compiled Linux/macOS RSS or Windows peak-working-set observations, with distinct native accounting sources and process-lifetime tests. [Index-sorted hashing](content-hash-allocations.md) reduces per-member allocation while preserving the canonical byte contract. [Bounded bundle reads](bundle-read-allocations.md) reduce raw file-buffer growth while preserving byte, read-error and decoding checks. [Signed-envelope buffers](envelope-hash-allocations.md) reduce header/account hash allocations with independent byte oracles and measured full retained-state workloads. [Reference consumer observations](query-consumer-resources.md) retain 21 sequential fresh-process elapsed/memory measurements at each of 1/16/256 targets, separately from verifier execution, with no failure retries or sample filtering. Representative application traffic, target hardware and real-network bandwidth/latency remain open; synthetic evidence is bounded. |
| Controlled network pilot | Use the selected block observer application with independently selected real account-block targets and authenticated network inputs, then record read-only restart, disconnect, stale peers, expiry and delayed queries on target hardware. Keep actual observations and all failures separate from synthetic artifacts. No live pilot is claimed by local application conformance. |
| Reviewed release and integration | [Tested candidate artifacts](candidate-artifacts.md) retain each native run's exact ordinary executable bytes with its report and manifest, plus an independent archive/pin checker. Obtain independent review of that exact candidate, test a real report consumer, choose the smallest public API, verify source/binary provenance and document upgrades/support limits. The unsigned packages and CI do not substitute for independent review. |

The [complete observer resource workflow](observer-workflow-resources.md)
adds native repeated observations of the actual observer, verifier and consumer
with full K=256/4096 windows, 16 selected targets and concurrency one/four.
Each of the four workloads retains 21 fresh groups, successful child outcomes
and input/cleanup checks. Native waited-process memory has distinct OS scopes;
it is not simultaneous process-tree memory or a production capacity guarantee.
This local synthetic workload leaves independent consumer, hardware, traffic,
network and release acceptance gates unchanged.

The [hash/address text buffer comparison](chain-text-hex-allocations.md) removes
intermediate conversion allocations while preserving exact legacy bytes,
errors and failure atomicity. Finite byte-position controls, a pinned codec
reference and native allocation observations complement the unchanged
large-content inclusion and budget workloads. These observations do not set
production memory or latency limits.

## Separate consensus research

Before implementation, specify which authenticated history/commitments bind
election inputs, slot authorization, producer transitions and activation.
Define conflict resolution, long-offline recovery, weak-subjectivity/checkpoint
and freshness assumptions, and storage/bandwidth costs. Matching RPC responses
or an operator schedule cannot complete this track.

## Separate state-root research

The [candidate commitment contract](state-root-candidate-contract.md) pins
`digitalSloth/go-zenon@56ce2c384966f2f1940967257a0788d3998a5eef` and separates
observed source rules from unresolved profile decisions. Its root covers token
balances and contract storage; plasma, frontier, mailbox and the separate ZNN
index are excluded. The first typed consumer target is a selected token balance
under an exact verified Momentum. Refuse excluded-key queries before treating
absence as a ledger value. Stored balances use an at-least-32-byte integer
codec, so a present zero and an absent balance key need distinct proof results.

Proceed through the contract's coordinated deliveries: agree the commitment
profile and resource policies; produce node-derived v3/root/proof vectors with
an independent byte oracle; extend strict headers, RPC, bundles, persisted
state, context and typed consumer reports; qualify node lifecycle and snapshot
import separately; then run a read-only pilot under explicit activation and
header trust inputs. Snapshot chunk digests and reconstructed SMT roots are
different objects, and a partial root does not authenticate excluded state.
Require hash-bound recovery tests and measurements of the actual `NodeTree`,
rather than inferring bulk build costs from per-height comments.

The contract is research, not an enabled profile, deployment claim or security
endorsement. The current client continues refusing v3 and state-value proofs.
The [candidate byte fixtures](../tools/gen-state-root-vectors/README.md) exercise
unsigned header hashes and the candidate's storage-free SMT APIs with an
independent oracle. They provide a first conformance baseline; activation, wire
conversion, context/persistence, runtime typed queries and node lifecycle remain
separate gates.
Do not reuse the broader reserved `IAVL_STATE` kind for this partial SMT.
The same isolated tool records the L1 family filter's exact patch events. Its
22 cases distinguish family membership from the selected typed balance key
grammar and empty Put events from the later empty-to-delete applier. This
storage-free filter conformance does not qualify state transitions or a
persisted `NodeTree`; those remain separate deliveries.
The [separate in-memory applier fixture](../tools/gen-state-root-vectors/README.md#separate-in-memory-nodetree-applier-fixture)
now executes six synthetic `NodeTree` commits and compares seven roots and 56
proofs with an independent leaf-map oracle. Stored zero remains present;
empty Put and Delete remove a leaf, and later duplicate events win. This mode
opens and closes a temporary in-memory database. Disk recovery, retention,
reorgs, startup, snapshot import, real resource budgets and proof RPC remain
open; production v3 and state-value acceptance stay disabled.
The [separate StateProof serializer fixture](../tools/gen-state-root-vectors/README.md#separate-stateproof-serializer-and-synthetic-binding-fixture)
adds 14 actual response encodings and independent bounded wire/key/root checks.
Seven primitive-proof cases model locally selected unsigned header identifiers
and context pins; these are research selections, not authenticated headers or
an enabled profile. That serializer mode excludes `LedgerApi` execution. Real readiness/retention
gates, JSON-RPC transport and accepted `VerifiedState` binding remain separate work.
The optional serializer build needs reference CGO; the three previous generator
modes remain without CGO and preserve their fixtures. The MIT runtime stays
unchanged, with v3/state-value refusal intact.
Canonicality, consensus finality, freshness and authenticated election remain
separate gates. Older "no state tree" audits apply to their pinned v1/v2
baseline, not every fork. Selective extension remains preferable to a rewrite.

## Reuse and later tracks

`edgepillar/zenon-spv` remains the implementation. Upstream SPV/vault history
informs compatibility; pinned `zenon-network/go-zenon` behavior supplies the
reference. Use SDK RPC/model adapters selectively, without importing a whole
wallet/runtime into the verifier. Treat TminusZ Commons as selected threat-model
and test input, the digitalSloth branch as protocol research, the browser light
client as a later comparison, and Trevor's SPV/pyznn as historical prototypes.

Bitcoin work starts only with a concrete use case and its own Bitcoin Core
header/retarget conformance, transaction-to-Merkle binding, reorg and freshness
model. Portal/custody integration needs a further review; neither prototype nor
Commons text is a ready implementation or a replacement for those gates.

The [separate actual LedgerApi method fixture](../tools/gen-state-root-vectors/README.md#separate-actual-ledgerapi-method-fixture)
now records 40 actual read-only method observations and 160 call events against
synthetic recording chain/store stubs. Twenty controls independently check
height/version gates, exact key/full-identifier forwarding, error precedence
and unsigned consumer selections. Later reference versions, mismatched store
identifiers, nonzero roots with errors and coherent provider root/proof
replacement cannot select consumer trust inputs. Three balance and one root
observations match only within this synthetic research scope. The same locked
CGO reference module preserves all four previous corpora and every runtime
input. JSON-RPC envelopes, accepted-header binding, real chain lifecycle and
resource budgets remain separate deliveries; state-value acceptance stays off.

The [separate offline HTTP/JSON-RPC fixture](../tools/gen-state-root-vectors/README.md#separate-offline-http-and-json-rpc-dispatcher-fixture)
now qualifies 86 in-memory reference handler observations, exact response
envelopes and 60 read-only Ledger delegate calls against the same recording
stubs. Twenty controls keep selected request ID/method/height/raw-key bytes and
unsigned context pins separate from permissive reference parsing and provider
proof/root consistency. All five prior corpora and the runtime refusal remain
unchanged. Actual reference execution is local macOS ARM64; native CI checks
independent offline fixtures. The next node research gate is actual chain
readiness and hash-bound retained-version provenance, followed by persisted
recovery/retention and realistic resource measurements. Accepted `VerifiedState`
integration and profile/activation agreement stay separate from these stubs.

The [separate real chain component startup fixture](../tools/gen-state-root-vectors/README.md#separate-real-chain-component-startup-fixture)
now exercises ten controlled cases through eleven actual `Init` calls and 66
state-tree reads. The selected source remains unchanged; serialized unsigned
momentums and manager/cache/genesis inputs are synthetic. Twenty controls check
short catch-up, the ten/eleven startup gap, ancestor/hash refusals, retained
roots/proofs and clean reopen. An ahead A tree can be retargeted to B's identifier
while remaining ready with A's retained root; all three independent B-state
observations refuse, including reopen. Height-only reads cannot authenticate a
hash. This closes a bounded startup conformance step and leaves hash-bound
version provenance unqualified. No full node, `Chain.Start`, signing, transaction
or live RPC runs. Crash/recovery, pruning and realistic retention/resource
measurements remain separate work, as do accepted-header/profile/activation
binding and production state-value acceptance.

The [separate controlled disk process exit and reopen fixture](../tools/gen-state-root-vectors/README.md#separate-controlled-disk-process-exit-and-reopen-fixture)
now exercises five planned child exits after returned `NodeTree` calls and one
normal-close control. Twelve reopens preserve the finite committed/truncated/
pruned frontier and selected retained heights. The independent oracle checks
240 observations, including canonical inclusion/absence proofs and exact
unavailable-version errors; twenty controls bind the inputs and scope. Logical
key/value record counts describe only this small one-key workload. They do not
measure physical disk, RAM, compaction or latency. Actual backend execution is
local macOS ARM64; native CI checks fixtures without the node or exit experiment.
In-flight write faults, power loss, torn writes, production crash recovery and
realistic retention/resource qualification remain open. The startup hash-bound
version provenance failure is unchanged, as are all seven prior corpora and the
MIT runtime. Accepted-header/profile/activation binding, human review and
authenticated distribution remain separate gates.

The [isolated patch dump decoder corpus](../tools/gen-state-root-vectors/README.md#patch-dump-decoding-and-diagnostic-replay)
adds finite truncation, malformed type/length, nonminimal varint and duplicate
write conformance. Its independent byte oracle checks 232 cases and every byte
prefix of the selected complete patch, including error-returned partial records
and recovered runtime bounds panics. All four constructor callers check ordinary
errors in the pinned source; production reachability and caller execution remain
unqualified. The [bounded research import contract](../tools/gen-state-root-vectors/README.md#bounded-patch-import-and-detached-staging)
now rejects malformed, incomplete or unselected dump bytes before the candidate
constructor. Isolated staging checks the complete ordered callback sequence and
publishes one owned memory map only after successful replay. Its 264 finite cases
include all 232 decode counterexamples, explicit limits, independent raw selection,
alias changes and injected constructor/replay failures; 254 rejections preserve
the entire target map. This is a research prototype under an exclusive caller,
not authenticated snapshot import or shared/durable storage. Typed state domains,
excluded snapshot state, accepted-header/profile/activation, retained hash
provenance, real workload budgets and review remain separate gates. The native
verifier and its state-proof refusal are unchanged.

The [initial and transient target bounds](../tools/gen-state-root-vectors/README.md#bounded-initial-and-transient-patch-targets)
check explicit entry/hex-payload caps before raw copying and delay the detached
clone until complete input selection and constructor/dump checks pass. Every
prospective callback map must fit, including temporary growth before a later
Delete. The changed import mode preserves all 264 prior outputs. A separate
46-case node-derived corpus covers exact caps, large ceiling cases, independent
map digests, untouched original aliases and rejected partial stages; 18 research
patches stage and all 46 proof consumers remain `REFUSED`. The independent
Python oracle recomputes full maps rather than repeating incremental accounting.
Whole-handoff memory, shared/durable writers and snapshot authentication remain
unqualified; the string payload caps are research policy, not resource budgets.

The [read-only raw patch planner](../tools/gen-state-root-vectors/README.md#read-only-raw-patch-plans)
now makes the bounded byte contract usable with a local regular dump file and
explicit caller-selected digest/count/limit inputs. Complete ordered events are
emitted only after byte parsing and output bounds pass; no constructor, Replay,
target replacement, database or NodeTree executes. Native consumer tests cover
file reads, actual CLI behavior, private refusals and all 264 prior inputs.
Syntax plans never accept state proofs or authenticate snapshot completeness.
Production target-size bounds, exclusive ownership, storage durability, realistic workloads,
typed/excluded state, authenticated retained version/hash and accepted header,
profile and activation remain separate gates. No new reference-node generation
is needed: the existing sixteen source-pinned corpora and backend inputs are
preserved. Their prior local reference execution remains distinct from current
native Python consumer tests and runtime CI.

The [patch planner resource observations](../tools/gen-state-root-vectors/README.md#read-only-patch-planner-resource-observations)
add 36 fresh Python workers for six independently selected synthetic input
families, including the exact 1 MiB raw cap, 1,024 records and 4,096-byte keys.
Each complete plan's ordered events, encoded length and hash are checked
independently. Plain elapsed time, traced Python peak and OS process high-water
memory remain distinct; startup/accounting, cache state and parent-pipeline
limits are explicit. Linux, macOS Intel and Windows observe this bounded
read-only workflow without resource pass thresholds. Representative application
budgets, concurrency, NodeTree retention, full snapshot/header authentication
and state-value acceptance remain unqualified.

The [selected-count read improvement](../tools/gen-state-root-vectors/README.md#selected-count-patch-read-allocation-comparison)
uses the independently selected byte count plus one instead of reserving the
full raw ceiling for every file. Exact returned length, global/type/descriptor
checks, raw digest/record selection and capped complete JSON publication remain
required. A verbatim pinned historical reader and historical encoder with unchanged parser pins
support 72 fresh comparison workers on the same six input families. Independent
complete-byte checks and native controls preserve refusals and sample inventories.
Python peak reduction observations remain separate from latency, OS accounting,
whole-pipeline/NodeTree resources and production budgets. This read-only change
does not add a writer, authenticate snapshots or enable state-value proofs.

The [bounded output encoding comparison](../tools/gen-state-root-vectors/README.md#bounded-patch-output-encoding-comparison)
examines the final JSON buffer separately. The current encoder appends bounded
ASCII chunks and returns complete immutable bytes including the newline. A
verbatim pinned bytearray encoder from the selected prior main remains the
reference, while read/parser/plan helpers and instrumentation are unchanged.
Seventy-two fresh matched workers retain all six fixed input families and bind
every complete output independently. The earlier read comparison explicitly
keeps its historical encoder in both modes; standalone observations measure the
current default. Actual Python peak observations qualify neither an API-wide
zero-copy guarantee, latency improvement, causal OS delta, NodeTree/retention
resources nor production budgets. All proof, snapshot and accepted trust gates
remain separate.
# Recorded account transaction method conformance

The [actual account transaction observations](../tools/gen-node-account-vectors/README.md)
add the exported node method to the source-pinned account byte checks. Existing
synthetic signatures are reused across 58 retained calls, with exact opaque
context lookup traces and independently reconstructed bytes. The separate SPV
tests keep the original signed chain and commitments fixed; a method match
cannot furnish missing commitment evidence, activation, producer authority,
canonicality, consensus finality or state proofs. Direct nil calls and forbidden
user descendants remain recorded method boundaries. This adds no runtime
validation or accepting network/state profile. Real store execution and full
account protocol validation remain separate conformance work.

## Actual node missing-account context gate

The [separate context failure corpus](../tools/gen-node-account-context-vectors/README.md)
extends the opaque-store transaction experiment with 50 actual calls through
both node entry points. Exact synthetic store plans, complete account preimages,
lookup arguments and error precedence are independently checked. All 38 returned
errors and 12 selected nil-store/frontier panics remain; no validator success,
basic account checks, signature checks, chain startup or new signatures occur.
This closes a bounded source-pinned missing-state conformance gap. It does not
establish fault reachability on a real node, authenticate context or expand
runtime acceptance. Real store/consensus inputs, consumer and trust selection,
network qualification, independent review and release remain separate gates.

# Recorded account basic checks with memory stores

The [basic account store observations](../tools/gen-node-account-basic-vectors/README.md)
close a finite gap left by the transaction/context experiments. Fifty actual
method calls use actual in-memory account and momentum stores. The independent
oracle checks complete hash preimages, complete protobuf seed records and all
selected database reads. Basic checks reject negative amounts or absent/corrupt
acknowledgements even where the selected transaction method succeeds; the basic
method does not substitute for hash/signature validation.

Caller-selected handles and unsigned momentum metadata remain synthetic trust
inputs. The experiment does not qualify account execution, full node validation,
real-chain histories, nonzero PoW, receive/mailbox/contract paths, consensus,
production resources, canonicality, finality, network activation or state-value
acceptance. Those remain separate roadmap gates, as do independent review and
authenticated release distribution.

The follow-up native runtime regression consumes all 50 immutable observations
against the original fixture's independently selected trust/commitment inputs.
It distinguishes ten accepted inclusion/signature observations, thirty rejected
inputs and ten unsupported-version/type refusals. Basic-method matches cannot
bypass hashes/signatures, transaction-method matches cannot bypass scalar checks,
and the selected memory stores cannot supply a missing retained committing header
or a missing account commitment proof.
This adds runtime boundary coverage without changing acceptance or authenticating
the synthetic store history. Its merged source has exact native-platform CI
and artifact qualification; that evidence remains bounded to its recorded scope.

The next [RPC integration controls](../internal/conformance/node_account_basic_rpc_test.go)
use the actual fetch client with loopback HTTP/JSON-RPC envelopes and the same
fifty immutable node observations. Thirty-eight fail conversion with no returned
blocks; twelve reach the unchanged segment verifier, where ten accept inclusion
and signatures and two reject missing signatures. Independently selected original
accounts, ranges, trust inputs and commitments remain separate from provider
payloads and node method results. Four missing commitment-input controls and six
complete-range controls preserve those boundaries. This closes a finite RPC
conversion gap, without executing a new node or enabling an acceptance profile.
Native CI must qualify the sixty RPC controls against their exact published source.
Real histories, nonzero PoW, receive/mailbox/contract execution, independent
consumer/network inputs and reviewed release remain separate roadmap gates.

The [compiled observer follow-up](../internal/conformance/cli_node_account_basic_test.go)
adds the same fifty recorded inputs to actual proof-only collection, retained-only
verification and independently selected query consumption. Thirty-eight collection
failures emit no partial bundle; both empty signatures stop at the verifier;
ten observations match the original target with inclusion/signature guarantees.
Eight additional controls keep missing retained headers or omitted confirmations
from reaching consumption and make different consumer targets/tips fail there.
Every run checks actual completion, exact read-only requests, input preservation,
summary privacy and removal of raw private files. The fifty-eight native controls
require exact source/artifact qualification. All trust attestations are synthetic;
full protocol execution, real histories, independent consumer/network selection,
human review and authenticated release remain separate gates.

## Recorded receive protocol-store boundaries

The [separate receive mode](../tools/gen-node-account-basic-vectors/README.md#separate-user-receive-memory-store-mode)
adds 44 actual node method calls with memory account/ledger stores and the
original signed user receive. The independent oracle checks all preimages,
88 complete store maps and 120 raw reads, including actual prefixed snapshot
reads. Source/confirmation/received and receiver-frontier checks belong to the
basic method; a transaction-method match does not establish those checks.
Absent confirmations, an incoherent index, an empty received marker and the
exact receiver enforcement boundary are retained as scoped method observations.

The native runtime controls preserve 36 inclusion/signature acceptances of the
unchanged original receive, reject eight changed signed inputs and refuse four
missing retained-header/proof selections. Inclusion never claims receive execution
eligibility or state transition. The original first-send corpus/locks, signed
history and runtime acceptance remain unchanged. Reference execution is local
macOS ARM64; CI consumes recorded bytes on the three native platforms. Full
execution, real authenticated histories, mailbox/contract/nonzero-PoW paths,
independent consumer/network inputs, reviewed release and authenticated
distribution remain separate gates. Exact published source/artifact qualification
is required before treating this local step as delivered.

The [receive RPC follow-up](../internal/conformance/node_account_receive_rpc_test.go)
passes all 44 unchanged recorded inputs through the production fetch client and
a loopback HTTP/JSON-RPC peer. Thirty-six unchanged receives reach inclusion and
signature verification; eight changed signed inputs fail hash conversion before
any block is returned. Every observation also exercises the original two-block
send/receive range: a failed later receive discards the valid first send.
Four further controls keep missing retained committing headers and supplied
proofs refused after both positive node method observations convert successfully.
These 92 native controls use original account/range/trust/commitment selections
and preserve verified state. They add no node calls, corpus regeneration,
signatures, network pilot or runtime acceptance change. Protocol-store outcomes
never select expected inclusion results, and `STATE_TRANSITION` remains unproven.
Exact source/artifact qualification remains required before delivery; real
histories, execution, independent consumer/network inputs and review remain open.

The [compiled receive observer follow-up](../internal/conformance/cli_node_account_receive_test.go)
passes all 44 recorded observations through ordinary proof-only collection,
retained-only verification and independently selected query consumption.
Thirty-six unchanged receives match bounded inclusion/signature requirements;
eight changed signed inputs stop collection without a partial bundle or a later
child. Eight additional positive-method controls retain absent-header/proof and
different consumer target/tip boundaries. All 52 controls check actual completion,
exact read-only requests, input preservation, summary privacy and private cleanup.
No reference node is rerun and no signed input, corpus or runtime policy changes.
Synthetic store outcomes and this compiled workflow establish neither execution
eligibility nor state transition. Native CI and artifact qualification must bind
the exact published source before delivery. Independent consumer/network trust,
human review and authenticated distribution remain separate gates.

## Recorded account PoW byte and method boundaries

The [separate finite PoW corpus](../tools/gen-node-account-basic-vectors/README.md#separate-finite-account-pow-mode)
records 32 fixed nonce/difficulty probes and 64 method calls at the same pinned
node source. Independent SHA3, byte-order and unsigned threshold checks cover
both sides of `2^63` and the maximum `uint64` values. Ten nonce probes match;
the memory-store methods record 11 matches, 53 rejections and no panic. Complete
hash preimages, 128 store maps and ten raw reads keep method composition explicit.
Matching work does not re-sign changed input or establish a full protocol match.
The zero-difficulty producer helper is not called. Previous corpora and module
locks remain unchanged. No wallet, nonce search, signature generation, node
service or network pilot runs. The MIT verifier's account-PoW, state-transition
and state-value boundaries remain unchanged. Exact published source/native
CI/artifacts must qualify this finite step; authenticated histories, protocol
resource limits, consumer/network trust, human review and release remain open.

The [native PoW boundary follow-up](node-account-pow-boundaries.md) now consumes
all 64 immutable method observations through actual segment verification and
loopback production RPC conversion. Its 324 controls distinguish changed claimed
hashes from coherent hashes with unchanged signatures, preserve exact upper-half
`uint64` inputs, discard failed complete ranges and refuse missing commitment
inputs through both layers. Node work or method matches never select trust or
expected acceptance. No corpus, signature, runtime policy, reference-node call
or resource observation changes. Native source/CI/artifact qualification remains
required; account PoW, state transitions, real histories and independent network,
review and release gates remain separate.

## Qualification cost: selected target hex validation

The [selected hex recipe](../tools/gen-state-root-vectors/README.md#selected-target-hex-validation)
optimizes character membership in 22 existing complete Python qualification
programs. All prospective-map copies, full entry/byte accounting, error ordering
and independent byte checks remain required. Builtin strings use `str.translate`;
other types retain the original iteration behavior. The original producer inputs
and recorded source pins stay intact. A separate execution manifest binds the
current runner and selected function seams, which restore on success or failure.
The original commands remain available, and later imports and child CLI programs
stay unchanged. Finite equivalence and rollback controls do not qualify a native
CI speedup or production workload budget. Exact source, native CI and artifact
validation remain required before delivery. Trust, activation, independent review
and authenticated distribution gates are unchanged.

The larger file NodeTree import and complete child lifecycle checkers and
their 28 and 34 controls now use the same explicit seam. Their recorded source,
sample files, complete graph/proof checks, ordered refusals and actual child
exit/completeness requirements remain intact. Only the selected loaded function
instances change; original commands and child processes retain their own source.
Local timing observations do not establish a whole CI or production speedup.

The separate driver/build resource checker and all 21 controls also use the
explicit seam. Their complete child byte checks, source/sample bindings, SELF
lifetime RSS, nested build intervals and waited-child CPU contracts stay intact.
This portable replay performs no build or new resource observation. Compiler
peak memory, whole-pipeline memory, cache state and production budgets remain
unqualified; the recorded measurements keep their original boundaries.

The complete file-to-NodeTree handoff and retained-tail checker/control pairs
also select the explicit seam. All 25 handoff and 24 tail controls remain,
including full compressed records/refcounts, sparse proof bytes, stored-zero
and absence distinctions, refusal ordering, pruning and clean reopen. Their
original CLI children, corpus/sample bytes and recorded source inputs stay
unchanged. Portable replay performs no Go, LevelDB or resource observation;
the 132 handoff and 96 tail child samples retain their recorded scopes.

The sparse-oracle and complete-driver projection pairs use the same hex-only
selection and retain all 28 and 30 controls. This selection changes no level
projection function, selected query set, every-leaf hashing, complete stock
oracle, captured worker/build/child outcome or recorded resource boundary.
The 24 oracle workers and four complete driver workers remain recorded evidence;
the portable checkers launch no new workers, builds, nodes or observers. Their
reference/projected modes remain separate from the current hex execution mode.

The whole owned-import resource and fixed prior/candidate callback comparison
pairs also select the explicit hex seam and retain all 24 and 21 controls.
All 12 complete corpus cases, prospective maps, callback/alias bytes, target
counts, refusal ordering and original CLI children remain required. The
comparison still binds all 288 recorded samples and 36 ownership-control
outcomes to their original source pins. The portable checkers execute no new
reference importer, node or resource observer and qualify no latency or budget
claim about those recorded producers.

The [retained-state sequence oracle](retained-state-sequences.md) now uses an
all-field header comparison in its repeated full-window checks. Independent
reflection equivalence controls retain nil/empty distinctions and every scalar,
hash, public-key and signature bit. Both sequence matrices, their exact steps,
retained capacities, immutable predecessors, cryptographic validation and query
assertions stay intact. Comparator measurements have a separate scope from
complete test or pipeline timings. This changes no runtime verifier, signed
fixture, trust input, network behavior or production acceptance gate. Exact
published source/native CI/artifact qualification remains required for delivery.

The [bundle row storage follow-up](bundle-row-owned-slots.md) removes one
temporary allocation per decoded row by filling private result-slice slots.
All count checks still precede a callback, only successful rows consume shared
budgets, and receivers change only after complete success. The pinned old
helper, 3,024 finite cases, ownership/error-order controls and bounded fuzzing
cover all six concrete row types. Both full flat-content and compiled consumer
grids retain their original inputs, signatures, targets and trust boundaries.
Native allocation observations keep their own scope and do not qualify a
whole-CI speedup, production resource budget or stronger proof guarantee.
Exact source/native CI/artifact qualification remains required before delivery;
independent consumer/network inputs, human review and release gates remain open.

The flat-list follow-up in the same [row-storage contract](bundle-row-owned-slots.md#bounded-flat-list-capacity-hint)
adds a private initial-capacity hint for flat account headers. Encoded bytes,
remaining row allowances and a fixed 100,000-slot ceiling bound the reservation;
the original JSON decoder and refusal order still govern acceptance. A separate
16,640-case array oracle, 8,192 adverse byte substitutions, 6,480 pinned-reference
comparisons and populated ownership/budget controls cover the change. Native
allocation observations retain the whole original M/P and compiled consumer
grids. They do not qualify process memory, latency, canonicality, finality,
network activation, state-value acceptance or production readiness.

The [fresh grouped CLI build follow-up](conformance-cli-builds.md) reduces
repeated Go-tool launches within one conformance scenario. It creates every
selected ordinary executable in that test's own directory with bounded build
parallelism; there is no cross-test executable cache. Complete byte comparisons
with the pinned individual-build helper, private-output mutation and unchanged
candidate-export identities cover all seven commands. Existing test selections,
content/retention grids, concurrency and all 59 offline pilot scenarios remain
required. This test-harness change does not strengthen runtime or proof claims,
and its component observations do not qualify a whole-CI speedup.
