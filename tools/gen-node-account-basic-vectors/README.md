# Recorded account basic checks with memory stores

This isolated research module calls the actual node's `AccountBlock` and
`AccountBlockTransaction` methods at commit
`c64ed6279ff1d07335dab0ac36156dec8b5b71e9`. Its module version and checksum
match the preceding transaction/context experiments. The MIT runtime imports
no node dependency; this tool uses the GPL reference node only in its separate
module.

The [immutable corpus](../../internal/testdata/conformance/node-account-basic.json)
contains all 50 calls: 25 selected profiles of the existing signed first user
send, each passed to both methods. It records 11 method `MATCH` results, 39
`REJECT` results and no panic. No keys or signatures are generated. Mutations
retain the original claimed hash and signature, except for the explicitly
selected hash/signature mutations.

The context adapter supplies caller-selected account and momentum handles.
Those handles forward only selected reads to actual `account.NewAccountStore`
and `momentum.NewStore` instances backed by actual `db.NewMemDB` databases.
The stores start empty or with explicit `db.SetFrontier` records. Their full
maps, ordered store calls and 21 raw database reads are retained. Iterators are
released; no disk database, chain lifecycle, consensus service or network runs.
Chain identifier metadata is synthetic. Acknowledgement records are unsigned
synthetic momentums carrying selected hashes; they are not validated momentums.

`AccountBlock` reaches basic checks for version, chain identifier, block type,
amount/token/from-hash constraints, previous frontier and acknowledgement
presence/order. `AccountBlockTransaction` reaches its hash/signature method
checks. With this selected user send it does not perform the basic checks.
For example, the negative amount shares the original magnitude hash and passes
the transaction method while the basic method rejects it. Missing, wrong-hash
and malformed acknowledgement records similarly leave the transaction method
unchanged. Conversely, zero/mutated claimed hashes and a missing signature do
not make the basic method perform cryptographic validation. These observations
require consumers to respect the method composition boundary.

The [independent checker](check.py) reconstructs all 50 complete account hash
preimages, both complete store maps for every observation, their proto3 seed
bytes and all selected database keys/reads. Frontier identifiers use protobuf;
hash-to-height and entry-by-height keys use big-endian heights. The checker
imports no node/protobuf backend and runs no signature process or database.
Its [corruption controls](check_test.py) cover outcome substitution, missing or
reordered calls/records, seed/read corruption, type aliases and scope claims.
Native CI runs these checks on the recorded corpus; it does not execute a new
reference node on the three hosts.

The [SPV runtime regressions](../../internal/conformance/node_account_basic_test.go)
project these 50 observations into the lower-level segment verifier. Trust inputs
and commitments come from the original signed fixture rather than from selected
store handles or a node method result. Expected SPV outcomes are 10 `ACCEPT`,
30 `REJECT` and 10 `REFUSED`; the accepted scope is inclusion and user signature
verification. The two positive method observations also refuse when the committing
header is outside the retained state or when no proof is supplied with a retained
header. Queries preserve the selected state. The
projection is a fixed-corpus test adapter, not a production RPC decoder or an
authenticated node context.

The separate [RPC regressions](../../internal/conformance/node_account_basic_rpc_test.go)
send the same fifty recorded account blocks through the actual fetch client and
a loopback HTTP/JSON-RPC peer. The requested account and ranges are selected from
the original fixture, independently of the response. Expected conversion errors
are selected by fixed input profiles, never by node `MATCH`: thirty-eight fail
without partial results. Twelve blocks reach `VerifySegment` under the original
trust/commitment inputs; ten accept inclusion/signatures and both empty-signature
cases reject. Every query preserves the selected state. Four controls keep
missing retained headers/proofs refused even after successful RPC conversion.

Six additional controls use the original signed two-block user segment. A
valid first row is discarded when the later row has a wrong hash, invalid amount,
unsupported version, wrong height or different account. The different-account
control is an original hash-consistent embedded block. No new node observation,
signature, corpus regeneration, real RPC service or network pilot occurs.
The fifty-four lower-level controls and sixty RPC controls run in separate
native CI steps; actual RPC conversion of these fixed inputs is a finite
integration result, not production or full protocol qualification.

The [compiled observer regressions](../../internal/conformance/cli_node_account_basic_test.go)
exercise all fifty unchanged observations through the ordinary proof-only
collector, retained-only verifier, query consumer and observer. Original signed
momentum bytes and locally selected trust/context inputs are fixed before any
collection. Thirty-eight conversion failures publish no partial bundle; both
empty signatures stop at the verifier; ten observations match the independently
selected original target with inclusion and signature guarantees. Node `MATCH`
is not a consumer expectation or an authentication source.

Both positive node entry points also exercise four independent selection gates:
missing retained committing headers, deliberately omitted confirming heights,
another original consumer target and an earlier expected tip. All fifty-eight
runs check actual child exits, exact request counts, summary privacy, unchanged
input bytes/identities/modes, absent state writer locks and private file cleanup.
No corpus regeneration, new node call, key/signature, protocol activation or live
network execution is added. Exact native CI/artifact qualification is required
before treating this local compiled workflow as delivered.

From this directory, regeneration with a Go 1.25 toolchain is:

```sh
CGO_ENABLED=0 GOWORK=off GOTOOLCHAIN=local go run -mod=readonly . ../../internal/testdata/conformance/account-segments.json > node-account-basic.json
```

Review the generated bytes against the recorded fixture before replacing it.
The independent checks, run from the repository root, are:

```sh
python3 -I -B tools/gen-node-account-basic-vectors/check.py
python3 -I -B tools/gen-node-account-basic-vectors/check_test.py -v
go test -count=1 -run '^TestNodeAccountBasic' ./internal/conformance
go test -count=1 -run '^TestCompiledNodeAccountBasicObserver$' ./internal/conformance
```

`MATCH` means one method returned no error in this finite synthetic context.
It does not establish full node validation, account execution, coherent signed
history, authenticated context, production resource limits, canonicality,
consensus finality, network activation or state-value acceptance. Difficulty is
zero and receive/mailbox/contract/sequencer paths are outside this selection.
All earlier corpora and runtime trust inputs remain unchanged.

## Separate user receive memory-store mode

The `--receive` mode records 44 additional calls at the same pinned node commit,
using the original signed `user-type-3` receive. Twenty-two explicitly selected
profiles run through both exported methods. Actual memory account and ledger
stores contain synthetic previous/source account records, hash indexes,
confirmation heights, acknowledgement/frontier identifiers and received markers.
The adapters preserve raw read interception through the ledger's actual
`Subset`/`Snapshot` implementation. The complete 88 store maps and 120 database
reads are retained. Every input block and map is checked unchanged after each call.
Each iterator entry also pins its actual `Get` status: the memory database's
empty deletion tombstone is absent to `Get`, while a present empty marker is not.
These seed-status reads occur outside the 120 recorded validator reads.

The [separate corpus](../../internal/testdata/conformance/node-account-receive.json)
has SHA-256 `153c7563d863ccfb1563a1bdaca310215a415236ef0bf9e85c2e44228a1fe21c`.
It records 23 `MATCH`, 21 `REJECT` and no panic. The transaction method performs
no protocol-store reads for these selections. The basic method distinguishes
missing/corrupt source indexes and bodies, confirmation later than the selected
acknowledgement, previous acknowledgement ordering and already received sources.
Four changed receive fields fail basic constraints and original hash binding in
the transaction method. No signature or claimed receive hash is regenerated.

At this source, an absent confirmation record returns zero. It does not become
an authenticated historical confirmation. Receiver mismatch is enforced using
the ledger frontier at `10109240`, including at/after the boundary even when the
receive acknowledges `3000`; the before-boundary method selection matches.
A present empty received-marker value is still treated as received. One explicitly
incoherent hash-index selection resolves another original send and matches below
that receiver boundary. Such synthetic store selections qualify neither reachable
live-node states nor validation of an authenticated ledger's indexes or history.
All observations, including these matches, remain in the corpus.

The [independent checker](check_receive.py) reconstructs complete preimages,
protobuf source/index/frontier records, big-endian heights, ordered method calls
and every raw read, including prefixed snapshot reads and missing-key errors.
It imports no node/database/protobuf implementation and starts no signature process.
Its [corruption controls](check_receive_test.py) bind inventory, byte/lookup/error
precedence, the frontier boundary and explicit scope limits.

The [runtime boundaries](../../internal/conformance/node_account_receive_test.go)
keep the original signed momentums, trust inputs and commitments separate from
the supplied stores. Thirty-six unchanged receive observations prove only bounded
inclusion/signatures; eight changed signed inputs reject. `STATE_TRANSITION`
remains unproven, including where the basic method rejects a supplied context.
Both exact positive entry points also refuse a missing retained committing header
or missing supplied commitment. Method matches cannot furnish either input.

The [receive RPC controls](../../internal/conformance/node_account_receive_rpc_test.go)
use the same 44 pinned observations through the production fetch client and a
loopback HTTP/JSON-RPC peer. Request account, height and count come from the
original signed fixture, independently of peer fields and protocol-store outcomes.
The 36 unchanged inputs convert to the original signed receive and prove bounded
inclusion/signatures. All eight changed signed inputs fail hash conversion with
no returned block. None of the supplied confirmation, received-marker or source
store selections supplies execution eligibility to the verifier.

All 44 observations also run as the later row of the original two-block
send/receive range. The same eight errors discard the valid first send; 36
complete ranges preserve both original blocks and their bounded guarantees.
Four positive-method controls refuse a missing retained committing header or
supplied account proof after successful conversion. All 92 controls preserve
verified state and check the exact single read-only request. No new node method,
key/signature, corpus, real RPC endpoint or network qualification is introduced.
Native CI runs lower-level receive and RPC controls in separate steps, avoiding
duplicate execution; exact source/artifact qualification remains required.

```sh
go test -v -count=1 -run '^TestNodeAccountReceiveRPC' ./internal/conformance
```

Regenerate this separate corpus from the module directory:

```sh
CGO_ENABLED=0 GOWORK=off GOTOOLCHAIN=local go run -mod=readonly . --receive ../../internal/testdata/conformance/account-segments.json > node-account-receive.json
```

Run the offline checks from the repository root:

```sh
python3 -I -B tools/gen-node-account-basic-vectors/check_receive.py
python3 -I -B tools/gen-node-account-basic-vectors/check_receive_test.py -v
go test -v -count=1 -run '^TestNodeAccountReceive' ./internal/conformance
```

The original no-flag generator output and all earlier fixtures/locks remain
byte-for-byte unchanged. Actual new reference method execution is local macOS
ARM64 with CGO disabled. Linux/macOS Intel/Windows CI consumes the recorded
corpus; it does not execute that node. Full account execution, contract/mailbox
paths, nonzero PoW, authenticated histories/activation, independent network and
consumer inputs, production budgets, review and distribution remain separate
gates. The MIT runtime and its state-value refusal are unchanged.
