# Public Chain reorg and fresh-process reopen

This finite M2 comparison uses the selected
[go-zenon revision](https://github.com/digitalSloth/go-zenon/commit/9c71ae82fc983e16f914ae085d4034030c8ebe3b)
and the existing experimental runtime tree
`d56bf37a23ddf0ec0f8af2eca62be01bb6c54dbc`. It adds one ordinary observer
entrypoint, producing tree `6a0803e012483bfc612cbdfa28581cc74be40c43`;
the runtime and module files are unchanged. The ordinary Darwin ARM64 binary
was built with Go 1.25.14 and retained before either process ran. Its SHA-256 is
`e20f8111d55a2319ee18b953a9cc111b19b6f68cab9d3744c220bde0e8331770`.

The [recorded corpus](../tools/gen-state-root-vectors/testdata/native-public-chain-reorg-reopen.json)
contains complete stdout and stderr from two successful processes. Both use real
disk ledger, cache and state-tree managers through public Chain APIs. The first
initializes and starts the chain, advances through A2/A3, rolls back to A1, and
inserts B2/B3. The second OS process uses a fresh genesis configuration and fresh
managers to reopen those closed stores at B3. Both Stop calls are repeated and
leave the instance unready.

## Independently selected bytes

Before the backend ran, a separate Python encoder fixed the key, patch bytes,
160-byte v1 header preimages, complete identifiers, roots and canonical proofs.
The input digest is
`220bb05cd50a6e3b174022950f66530c28c0c8f93529ac1194bfa5c15b323b3f`.
It extends the previously checked source-genesis witness and verifies the known
empty v1 successor hash before constructing these new local headers. The
candidate's newly returned roots do not select their own expectations.

| State | Height | Selected balance value | Partial-SMT root |
| --- | ---: | --- | --- |
| A1 | 1 | 100000, present | `864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d` |
| A2 | 2 | 0, present | `513b3eeb7dbbd99fcc99d3296542fbbca8843607e146e10f866bd37d81010416` |
| A3 | 3 | 1, present | `775b473ce894ae3901a80d883644720f857b3d5fc6b4a419a2fca58d6ed47a71` |
| B2 | 2 | 42, present | `3ada91743bbc3b0da5ffd9926d266756bf0ba2918f2840e1932942ede145c436` |
| B3 | 3 | Absent | `4e2b2ff1db8c10d7bcacb054b748c88f38618ebd3c3dfed81f3a5d7bd61db694` |

A2/B2 and A3/B3 have different full identifiers at equal heights. The four new
momenta are unsigned v1 fixtures with empty account-block content and a zero
header StateRoot. Their balance patches exercise local manager maintenance;
they are not a consensus-valid network history or accepted-header state proofs.
Cache account-block extraction and cache balance values are outside this case.

## Recorded outcomes and limits

All 57 preselected events match: 45 in the first process and 12 in the second.
There are 31 combined root/proof observations: 15 exact matches and 16 refusals
for missing versions or a different hash at the selected height. Stored zero
remains present and differs from absence. Truncated A versions cannot be queried
as the new B versions, including after fresh-process reopen.

Each of four speculative projections is repeated, leaves the prior committed
root/frontiers unchanged, and does not create the next retained version. Three
old-identity projection requests are refused. Updates follow the selected
broadcaster's cache, state-tree, ledger order under the real insert lock.
Rollback follows the selected bridge's ledger, cache, state-tree order.

The three complete ordered raw KV image digests and counters match before and
after reopen. Zero-length raw values remain counted as present rows. These
digests are recorded observations, not an independent reconstruction of the
large genesis databases, physical LevelDB files, crash recovery or durable
network history.

The runtime is unchanged from the preceding startup-record comparison. This
case adds sequential component advancement, rollback and fresh-process reopen;
it leaves node/client profile agreement, concurrent lifecycle, interruption,
retention/import workload and full node qualification open. There is no network,
consensus verification, signing or broadcast. Runtime v3/state-value acceptance
and the consumer result remain **REFUSED**.

## Cost and evidence handling

One build and two processes reuse the already verified source/module inputs;
there are no new source or dependency archive transports. The linked build
inventory matches the 25 selected modules against the source sums.
Whole-module archive-graph qualification remains `NOT_QUALIFIED`.

The private run reserved 2 GiB expected allocation with a 3 GiB task quota above
the 10 GiB production floor and other reservations. Its closed generated
workspace contained 342,031,127 logical bytes, including compiler/module caches
and the test stores. It was removed only after process completion, full file
identity checks, retained input/output references and successful task close.
This is not a measurement of APFS physical reclaim, peak RSS or a representative
node budget. Existing historical data and held evidence were not cleaned.

The complete ordinary stdout totals 40,304 bytes. The small portable corpus
retains the build inventory and process streams; it does not recursively package
workspaces or copy raw stdout into another ZIP. The binary, exact inputs,
original execution receipts and closed workspace manifest remain protected.
Logical test data can be regenerated from those inputs; byte-for-byte physical
LevelDB reproduction and authenticated distribution are separate gates.

## Reproduction and portable checks

Use verified offline inputs, a new owned task, registered disposable workspaces
and bounded foreground execution. Configure the stated reservation and quota
before the build. The source preparer does not compile, run a backend, download
dependencies or clean caller data. Source and destination must be disjoint;
an existing destination or either directory nested inside the other is refused
before the source snapshot is read.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_public_chain_reorg_reopen.py prepare \
  --node-source "$PINNED_COMPLETE_NODE_SOURCE" --workspace "$NEW_OWNED_WORKSPACE" \
  --go "$PINNED_GO"
```

The returned plan includes the fixture, pinned source tree, build command and two
run templates. The first run needs a new empty owned case root. The second must
use that same root after the first process exits and closes its stores.
`verify` checks the prepared source/fixture inventory without executing it.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_public_chain_reorg_reopen_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_public_chain_reorg_reopen_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_public_chain_reorg_reopen.py
```

The reader independently regenerates the selected fixture and checks the full
recorded event sequence, captured stream digests, execution/source pins and
refusal scope. Direct stdout-object inputs are also supported; they perform
recorded event checking only. The added CI steps replay these controls on Linux,
macOS Intel and Windows; check the exact revision's run status separately.
These steps do not rebuild or execute the reference node on those
platforms, authenticate private execution, or establish canonicality, activation,
independent human acceptance or production readiness. Storage tooling is outside
this change.
