# Native cache replay-window experiment

This M2 experiment reproduces missing intermediate momentum records with real
disk ledger, cache and NodeTree managers, then tests a separate experimental
preflight. It changes no SPV runtime acceptance path and enables no state-value
claim. The selected source is
[`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/tree/9c71ae82fc983e16f914ae085d4034030c8ebe3b).

| Selection | Runtime tree | Complete build tree |
| --- | --- | --- |
| Parent, including the [cache-base preflight](cache-forward-replay.md) | `57759bee9f143a10ef5a60880170b62a61ede7de` | `7d7c469edb3e7d934cc9333db69d49011a73f773` |
| Experimental complete-window preflight | `40cc88bb9671cef130cb87ccb3c726f7e8977299` | `cde719c8defa1b25f7e043815ebf27ec49ea05a0` |

The original source has 467 blobs. The parent build adds three component control
files and one tagged entrypoint. The candidate has 472 blobs, including the new
control file and a disclosed compatibility adjustment to the old forward tests.
The runtime replacement changes only `chain/cache.go` relative to the parent;
module inputs, disk format, cache-manager interface and SMT profile remain fixed.

## Reproduction and resulting behavior

The source's missing-height reader returns `(nil, nil)`. The parent's cache
startup loop dereferences that result. Five bounded cases prime the unsigned
source genesis and three empty-patch successors through height four. The cache
starts at height one, height four, or a separately created empty cache.

Two cases remove only the closed fixture's momentum-body record at height two
or three. Ledger frontier and patch rows remain present. Each case performs two
public `Chain.Init`, query and `Stop` attempts. The removed entry is then restored
explicitly as a fixture control, followed by two more startup/query/stop attempts.
No runtime repair is selected.

| Closed fixture | Parent observations | Candidate observations |
| --- | --- | --- |
| Intact behind, current and empty cache | Replay or reopen succeeds | Same final logical cache and selected witness |
| Missing first replay momentum | Two recovered `Init` panics; no available state query | Two ordinary missing-momentum errors; complete logical cache unchanged |
| Missing later replay momentum | First attempt reaches height two; both attempts panic and observe that same prefix | Two ordinary missing-momentum errors before the first write; complete logical cache unchanged |
| Exact fixture entry explicitly restored | Valid replay and clean reopen resume | Valid replay and clean reopen resume |

The test caller records recovered panics separately. All ten process exits are
zero because the caller completes its observations; that exit code is never
interpreted as successful startup. Every observed `Stop` completes and withdraws
readiness. Failed startup queries return no root, value or proof.

The experimental runtime validates the entire selected stored identifier path
before its first cache write. It checks presence, height, predecessor hash and
the final full target identifier using constant additional memory. During replay
it repeats presence/linkage checks, rejects absent or mismatched prefetch results,
checks the acknowledged cache identifier, and breaks before incrementing the
last uint64 height. Stored linkage is not ledger authentication or fork choice.
This is not a transaction across later replay I/O: a later lookup or application
failure can preserve an already acknowledged prefix.

## Recorded native evidence and portable checks

Two ordinary Darwin ARM64 binaries produced five cases each. The final candidate
also passed 14 native component roots, 46 test results and two packages with the
race detector enabled and no skips. These include the previous 13 logical roots
and 15 new replay-window subcases. The old forward tests receive only an actual
predecessor hash in their positive fixture and the two resulting lookup traces;
their five adverse predecessor cases and other assertions stay unchanged.

The parent observations came from a task that subsequently failed to compile a
candidate test calling a pointer method on a temporary value. That failed task
is preserved as failed. Its five completed parent cases are reused as evidence;
they are not presented as a successful candidate qualification. The test assigns
the identifier to an addressable variable in the final candidate source, whose
complete native controls and five ordinary cases were then executed successfully.

The [recording](../tools/gen-state-root-vectors/testdata/native-cache-replay-window.json)
contains 196 events and 28 queries: 20 available component witnesses and eight
refused queries. The bounded reader independently reconstructs three 160-byte v1
hash frames, both 121-byte removed protobuf/wrapper values and their exact keys,
and one 256-level witness fold. It checks every recorded event, closure state,
refusal, restore and logical-store equivalence. Complete logical-store digests
remain native observations; the reader does not reconstruct all database bytes
or authenticate the private execution receipts. Raw diagnostic paths are excluded.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_cache_replay_window_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_replay_window_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_replay_window.py
```

The 10 preparation and 20 recorded-data controls cover substitutions, missing
events, hidden panics, partial cache writes, false readiness, leaked results,
inflated evidence, wrong fault bytes, duplicate names and incomplete output.
The reader has a local 256 KiB corpus cap and starts no compiler, backend or
network request. Hosted Linux, macOS and Windows steps execute these portable
checks against the recorded Darwin ARM64 observations; they do not rerun this
reference-node experiment on those platforms. Workflow presence alone does not
qualify an exact CI commit or its artifacts.

## Resource and reproduction boundary

The candidate follow-up reuses the completed parent evidence instead of another
ordinary build and five database cases. Its race tests and ordinary build share
one private compiler/module cache serially within that owned task. All 75
verified dependency inputs for 25 linked modules are reused with zero new
transports. Whole-module-graph verification remains not qualified; the earlier
unused-input failure is preserved. No closed cache is adopted for a later task.

The 20 recorded-data tests reuse a source selection only within their serial
test class, with complete source bytes and selection checked before and after.
The no-execution control still evaluates the real selection. In one local run,
the same 20 test methods fell from 56.085 to 1.448 seconds. This measures that
test group, not native backend or pipeline performance on other platforms.

Use an admitted, newly owned private workspace for a new native reproduction.
Source acquisition, SHA-256 checks, compiler/platform pins, actual exit/output
completeness, retained reports and cleanup remain the caller's responsibility.
The preparer can inspect the finite plan without execution:

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_cache_replay_window.py plan \
  --workspace "$NEW_PRIVATE_WORKSPACE" --go "$PINNED_GO"
```

The plan retains a 10 GiB free-space floor plus expected allocations, a 2 GiB
expected allocation and a 4 GiB task quota. These are admission settings, not
measured production requirements. Compiler peak, simultaneous pipeline peaks,
representative ledger size/churn, full patch-retention validation, concurrency,
real power loss, live reorg and full-node service behavior remain open.

Accepted-header/root binding, profile agreement, network activation, independent
review and authenticated distribution remain separate gates. Anchor, schedule
and context-pin trust inputs stay explicit. The consumer remains `REFUSED` and
production state-value acceptance remains disabled.
