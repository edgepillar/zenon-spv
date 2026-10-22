# Public Chain reads during Stop

This M4 experiment selects the public `Chain.Init`, `StateRoot`, `GetProof` and
`Stop` methods with real disk ledger, cache and tree managers. It observes calls
at their caller boundaries. It does not establish an internal database or mutex
interleaving, a network activation, canonicality or consensus finality.

The source is `digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`
with the existing experimental runtime tree
`053c87e5bc4addd1bb70a467cb34facd439e66bc`. The source-genesis witness catalog is
shared with [the proof workload](public-chain-proof-workload.md). Its 128 witnesses
were selected and derived before reference-backend execution. Reusing that catalog
does not recompute the full genesis projection or authenticate its execution.

## Selected experiment

One ordinary build and one race-instrumented build each have one selected process
attempt against fresh owned stores. Each process performs:

- 128 warmup Root/GetProof pairs, checked against the independent witnesses;
- 2,048 concurrent pairs across 16 workers;
- one separate pair after Stop;
- one Stop call during the concurrent batch and one idempotent cleanup call.

This is 4,354 individual Root/GetProof calls per process. The ordinary and race
observations remain separate. Neither is a performance comparison with the other.
The two modes are preselected experiments; no component retries are automatic.

Stop is released after 32 concurrent pairs have completed. A matching observation
requires at least one successful caller interval to overlap Stop. Overlap by
refusals alone is insufficient. If no successful overlap is observed, the result
is `INCONCLUSIVE`, even when the remaining bytes and counts match.

Every successful root and proof digest must match the independently pinned
catalog. Refusals may only use the selected readiness or closed-database classes,
must not retain a partial payload, and must become readiness refusals after Stop
has completed. A missing row, wrong context, substituted digest, unselected error,
invalid clock sequence or acceptance claim refuses validation.

## Boundaries and reproduction

`Chain.Start`, the Node entrypoint, wallets, signing, user transaction submission
and chain networking are outside the selection. Source genesis is unsigned v1;
its momentum header has a zero StateRoot. The locally reconstructed partial
balance/storage root is not an accepted-header commitment. Projected absence is
not full-ledger absence. Consumer state-value acceptance remains `REFUSED`.

The preparation tool stages source and emits build/run recipes. It never executes
the node component. `plan`, `prepare` and `verify` require an explicit workspace
and Go tool. `prepare` requires a new destination and the exact original node
source. Existing or overlapping destinations refuse before staging.

Use the approved task-storage workflow for source extraction, builds, captures and
owned scratch. Keep at least 10 GiB free plus expected allocations and the safety
reserve. The selected task quota is 4 GiB. Dependency inputs must be retained and
checksum-verified; the experiment does not authorize new external transports.
Independent executable aliases use APFS clones, never hard links to evidence.

Closed file lengths do not measure physical allocation or reclaim. SELF resource
snapshots do not measure a complete process or pipeline peak. A through-exit
resource claim requires a separate selected-child wait receipt and explicit
platform units. No deployment resource budget or full M4 qualification follows
from these component observations.

## Current evidence

The corrected producer has two recorded Darwin/arm64 processes built with
Go 1.25.14. Both agree with all 128 independently selected warmup witnesses.
The ordinary and race observations have different scheduler outcomes:

| Build | Successful Root calls in batch | Successful GetProof calls in batch | Successful caller intervals overlapping Stop | Outcome |
| --- | ---: | ---: | ---: | --- |
| Ordinary | 128 | 128 | 0 | `INCONCLUSIVE` |
| Race | 46 | 35 | 1 | `MATCH` |

Stop was released after the selected 32-pair threshold. By the time the ordinary
Stop caller began, 128 concurrent pairs had completed; the race case had 34.
The ordinary case observed refusal intervals during Stop but no successful
overlap, so the combined overlap qualification remains false. The reader preserves
that result. A green replay check does not promote it to `MATCH`, and the race
observation does not substitute for an ordinary observation.

The corrected processes made 8,708 individual Root/GetProof calls in total,
including warmup and separate post-Stop checks. All successful batch digests match
the catalog; error results retain no payload. Both post-Stop pairs readiness-refuse,
and both second Stop calls return no error. Caller clocks do not establish which
internal mutex or database operation overlapped Stop.

The first producer's two processes completed, but their warmup digests were
rejected: the producer framed root/key/value/proof instead of the catalog's
key/value/root/proof order. The catalog and original contract were preserved.
The correction changes the observer and adds two independently framed checks for
absent versus empty values; the candidate runtime tree remains unchanged.
Two corrected builds with one selected process each followed those two failed
producer processes. There are four recorded reference processes overall. No
automatic retry is selected when an overlap observation is inconclusive.

Full original failure captures remain protected. The portable corpus carries the
failure's pinned capture digests and all 128 observed warmup digests per profile;
the reader independently recomputes their alternate framing. It does not claim
to authenticate the omitted complete failure bytes or any execution's origin.

Portable controls and replay use no reference backend:

```sh
python -I -B -m unittest discover -s tools/gen-state-root-vectors -p "*public_chain_proof_stop_test.py" -v
python -I -B tools/gen-state-root-vectors/check_public_chain_proof_stop.py --source-revision <source-revision>
```

Hosted Linux, macOS and Windows checks replay the retained observations. They do
not execute the node component on those hosts. The ordinary overlap gate, full
M4 workload, independent review, profile agreement and accepted-header state-value
gates remain open.
