# Startup sync observation after the readiness refusal

The single explicitly authorized [owned fixture run 43601430616, attempt 1](https://github.com/edgepillar/zenon-spv/actions/runs/43601430616)
used main source `b8bae80df0b0d7f1792aeaafae25cbe9bc567275` and the unchanged
reference-gas contract
`6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31`.
It recorded `REFUSED` at stage `nodes`, reason
`owned_rpc_readiness_deadline`. Domain configuration, vault setup, deposit,
closed-ledger oracle and native consumer phases were not reached.

## Retained observations

The original archive is 320,841 bytes with SHA-256
`21ab6d07f9d2a5b711ab8f3b35ffc8dd30ebf183a762e34c6c7d00dc0d65f9e6`.
It was transported once, retained without extraction and checked against the
selected run, job, source, digest and indexed members. Review completed with
exit 1 and `HOSTED_RECORDED_NON_ACCEPTING_OUTCOME`.

All 29 validated frontier responses, requests 2 through 30, contained v1 H1:
`fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`.
Request 31 was a complete successful `stats.syncInfo` command and retained these
82 original response bytes:

```json
{"jsonrpc":"2.0","id":31,"result":{"state":2,"currentHeight":2,"targetHeight":2}}
```

Its response SHA-256 is
`8480d2338a5aa510cba5ed8f484e6c9a207202ec5919b97f346530970c3ea6a2`.
State 2 means the source-reported `SyncDone`. This DTO supplies no header hash,
signature, StateRoot or producer authorization. No H2/H3 candidate header or
BatchEntry proof was retained by this attempt.

## Source interpretation and the remaining gap

At node `2835c436b197fece5c76adf4ba8dc1decca2e3ea`,
[`ProtocolManager.syncInfo`](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/protocol/sync.go#L154-L179)
gets its current height from
[`chainBridge.CurrentBlock`](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/protocol/chain_bridge.go#L128-L133).
Both that path and
[`LedgerApi.GetFrontierMomentum`](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/rpc/api/ledger.go#L301-L306)
read the chain's frontier momentum store. The controller issued the sync request
after the last readiness sample. These are separate reads; the archive contains
no atomic comparison or precise per-command absolute timestamps. The height
difference does not establish a stale cache, producer fault or the arrival time
of H2. The startup cause remains open.

The bounded follow-up captures one candidate frontier after a valid sync
observation. It preserves the original refusal and the existing anchor,
profile, schedule, context, readiness and global resource limits. This source
extension has no execution permission and cannot turn the earlier attempt into
an accepting result.

## Resource and closure observations

The budget report sampled peak new disk use of 2,995,077,120 bytes, below the
declared 8 GiB allowance, with no recorded budget refusal. Sampling leaves
transient allocations, unrelated-writer attribution and OS aggregate quota
enforcement unestablished. The 10 GiB free-space floor plus expected allocation
and margin remains.

The RPC stop-state reported exit 137 with `OOMKilled: false`. All three pillar
stop-states reported exit 0. The terminal record kept
`owned_runtime_observed_closed: false`; successful runtime closure is still an
open condition. Neither exit 137 nor the sampled disk observation establishes
the startup cause.

The single-dispatch authorization is consumed. No automatic repeat was made.
Actual selected-network H2/H3 capture and the three-proof consumer result,
representative R1 data, applicable independent review and authenticated
distribution remain open. Production state proofs and irreversible settlement
remain NO_GO.
