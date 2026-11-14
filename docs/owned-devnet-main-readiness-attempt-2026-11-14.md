# Main-source readiness attempt and export gap

The additional, separately authorized main dispatch is
[Actions run 43582880684](https://github.com/edgepillar/zenon-spv/actions/runs/43582880684),
attempt 1, experiment job `132411174559`. It concluded `failure`; the controller
recorded `REFUSED` at stage `nodes`, reason `owned_rpc_readiness_deadline`.
Evidence upload succeeded. This one-dispatch permission is consumed. There is
no automatic retry or permission for another signed fixture.

| Input or result | Exact identity |
| --- | --- |
| Runner source / ref | `46a26569a4eb5b8a333d232db8fc58de01b5cc51` / `main` |
| Source tree | `004be590846aff2c413bada91eb823491513e902` |
| Reference-gas contract | SHA-256 `6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31` |
| Selected consumer/oracle source | `7493c5929c7dbcfb29f94be521f7533d90a1a687` |
| Artifact | `14109571555`, `owned-devnet-query-43582880684-1` |
| Original ZIP | 310,906 bytes; SHA-256 `c7d54fef15930916492cbd5cda13a35a40a38175bd3c00be8ac4ad3642435def` |

## Observations and limits

Both image builds and the builder handoff completed. The four node roles started.
The 29 retained frontier responses, `rpc-02` through `rpc-30`, all describe chain
69, height 1, version 1, genesis hash
`fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`.
They do not show the selected H2 anchor or first incoming v3 H3. No domain
configuration, vault setup, test-ZNN deposit, closed-ledger oracle or native
consumer was reached. The reason for the H1 plateau is not established.

The original archive has 621 regular ZIP members: its index and 620 indexed
files. Independent in-place readback checked every indexed size/SHA-256 and ZIP
CRC without extraction or another transport. This integrity result is separate
from complete evidence-reader acceptance, which failed as described below.

The initial host sample reported four effective CPUs, 15,785,627,648 available
memory bytes and 91,477,561,344 free disk bytes. Across 824 samples, peak observed
new disk use was 2,992,418,816 bytes (about 2.79 GiB), with 524,222 peak evidence
bytes and no resource refusal. The last sample was at 307.34 seconds. These are
sampled observations, not an OS aggregate quota or isolated writer attribution.

Stop-state diagnostics report all four node roles non-running with PID 0.
`rpc` and `pillar2` reported exit 0; `pillar` and `pillar3` reported exit 137.
All four reported `OOMKilled: false`. The cleanup record refused to qualify the
latter two, and the terminal retained `owned_runtime_observed_closed: false`.
Exit 137 does not establish its cause or a clean shutdown. The fresh hosted VM
remained the disposal boundary; no manual image, volume or network removal was
performed.

## Source-only diagnosis boundaries

The retained source at node `2835c436b197fece5c76adf4ba8dc1decca2e3ea`
provides two checks that constrain follow-up changes:

- The committed pillar and RPC configurations use the same role/IP mapping as
  the controller: pillar `.10`, RPC `.11`, pillar2 `.12`, pillar3 `.13` on the
  declared `172.30.0.0/24` bridge. Both legacy seeders and libp2p bootstrap
  addresses are present. The controller explicitly supplies those IPs, so the
  different Docker role aliases do not by themselves demonstrate an address
  mismatch. This source check does not prove a runtime connection.
- Protocol sync is gated by `MinPeers`, not `MinConnectedPeers`. The bootstrap
  pillar has `MinPeers: 0`; the other two pillars and RPC have `MinPeers: 1`.
  `MinConnectedPeers: 3` drives the P2P dial target. In
  [protocol/sync.go](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/protocol/sync.go#L154-L179),
  the node reports `NotEnoughPeers` when its actual protocol peer count is below
  `MinPeers`. The
  [pillar manager](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/pillar/manager.go#L76-L91)
  checks sync state, configured producer and the scheduled producer before work.

The archive lacks peer counts, protocol sync state and producer-event outcomes.
Consequently it cannot distinguish absent connections, sync gating, producer
selection or blocked/late work. The source exposes `stats.syncInfo` and
`stats.networkInfo`; the latter also contains peer IDs and addresses, so any
future retained diagnostic needs a separately bounded public field selection.
No such diagnostic was executed for this historical run. No deadline, network
configuration, producer schedule or resource limit is changed by this source
analysis.

## The exporter omitted the paired requests

The source-bound hosted metadata selector passed. The original strict reader
then exited 2 with `review_member_bound`: none of the 29 required matching
`rpc-NN.request.json` files were in the export. The recorder created those files,
but the finalizer selected only the validated `.frontier.json` response names.
The existing reader correctly requires the exact method, parameters and request
ID alongside the command receipt and original response bytes.

The follow-up selects each validated frontier response together with its exact
request. It keeps unrelated request files, invalid response bodies, stderr,
service logs and private configuration outside this extension. The regression
uses the real recorder and refusal finalizer, constructs only their selected
index in memory and passes it through the existing strict frontier reader.
Response, call and total evidence bounds remain unchanged. The writer change
requires its own local controls and exact-source CI; it does not repair the
historical archive or weaken reader acceptance.

The selected local recorder/capture, reader, model and process suites passed
79 root tests with no skips. A separate negative control restored only the old
response-only selection in memory and observed the expected missing-request
failure. These controls run synthetic regular-file/process fixtures; they do
not execute a node, signed fixture or actual consumer query. The reviewed
portable runtime-closure pin is refreshed for the runner change without adding
the runner to the portable allowlist. This change still selects full runtime CI.

The original ZIP, failed reader result and all earlier attempts remain intact.
Candidate H1 observations do not create accepted-header authority, a producer
schedule, state-value proof, consensus finality or production qualification.
Selected-network D2/D3/D5 exits and the separate R1, review and release gates
remain open.

## Earlier dispatch refused before runtime

The preceding separately authorized
[run 43562689023](https://github.com/edgepillar/zenon-spv/actions/runs/43562689023)
selected the same source through
`codex/owned-devnet-frontier-diagnostics-46a2656`. The unchanged source/ref guard
refused it at `workflow_source_binding` before engine or fixture work. Its
1,983-byte original ZIP, SHA-256
`5b5cf3fe25f823b9e30faa1a3b80f0795190ac5497816275fb7a94a1bc44a4f1`,
remains a separate failure record. The main dispatch above used a new explicit
one-dispatch permission. The guard was not relaxed and neither attempt is a
completed consumer experiment.
