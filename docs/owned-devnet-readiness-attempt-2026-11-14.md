# Third authorized owned-devnet attempt

The separately authorized `747fcf0` attempt is
[Actions run 43538524141](https://github.com/edgepillar/zenon-spv/actions/runs/43538524141),
attempt 1. Its experiment job ran from 01:06:23 to 01:10:25 UTC on
14 November 2026 and concluded `failure`. The controller recorded `REFUSED`
at stage `nodes`, reason `owned_rpc_readiness_deadline`. Evidence upload
succeeded. The original ZIP was acquired once and reviewed in place against
retained run, job and artifact metadata; no extraction or consumer reexecution
was performed. The reviewer returned `HOSTED_RECORDED_NON_ACCEPTING_OUTCOME`
with actual exit 1 and complete output, verifying all 591 indexed files.

| Input or result | Exact identity |
| --- | --- |
| Runner source | `747fcf0293a7a341fed34393cac5afa0a96e5f1e` |
| Source tree | `57bca12270e928973d08c5fc30a329e6d809d08f` |
| Execution ref | `codex/owned-devnet-query-runner` |
| Preserved second-attempt ref | `codex/owned-devnet-query-second-attempt-834d551` at `834d551fc285bb2ec0cc7617e0164caa0023eadf` |
| Reference-gas contract | SHA-256 `6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31` |
| Selected consumer/oracle source | `7493c5929c7dbcfb29f94be521f7533d90a1a687` |
| Experiment job | `132273308366` |
| Artifact | `14090104694`, `owned-devnet-query-43538524141-1` |
| Original ZIP | 277,053 bytes; SHA-256 `32ed43eee5eeafec110612c5235ac2b7e03f3c8ce2ad2f38faf046a2cd5a3a94` |

## Established observations

Both image builds completed, the builder-only handoff passed, and the
controller started `pillar`, `pillar2`, `pillar3` and `rpc`. The first frontier
command returned curl exit 56 with complete capture, a quiescent process group
and zero stdout bytes. The bounded startup policy preserved this failure and
continued. Commands `rpc-02` through `rpc-30` each completed with exit 0 and
quiescent groups. The controller did not reach its selected height before the
unchanged 90-second checked deadline / 30-attempt readiness bound.

This records recovery from the initial receive failure. It does not establish
the stalled height, the server-side cause, eventual readiness or an actual v3
transition. The ZIP retains exact stdout pins and command receipts, but not the
frontier response bodies. Their sizes changed from 1,987 bytes for `rpc-02`
through `rpc-05` to 696 bytes for `rpc-06` through `rpc-09` and 697 bytes for
later two-digit IDs. Sizes and successful command exits cannot reconstruct
header heights, hashes or versions.

The initial host sample reported four effective CPUs, 15,800,221,696 available
memory bytes and 91,472,756,736 free disk bytes. Across 554 budget samples,
peak observed new disk use was 3,014,803,456 bytes (about 2.81 GiB) and peak
observed evidence size was 492,844 bytes. The last sample was at 231.76 seconds,
with no resource refusal. These are sampled filesystem observations, not an
OS aggregate quota, isolated writer attribution or measurements between samples.

Cleanup observed all four create-returned runtime container IDs closed. The
retained stopped-state summaries reported exit 0, PID 0, empty runtime errors
and no OOM, restart, dead, paused or running state. No executor or gateway was
started. No manual volume, image or network removal was performed; the fresh
hosted VM remains the disposal boundary.

## Follow-up: preserve the missing frontier evidence

The follow-up retains each original bounded frontier response only after the
existing envelope, request ID, selected-chain and header parsing checks succeed.
The final index includes those responses on a later refusal as well as success.
The reader binds them to the corresponding successful complete/quiescent
command, started record and exact `ledger.getFrontierMomentum` request before
reporting candidate height/hash/version observations. The per-response 128 KiB,
shared 96-call and 64 MiB retained-evidence bounds remain. Invalid or failed
responses are not selected by this extension; raw service logs, stderr and
private configuration are not exported.

This is diagnostic evidence, with no accepted-header authority. It cannot
replace the anchor, finite producer schedule, header-derived root or native
three-proof consumer path. Historical archives without the optional frontier
files remain readable. Their original records and outcomes are preserved.

Local regression controls cover real curl reset-to-response recovery on an
isolated ephemeral loopback port, frontier export after a simulated node-stage
refusal, exact response/receipt/request binding, size and call limits, wrong
identity/chain, incomplete commands and the legacy report shape. These synthetic
controls execute no node, signing operation or actual state-proof consumer.
They do not qualify another fixture attempt.

The accompanying portable-CI closure pin covers the changed runner dependencies
without broadening the portable allowlist. This refresh itself selects full
runtime CI; source binding and the dedicated preparation workflow remain
required before any later portable-only selection. Unchanged Go bytes do not
qualify a new revision. The purpose is to restore bounded preparation-only
qualification for future eligible changes after that full qualification.

## Open exits

No fixture configuration, vault setup or test-ZNN deposit was reached. No
opening-header capture, closed-ledger oracle or native consumer result exists
for this run. Actual selected-network D2/D3/D5 acceptance, representative R1
data, independent review and applicable release/production gates remain open.
All three exact-source one-attempt permissions are consumed. This follow-up
does not retry a workflow or authorize another signed fixture. The prior
[builder refusal](owned-devnet-attempt-2026-11-13.md) and
[first-RPC failure](owned-devnet-startup-attempt-2026-11-13.md) remain unchanged.
