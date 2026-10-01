# Local multi-peer watch scenarios

`TestOfflineWatchPeerFaults` exercises the actual JSON-RPC client, multi-peer
reconciliation, watch loop, verified state API, persistence, and trusted local
resume. All RPC endpoints are in-process HTTP test servers on loopback.

The base data is the [node-derived momentum corpus](../internal/testdata/conformance/README.md),
which pins go-zenon commit `3a4131e63881058b6ce2ee81d3a41d0033fafc99`.
Fault responses are synthetic mutations. The test does not contact public
nodes or authenticate deployment-time activation or producer information.

## Reproduce

Run from the repository root:

```sh
go test -race ./internal/conformance -run '^TestOfflineWatchPeerFaults$' -count=1 -v
```

The normal test suite and CI also run this campaign. Each scenario starts
from independently loaded fixture data, saves a verified v1 window ending at
height 2002, and uses three RPC peers with quorum two. The activation profile
selects v2 at height 2003; the producer schedule covers 2001 through 2006.
Watch uses `W=1`, safety margin one, and a three-header batch. These are
synthetic test parameters, not recommended public-network settings.

Each run stops after one completed tick. Successful advances are reloaded
through `LoadTrustedState`, and content inclusion is queried at height 2004.
Those results must retain the configured-anchor, persisted-state, activation-
profile, and external-producer-schedule trust assumptions without claiming
canonicality. Failed evidence must neither save nor log an ACCEPT tick.

## Expected results

| Scenario | Tick outcome | Persisted effect |
| --- | --- | --- |
| Three healthy peers | ACCEPT | Advance from 2002 to 2005 |
| One unavailable peer, two healthy | ACCEPT | Advance to 2005 |
| One peer uses the wrong JSON-RPC ID, two healthy | ACCEPT | Advance to 2005 using the two matching responses |
| All peers use the wrong JSON-RPC ID | REFUSED | No save; original bytes retained |
| All peers overwrite an RPC error with a duplicate null field beside a result | REFUSED | No save; original bytes retained |
| One stale peer, two healthy | ACCEPT | Advance to 2005 |
| One peer replays an older target header, two healthy | ACCEPT | Advance to 2005 using the two matching responses |
| All peers replay an older header for the agreed target height | REFUSED | No caught-up ACCEPT; no save |
| All peers return an older batch for the incoming range | REFUSED | No save; original bytes retained |
| Two unavailable peers | REFUSED | No save; original bytes retained |
| Two agreeing peers and one consistent conflicting fork | REFUSED | No save; original bytes retained |
| All peers agree on a bad signature at 2003 | REJECT | No save; original bytes retained |
| All peers agree on a chain disconnected from the retained anchor | REJECT | No save; original bytes retained |
| All peers agree on a valid signature from a producer absent from the configured slot | REJECT | No save; original bytes retained |
| All peers omit a required v2 price | REFUSED | No save; original bytes retained |
| Activation profile expires at 2004 | REFUSED | No partial advance; original bytes retained |
| Peers return three headers for a policy-capped two-header request | REFUSED | No save; original bytes retained |
| Peers append a malformed extra row beyond the requested count | REFUSED | Excess row is not decoded; no save |
| One peer replaces a range list with a second field, two healthy | ACCEPT | Advance using the two unambiguous responses |
| All peers replace a range list with a second field | REFUSED | No save; original bytes retained |
| One peer exceeds the content-member cap, two healthy | ACCEPT | Advance using the two bounded responses |
| All peers exceed the content-member cap in a batch or frontier | REFUSED | Excess member is not decoded; no save |
| All peers replace a content list with a second field | REFUSED | No save; original bytes retained |
| All peers remain at 2002 | Caught-up ACCEPT | Existing window saved with identical bytes; no advance |

The conflicting-fork case records the current strict disagreement policy:
reaching quorum does not override another usable, conflicting response.
The stale-peer cases exercise median frontier selection. An all-stale
caught-up tick is a lack of new progress, not evidence of network freshness.

## Evidence boundary

This is a repeatable local integration check. It does not test real-node
partitions, elected-producer derivation, live reorgs, long-running network
liveness, storage hardware, power loss, or consensus finality. Operator
schedules and activation profiles remain explicit external trust inputs.
Colluding peers and a substituted trusted local file are not made trustworthy
by this campaign. A deployment pilot still requires independently justified
anchors and protocol information, protected local state, and controlled real
nodes. Persistence-failure and post-rename behavior have separate coverage in
[watch persistence](watch-persistence.md).
