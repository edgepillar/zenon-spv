# Status

**Evidence cut: 28 November 2026.** Main
[`76b25d7`](https://github.com/edgepillar/zenon-spv/commit/76b25d7d547ea98a2c42ca1c6509f2758d25e53b)
includes [PR #450](https://github.com/edgepillar/zenon-spv/pull/450).
The selected owned experiment ran at `c64f545`. Its Linux consumer and
parent oracle use the separately qualified source `58e03fa`. The frozen
native review candidate remains `6ecc231`. [Source and evidence details](typed-query-readiness.md) ·
[Native review ledger](review-candidate-changes.md)

| Delivery and gate | Scoped state |
| --- | --- |
| D0 / G0 | One chain-69, domain 1, batch 0 attempt was selected and bound to its runner, contract and component sources. Its one-run authorization was consumed. |
| D1–D2 / G1 | The experiment checked the configured H2 anchor and v3 range H3–H127 under finite closed-ledger producer slots. Intended-network agreement remains open. |
| D3 and native D5 / G2 | The selected owned read succeeded at H126. Three present rows matched one header root and all 17 stored gateway fields matched. Exact-main macOS reproduced the result offline. |
| D4 | The retained empty L2 commitment supports a checked absence at a selected test path. The first actual vault storage value still needs its contract ID, key, accepted batch and gateway proof. [Read-only storage consumer](owned-l2-storage-read.md) |
| N2 / G3 | The full-identifier reorg and reopen comparison is recorded. A supported node/profile decision and wider lifecycle qualification remain open. |
| N1 and S1 / G4 | Keep the snapshot transport and typed-root checks separate. R1 still needs an authorized representative capture. [Data intake](https://github.com/edgepillar/zenon-spv/issues/270) |
| G5 | Intended-network trust inputs and a scoped consumer pilot remain open. |
| D6 / G6 | Independent review and authenticated distribution remain open for each proposed release scope. |
| G7 | Applicable hash/profile decisions require their own evidence. |

| Active track | Next action |
| --- | --- |
| Zeno read-only | Select one post-deposit vault balance and obtain its bounded proof for the exact batch already bound on L1, or obtain the accepted L1 batch evidence alongside that proof. |
| Native v1/v2 | Retain the native CLI as the first candidate interface. Select one historical inclusion query with an independent expected account-block identity, trust inputs and a named consumer. [Native pilot scope](native-roadmap.md#start-the-real-consumer-pilot) |

## Retained reference-gas renewal attempts

| Run and source | Terminal outcome and record |
| --- | --- |
| [44961621978](https://github.com/edgepillar/zenon-spv/actions/runs/44961621978/attempts/1), `740518e` | `UNKNOWN` at fixture deposit. [Opening replay](typed-query-evidence-2026-11-27.md#opening-and-terminal-outcomes) |
| [45905746425](https://github.com/edgepillar/zenon-spv/actions/runs/45905746425/attempts/1), `f058474` | `UNKNOWN` at fixture configuration. [Opening replay](typed-query-evidence-2026-11-27.md#opening-and-terminal-outcomes) |
| [46148797542](https://github.com/edgepillar/zenon-spv/actions/runs/46148797542/attempts/1), `c64f545` | `DEVNET_CONSUMER_ACCEPTED` for the selected owned read. [Accepted query](typed-query-evidence-2026-11-27.md#successful-owned-batchentry-query-on-28-november) |

Earlier source cohorts and attempts retain their
[15 November evidence records](typed-query-evidence-2026-11-15.md)
and [readiness history](typed-query-readiness.md).
