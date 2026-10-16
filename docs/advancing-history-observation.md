# Finite advancing-history observation

On 2026-10-16, the current block observer advanced a fresh saved prefix through
three separate processes using historical responses from one selected testnet
gateway. The first two observations refused their complete selected result;
the third matched all five signed account-block targets. This is an
operator-trusted historical experiment. Independent consumer/network acceptance,
freshness and production qualification remain open.

## Candidate and execution

The source was
[e2930f2fd0efb113deb2da97c1304e22b8aa2b6c](https://github.com/edgepillar/zenon-spv/commit/e2930f2fd0efb113deb2da97c1304e22b8aa2b6c), with source-input
SHA-256 `abb1376ecd4b82ebed141357e520fbcc885928ea0c427b99cee3ec9aabe7c003`. Four ordinary Darwin/amd64 executables came from artifact
12024235499 of [main CI run 38843052041](https://github.com/edgepillar/zenon-spv/actions/runs/38843052041).
The archive SHA-256 was `5e35cf9d4fbe9149cfe091ed5882d8af8b0ab3fdad452995ec27b0b9ef211ec7`. Its complete manifest and executable pins
were checked again before execution. The existing verified archive was reused;
no artifact download, new compilation or CI run was needed for this experiment.

The host was Darwin/arm64, so these exact amd64 CI bytes ran through the host's
translation support. This was not a new native ARM64 qualification or an
authenticated binary distribution. Go version was 1.25.14.

A finite loopback recorder forwarded each selected request to the same gateway
and returned its unmodified response body. It retained actual request/response
bytes and process outcomes. The result is scoped to this forwarding boundary;
it does not qualify equivalence to direct native TLS transport or timing.

## Selection and advancing history

The five account-block identities and their confirming Momentum at height 6026
came from the immutable earlier capture described in the
[five-block observation](live-signed-batch-observation.md). They were selected
before new proof collection. The same original gateway and development workflow
supplied the history, so this was not independent consumer or provider selection.

A separate configuration inspection checked that the current candidate still
matched the existing context pin. The anchor, observed producer schedule,
activation assertion and profile coverage through height 6144 were unchanged.
No profile/schedule renewal or activation authentication was performed.
A site/RPC preflight checked the existing genesis digest and the separately
selected historical identifiers; matching responses did not authenticate them.

The candidate verified 6,027 selected historical headers into a new state ending
at 6028, with K=256 and W=6. The intended final tip was independently selected
from the earlier capture at height 6034. Each new observation used batch size
two, the same expectations and a fresh ordinary observer process.

| Saved tip | Actual observer exit | Complete consumer interpretation |
| --- | --- | --- |
| 6030 | 2 | The confirming height remained below the selected depth; the query refused. |
| 6032 | 2 | Inclusion became available, but the strict consumer refused the tip mismatch against the preselected 6034 expectation. |
| 6034 | 0 | All five exact targets matched the selected context/tip, content-inclusion and signature requirements. |

An additional live invocation loaded a separate copy of the existing 6144 state.
Its unchanged profile refused the next incoming height 6145 before collection.
It did not renew trust inputs or change the saved state.

The live experiment made 21 forwarded RPC requests and received 49,274 response
body bytes. Three separate site GETs and three RPC preflight requests are
additional observations. Counts exclude HTTP/TLS framing. There were no network
retries, target substitutions or discarded candidate phases. These finite
measurements are not latency, bandwidth, memory or throughput acceptance limits.

## Controlled failures and record checks

The separate archived-response phase exercised disconnect, malformed response,
stale frontier and a conflicting retained signature. A busy cooperating writer
also stopped the observer before RPC or state save. These were deliberately
controlled local faults using captured signed bytes, not naturally occurring
gateway failures or an independent fork-choice experiment.

Eleven planned observer scenarios and eleven actual outer-reader processes
completed with their selected zero/nonzero outcomes. A separate read-only
record auditor checked every recorded child completion, 39 returned Momentum
preimages, 30 returned account-block preimages and complete serialized state
bytes at five selected tips. Twenty-four in-memory adverse record controls
refused changed exits, incomplete streams, substituted fixture/live records,
wrong state digests, missing observations and unsupported qualification claims.
The byte auditor did not perform independent Ed25519 execution; the actual Go
verifier processes checked signatures.

The first setup attempt is also retained. Its recording fixture refused a
collection request after watch had already saved tip 6030. A separately sealed
plan selected only confirming height 6026 and resumed those exact saved bytes.
It did not repeat the completed initialization or first watch tick, change
targets/expected tip/context, or roll progress back.

The first record auditor had a positional condition error for the stale-peer
collector. A separate correction preserved the exact expected requests and
process/state checks. Only read-only record auditing was repeated. Both initial
failures, their source, actual exits and partial observations remain protected.

The private unsigned aggregate record has SHA-256
`c781e8ad16dd60d9bc20497682969eb8d1422da246337dba88f7d761101dffeb`. Raw identities, replies and trust files remain private.
This document supplies aggregate observations, not a publicly reproducible
corpus, signed receipt, release attestation or independent security review.

## Remaining acceptance work

The experiment does not establish network freshness, canonicality, consensus
finality, authenticated elections, state transitions or state values.
Independent consumer selection and authenticated anchor/profile/producer
sources, representative application traffic and hardware, in-flight storage
failure/power-loss behavior, independent candidate review and authenticated
source/binary/report distribution remain separate gates. Controlled destination
and process failures do not qualify physical storage crash recovery.

The [native roadmap](native-roadmap.md) keeps accepted v3 balance binding,
hash-bound node retained-root recovery and state-root profile agreement outside
this native inclusion experiment. No wallet, signing, transaction, custody,
deployment or external message was initiated.
