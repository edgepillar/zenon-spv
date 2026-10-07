# zenon-spv

A resource-bounded SPV (Simplified Payment Verifier) for the Zenon Network of Momentum.

This module is the implementation. The [verification contract](docs/verification-contract.md) defines current guarantees; the sibling [`zenon-spv-vault`](https://github.com/0x3639/zenon-spv-vault) provides design history and upstream context. See the [development roadmap](docs/native-roadmap.md) for the staged product and research tracks.

## Status

The verifier currently ships, in five surfaces:

- **`verify-headers`** — header-chain integrity, signatures, linkage, height monotonicity, policy window (`Policy.W`), embedded mainnet checkpoints.
- **`verify-commitment`** — account-header inclusion under `MomentumContent.Hash` via flat sorted-content evidence (O(m) bandwidth, the only shape current go-zenon authenticates).
- **`verify-segment`** — per-block hash recompute, Ed25519 signature, account-chain linkage, F1 `PubKeyToAddress` binding, commitment lookup.
- **`verify-state-value`** — wire envelope + verifier skeleton for state-value proofs. **Refused by design** for every `StateCommitmentKind` today because current-protocol go-zenon has no consensus-bound authenticated state root. See [`docs/state-commitment-audit.md`](docs/state-commitment-audit.md).
- **`watch`** — stateful service that ticks against live peers at the chain's natural cadence; saves `HeaderState` before reporting ACCEPT and stops after repeated save failures.

Plus:

- **Verified state API** with immutable retained headers, captured policy, and explicit trusted-local resume; used by the CLI and watch. See [`docs/verified-state-api.md`](docs/verified-state-api.md).
- **Multi-peer JSON-RPC fetcher** with k-of-n agreement (`internal/fetch`, `cmd/fetch-bundle`).
- **Structured Result envelope** — every ACCEPT/REJECT/REFUSED carries machine-readable `proven:` / `not_proven:` / `trust_assumptions:` lists, so integrators can programmatically distinguish "this happened" from "I know the canonical chain state."
- **Trust-anchor tooling** — embedded mainnet genesis trust root, multi-peer genesis envelope cross-check against an expected pin (`tools/verify-mainnet-genesis`), checkpoint derivation (`tools/derive-checkpoints`), producer-schedule derivation (`tools/derive-producer-schedule`). See the [genesis observation boundary](docs/genesis-cross-check.md); matching peer envelopes do not authenticate the anchor's provenance.

This is **not a full Zenon light client.** See [`docs/trust-model.md`](docs/trust-model.md) for what each ACCEPT actually proves and [`docs/conformance.md`](docs/conformance.md) for the implementation matrix against the spec.

**Momentum layouts v1 and v2 are supported.** Verification of v2 requires an explicit `--protocol-profile` bound to the configured checkpoint and a height range. Without a profile, verification remains v1-only and makes no activation claim. The profile is an operator attestation, not independent proof of network activation. See [`docs/header-versions.md`](docs/header-versions.md).

## What it does NOT do

| Capability | Status |
|---|---|
| **State-value verification** (balance at height H) | **Refused by design.** No consensus-bound state root exists upstream. Wire envelope + verifier skeleton ready for the day go-zenon ships one. |
| **Producer-set authorization by default** | Opt-in via `--schedule <path>` (operator-attested per-momentum schedule). Without it: tier-1 caveat ("not enforced"). |
| **Chain-derived producer-set transitions** | Deferred; the release-time operator-attested schedule is the bridge available today. |
| **libp2p / WebRTC peer transport** | Current transport is HTTPS JSON-RPC. |
| **Sentinel/Sentry attestation as state proof** | Possible future track. If pursued, lands as a distinct mode with its own `Guarantee` value, never under `STATE_VALUE_INCLUSION`. See [`docs/sentry-sentinel-role.md`](docs/sentry-sentinel-role.md). |

Every ACCEPT carries a machine-readable trust audit + a human-readable caveat. See the bounded-verification frame at `zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md` for the formal G1–G3 guarantees and NG1–NG6 non-guarantees this verifier inherits.

## Build

```bash
make build      # builds ./zenon-spv and ./fetch-bundle
make test       # full test suite
make bench      # repeated local verification benchmarks
make vet        # go vet
make lint       # golangci-lint v2.6.2
make cover      # coverage report
```

Requires Go 1.25+. The repo sits outside the parent `~/Github/go.work` workspace; if you have one, prefix Go commands with `GOWORK=off`.

## Quickstart

After `make build`, the binaries are at `./zenon-spv` and `./fetch-bundle`.
To build them without Make, use separate explicit output commands:

```sh
go build -o zenon-spv ./cmd/zenon-spv
go build -o fetch-bundle ./cmd/fetch-bundle
```

Print the CLI surface:

```bash
./zenon-spv help
```

Record the running tools' build metadata without loading state or contacting
peers:

```sh
./zenon-spv version --json
./fetch-bundle version --json
```

See [build identity](docs/build-identity.md) for unknown source metadata,
modified builds, and the distinction from an authenticated binary digest.

Run the selected offline pilot and record its source, tested executable
hashes, scenario results, and skipped checks:

```sh
go run ./tools/offline-pilot > ../offline-pilot.json
```

This uses synthetic fixtures and loopback RPC. See [offline pilot](docs/offline-pilot.md)
for cached-dependency prerequisites, report interpretation, and native CI artifacts.
For the exact ordinary executables used by that run, see
[tested candidate artifacts](docs/candidate-artifacts.md) and their independent
archive/pin checker. These packages prepare review and retain the pilot's
synthetic evidence limits.

For a complete read-only operator run, follow the [operator workflow](docs/operator-pilot.md).
It records explicit trust settings and build identity, initializes protected
state, runs bounded watch/restart, and verifies collected evidence locally.
The [block observer](docs/block-observer.md#collect-and-observe-from-one-explicit-rpc)
can collect proof-only evidence from one explicit RPC and run the retained-only
verifier and query consumer in the same invocation, with pinned child binaries
and unchanged local state.
For separate application exits, finite private-file metadata samples and an
explicit post-exit directory check, follow the
[consumer resource observation guide](docs/consumer-resource-observation.md).
It links the existing resource reports and keeps fixed replay observations
separate from consumer budgets and network qualification.
Use `inspect-config --json` to review settings and `--expect-context <64-hex>`
to require the same configuration on later verification, inspection, and watch
commands. A matching fingerprint is configuration consistency, not independent
authentication of the anchor, profile, schedule, peers, or binary.

Inspect an existing trusted local state without a bundle or RPC refresh:

```sh
./zenon-spv inspect-state --state state.json --json
```

Supply the matching anchor/profile for non-default state. See
[state inspection](docs/state-inspection.md) for effective window/depth ranges
and the distinction between successful inspection and proof verification.

Run a fixture-based smoke test (no network required):

```bash
./zenon-spv verify-headers \
  --genesis-config internal/testdata/genesis_test.json \
  internal/testdata/headers_valid.json
```

Expected output:

```
ACCEPT ReasonOK
proven:
  - HEADER_CHAIN_INTEGRITY
  - SIGNATURE_AUTHENTICITY
not_proven:
  - CONTENT_INCLUSION
  - CANONICALITY
  - STATE_TRANSITION
  - PRODUCER_AUTHORIZATION
CAVEAT: producer-set authorization is not enforced. ACCEPT means local consistency
under the configured trust root and checkpoints, not full Zenon chain validity. ...
```

(A mainnet bundle additionally lists `trust_assumptions:` with `TRUST_CHECKPOINT_ANCHOR`; the testnet-shaped fixture above is checkpoint-free by design.)

Exit codes: **0** = ACCEPT, **1** = REJECT, **2** = REFUSED.

## Try it against live mainnet

The `fetch-bundle` tool builds a multi-peer HeaderBundle JSON that `zenon-spv` then verifies offline. Two-step flow:

The generated checkpoint comes from the selected peers. Authenticate its
provenance independently before treating it as a trust root. See
[bundle fetching](docs/fetch-bundle.md) for peer selection and input limits.

```bash
# Pick an address + block to verify. The address below is used in the
# repo's example traces.
ADDR="z1qrztagl9rukq3ltdflnvg4zrvpfp84mydfejk9"
HEIGHT=1466

# Step 1: ask the network which momentum committed that account block.
# This RPC metadata only locates a candidate committing momentum.
COMMITTING=$(curl -sk -X POST -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ledger.getAccountBlocksByHeight\",\"params\":[\"$ADDR\",$HEIGHT,1]}" \
  https://my.hc1node.com:35997 \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['list'][0]['confirmationDetail']['momentumHeight'])")

# Step 2: fetch a multi-peer bundle. The verifier needs `Policy.W` (default 6)
# headers PAST the committing momentum, so anchor at committing+W.
./fetch-bundle \
  --peers "https://my.hc1node.com:35997,https://node.zenonhub.io:35997" \
  --height $((COMMITTING + 6)) --count 7 \
  --segments "$ADDR:$HEIGHT" \
  --checkpoint /tmp/anchor.json \
  --out /tmp/bundle.json \
  --timeout 60s

# Step 3: verify the bundle offline. Each verify-* subcommand exercises
# a different layer; verify-segment runs the full stack (headers +
# commitments + segment).
./zenon-spv verify-segment --genesis-config /tmp/anchor.json /tmp/bundle.json
```

A successful run prints `ACCEPT ReasonOK` with `CONTENT_INCLUSION` and `SIGNATURE_AUTHENTICITY` in `proven:`. **Verify time is ~120 ms per block on a laptop**, dominated by JSON parse + Ed25519 signature verification.

## Subcommand cheatsheet

Each verification command reads a HeaderBundle JSON and checks the evidence
relevant to that command. Proof commands normally extend the header chain first;
`--retained-only` selects an existing trusted local window instead.

| Subcommand | Verifies | Returns ACCEPT when |
|---|---|---|
| `verify-headers` | Headers' linkage, hashes, signatures, checkpoint matches | The bundle's header chain is internally consistent against the genesis trust root. |
| `verify-commitment` | Every supplied commitment against a retained momentum's `ContentHash` and depth policy | The target account-header triple is included under the content hash of that trusted header view. |
| `verify-segment` | Block hashes, user signatures, account linkage, and matching commitment candidates for each segment block | The implemented block and inclusion checks pass under the trusted header view; embedded blocks do not gain an account-signature guarantee. |
| `verify-state-value` | Context and structural checks on each `StateValueProof` | **Never** today. Unsupported commitment kinds refuse; malformed or invalid input can fail earlier checks. |
| `watch` | Streams new momentums from peers and verifies them at the chain's natural cadence | ACCEPT is logged only after a successful state save. Three consecutive save failures stop the service. SIGINT/SIGTERM exits cleanly. |

Optional flags shared across all verify-* subcommands:

- `--window {low|medium|high}` — retained-window depth `W`. low=6, medium=60,
  high=360. Default `low`; names are case sensitive. Empty or unknown values
  fail with exit 64 instead of selecting a lower depth. This depth is not a
  consensus finality certificate.
- `--genesis-config <path>` — override the embedded mainnet anchor with a strict,
  bounded JSON file. Custom networks require this file or a complete anchor
  environment override; see [anchor configuration](docs/anchor-configuration.md).
- `--state <path>` — persist `HeaderState` across runs. Stateful writers hold
  an exclusive OS lock; competing writers exit 70. See
  [writer ownership](docs/state-writer-locks.md) for companion-file/path rules.
- `--schedule <path>` — load an operator-attested per-momentum producer schedule (tier-2 caveat).
- `--show-context` — print captured verification settings with a reproducible
  fingerprint, excluding private audit metadata. Also available on `watch`;
  see [`verification context`](docs/verification-context.md).
- `--json` — emit one versioned report with per-proof outcomes, guarantees,
  captured settings, and separate persistence/error fields. Check the process
  exit code as well as the report; see [verification reports](docs/verification-reports.md).

Proof commands also accept `--retained-only --state <path>` for queries against
a nonempty trusted local state. The bundle must contain no headers. The query
revalidates the state, applies the usual proof checks, and never rewrites it.
See [retained state queries](docs/retained-state-queries.md) for outcomes and
the distinction between a retained view and current network state.

`fetch-bundle --proof-only` produces these query bundles directly for requested
commitment addresses or account segments, without exporting headers or a
checkpoint. Select a range covered by the retained state and run the verifier
after collection; see [proof-only fetching](docs/fetch-bundle.md#evidence-for-an-existing-retained-window).

Place all verify-* flags before the bundle path. `watch` accepts no positional
arguments; extra arguments fail before loading configuration or starting RPC.

`watch --json` streams versioned JSON Lines events to stdout, with captured
settings, explicit trust inputs, and separate verification and persistence
results. A caught-up event does not claim fresh header verification. See
[watch events](docs/watch-events.md) for the schema and delivery boundaries.

`watch --once` performs one bounded synchronization step and returns its outcome:
0 after saving accepted state, 1 for rejected evidence, 2 for insufficient
evidence, or 70 for an operational failure. It works with `--json` and releases
the writer lock before exiting. A successful step can leave more headers to
fetch; see [single-step watch](docs/watch-persistence.md#single-step-watch).

## What ACCEPT actually proves

After this PR set, every ACCEPT result carries machine-readable lists:

```
proven:                    ← what this verifier path actually established
  - CONTENT_INCLUSION       (the AccountHeader was in MomentumContent)
  - SIGNATURE_AUTHENTICITY  (Ed25519 over the block hash)
not_proven:                ← what this path DELIBERATELY does not claim
  - CANONICALITY            (we saw one chain view; might not be canonical)
  - STATE_TRANSITION        (we did not replay state effects)
  - PRODUCER_AUTHORIZATION  (no producer schedule was configured)
  - HEADER_CHAIN_INTEGRITY  (proved in the parent `headers:` block)
trust_assumptions:         ← external dependencies of this verdict
  - TRUST_RETAINED_WINDOW_DEPTH
  - TRUST_CONFIGURED_ANCHOR
```

Integrators must check the guarantees they require in `proven:` and the external trust assumptions they accept. An ACCEPT verdict or an operator-attested producer schedule alone does not establish canonicality or finality for irreversible settlement. See the [`verification contract`](docs/verification-contract.md) for the current integration boundary and [`trust model`](docs/trust-model.md) for the full taxonomy.

## Layout

```
cmd/
  zenon-spv/                # CLI: verify-headers, verify-commitment, verify-segment,
                            #      verify-state-value, watch
  fetch-bundle/             # multi-peer fetch utility (writes HeaderBundle JSON)
internal/
  chain/                    # Header, AccountBlock, AccountHeader, Address, Hash
  verify/                   # Verifier core: header/commitment/segment/state_value,
                            #                policy, caveats, guarantees envelope
  proof/                    # Wire format (HeaderBundle JSON; StateValueProof envelope;
                            #              ADR 0001 for the future protobuf3 form)
  fetch/                    # JSON-RPC client + MultiClient (k-of-n agreement)
  syncer/                   # Stateful watch loop, persist-before-advance invariant
  testdata/                 # Deterministic fixtures (headers_valid.json, etc.)
tools/
  derive-checkpoints/       # Generate checkpoint commitment evidence
  derive-producer-schedule/ # Derive a per-momentum producer schedule from peer quorum
  verify-mainnet-genesis/   # Cross-check recomputed genesis envelopes against an expected pin
  stress-fixture/           # Stress-test fixture generator
docs/                       # Repo-local docs (spec and ADRs live in the vault)
```

## Documentation

See [`docs/README.md`](docs/README.md) for the full index. Start here:

- [`docs/architecture.md`](docs/architecture.md) — shipped components and roadmap.
- [`docs/trust-model.md`](docs/trust-model.md) — what each ACCEPT does and does not prove.
- [`docs/verification-contract.md`](docs/verification-contract.md) — native-client trust inputs, result interpretation, and next acceptance gates.
- [`docs/verified-state-api.md`](docs/verified-state-api.md) — owned verification state, query policy, persistence, and trust boundaries.
- [`docs/conformance.md`](docs/conformance.md) — spec conformance + known gaps.
- [`docs/state-commitment-audit.md`](docs/state-commitment-audit.md) — source-cited audit of what go-zenon authenticates (and the external dependencies that would unblock balance proofs).
- [`docs/sentry-sentinel-role.md`](docs/sentry-sentinel-role.md) — proof-availability vs. proof-authority boundary.

### Design decisions (ADRs in the vault)

The repo-local docs above are operator-facing; the vault holds the
design rationale and rejected-alternatives history. Most useful when
asking "why did the SPV do X this way, and what did the maintainer
already rule out?":

- [`decisions/0001-proof-serialization.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0001-proof-serialization.md) — wire format (JSON shipped, protobuf reserved).
- [`decisions/0002-genesis-trust-anchor.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0002-genesis-trust-anchor.md) — historical genesis-anchor rationale.
- [`decisions/0003-checkpoint-policy.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0003-checkpoint-policy.md) — embedded checkpoint list (long-range-attack defense).
- [`decisions/0004-producer-set-quorum-check.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0004-producer-set-quorum-check.md) — original producer-set design (superseded by 0005).
- [`decisions/0005-producer-schedule-shipped.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0005-producer-schedule-shipped.md) — opt-in tier-2 `--schedule` as actually built.
- [`decisions/0006-explicit-guarantees-envelope.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0006-explicit-guarantees-envelope.md) — `Result.{Proven, NotProven, TrustAssumptions}`.
- [`decisions/0007-state-value-refused-by-design.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0007-state-value-refused-by-design.md) — why `verify-state-value` REFUSEs every kind today.
- [`decisions/0008-sentry-sentinel-role-boundary.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0008-sentry-sentinel-role-boundary.md) — proof-availability vs proof-authority.
- [`decisions/0009-resource-bounds-policy.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0009-resource-bounds-policy.md) — `Policy.Max*` defaults that enforce G3.

## License

MIT — see [`LICENSE`](LICENSE).

## See also

- Vault: [`zenon-spv-vault`](https://github.com/0x3639/zenon-spv-vault) — spec, notes, ADRs.
- go-zenon reference: pinned at commit `667a69d9e9a418edf7580b08492ba5dcb9efd63a` (per `zenon-spv-vault/reference/CLAUDE.md`).
- [`znn-sdk-go`](https://github.com/0x3639/znn-sdk-go)
