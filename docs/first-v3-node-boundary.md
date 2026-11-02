# First incoming v3 node fixture

The selected node now has an executed boundary observation from its height-1,
version-1 fixture genesis through the first v3 momentum. The retained public
[header capture](../internal/testdata/conformance/first-v3-node-headers.json)
also supplies complete projected fields and fixture signatures for independent
SPV encoding checks. These are isolated chain-100 test data, not a Zeno devnet
activation profile or an accepted SPV state.

## Source, test and observed boundary

| Input or observation | Identity or result |
| --- | --- |
| Original node | `digitalSloth/go-zenon@938fca3b7787da86827a5eb63371509b36e14761` |
| Git root tree | `f3b7947d2267ebdb806f18ff0c02bba5bffae9c4` |
| Original source | All 484 regular files checked against Git blob identities; unchanged by the capture |
| Added test only | [first-v3-header-capture_test.go.txt](../tools/gen-state-root-vectors/first-v3-header-capture_test.go.txt); SHA-256 `fdf97c44cb9bf118d1704423f9be919d244ccb8d7fb07a4a13c93aaeab8bdcae` |
| Test selection | `TestSPVFirstIncomingV3HeaderCapture` in `./vm/embedded/tests` |
| Local node execution | Go 1.25.14, darwin/arm64, CGO enabled, system Clang; exit 0 and complete output |
| Genesis | Chain 100; `0385d849ee33b94c8783288c148e3ae741c2ecec98b08b3f59d6bcc219168fe5`; unsigned v1 at height 1 |
| Dynamic Plasma enforcement | 10; first incoming v2 at 11 |
| StateRoot enforcement | 11; first incoming v3 at 12 |
| Captured sequence | Heights 1–10 v1, height 11 v2, heights 12–14 v3 |
| Version refusals | Early v3, late v2/v1, unknown version 4 before/after, and missing version 0 before/after: seven passing subtests |
| Capture execution record | SHA-256 `6a977dedb439309f8925ffd997d245b4f71eb0e5e7f836dc7f421b3e4e42f4df` |
| Capture gate | SHA-256 `0eeeb54def6af3474a0af18c24961030fc70776882d9263d3b27a41db9430126` |

The harness runs the original chain, cache, state-tree, producer and verifier
implementations inside `mock.NewMockZenon`. Consensus is mocked. Spork changes
use only the repository's public deterministic fixture keypairs, with direct
in-process insertion; no RPC/P2P server, live wallet or network transaction is
started. Genesis remains a separate unsigned trust input.

Before each incoming momentum, the test reads the parent store's activation
predicates and the chain's state-tree readiness. Each generated header must
advance the selected height/hash link, satisfy the original node's static
hash/signature check and use the expected version. Every captured v3 root must
be nonzero and match the maintained tree at that exact header identifier.
Legacy roots stay zero. An unknown spork never acquires activation authority.

The seven negative subtests call the original raw momentum verifier's version
check. They do not establish all transaction-verifier behavior, authenticated
producer scheduling or correctness of the state transition function.

## Independent SPV checks

```sh
go test -json -count=1 -run '^TestCandidateV3HeaderNodeBoundary' ./internal/chain
```

These tests pin the capture and harness bytes, preserve the original execution
scope, and reconstruct all 14 node hashes using the SPV v1/v2 and candidate v3
encoders. They verify all 13 non-genesis Ed25519 fixture signatures and linked
heights. The v3 preimage must append the raw root at byte 176, after both prices.
The local capture controller separately reconstructed all 14 hashes with
Python's SHA3-256 implementation before preserving the capture.

Negative controls change each signed field, including both prices and the state
root. A changed root with a recomputed hash remains decodable but fails the old
fixture signature. Width-correct altered public keys and signatures also remain
encoding data and fail signature verification. The production version gate
still refuses v3. The existing three-platform CI candidate-header selection and
complete root suite both include these native SPV tests; reading this capture
on another platform does not execute the original node there.

## Reproducing the node capture

Use a new isolated, task-owned copy of the exact pinned node, with original
sources verified and dependencies already available. Copy the published harness
exclusively to `vm/embedded/tests/spv_first_v3_header_capture_test.go` in that
copy. Refuse an existing destination. Leave the original source checkout alone.
Then run from the isolated node copy:

```sh
GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=1 \
  go test -mod=readonly -p 1 -json -count=1 -timeout=60s \
  -run '^TestSPVFirstIncomingV3HeaderCapture$' ./vm/embedded/tests
```

The `SPV_FIRST_V3_HEADER_TRACE` log contains the capture. Go's JSON stream may
split a long log line across output events: concatenate the selected test's
output before decoding the JSON following that marker. Keep separately
attributed compiler `build-output` events; they are not test-package events.
Retain actual exit, completeness, source, compiler and dependency identities
for every attempt. Another invocation is separate evidence, not the recorded
local run above.

## Resource use and limits

The capture sequence took 46.626 seconds locally. Its largest workspace
observation after a command was 297,327,548 bytes, about 283.6 MiB, under an
explicit 512 MiB task budget. This is not a continuous peak measurement or a
production hardware target. Dependencies were prepared from a read-only local
file proxy. All 34 actually loaded module ZIP and expanded-directory h1 values
matched the original `go.sum`; expanded directories were checked again after
the test. Only this task's verified redundant ZIP copies, 24,124,342 bytes,
were removed before compilation. No module ZIP transport was repeated during
the test, and its owned temporary caches were removed on completion.

Full historical module-graph `go mod verify` remains `NOT_ESTABLISHED`: that
command needs unrelated unavailable dependency metadata. The loaded-module
checks do not relabel that broader diagnostic. Earlier failed preparation
attempts remain failures.

The original node's unchanged `TestStateRoot_Activation` and a smaller boundary
harness had already passed. Their observer task incorrectly rejected a separate
Go 1.25 compiler-output event. Its `FAILURE` remains preserved; a later reader
reconciled the completed passing test outputs without repeating those tests.
The header capture above was a new scope to obtain signed projected fields.

This fixture supplements the [original trie execution](selected-original-node-conformance.md)
and [candidate header codec](candidate-v3-header-codec.md). D1 still needs the
selected network's actual genesis/activation/profile and remaining canonical
encoding/limit/recovery controls. D2's owned v3 RPC/context/persistence path and
D3's root-bound typed `BatchEntry` consumer remain open. No canonicality,
consensus finality, accepted state value, live-network activation or production
readiness follows from these data.
