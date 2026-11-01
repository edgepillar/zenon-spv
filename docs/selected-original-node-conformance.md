# Selected original-node conformance

The native mathematical comparison and an execution of the selected original
node are separate evidence. The original node's unchanged
[`common/trie/TestConformance`](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/common/trie/conformance_test.go)
now has an actual local pass at that revision. This closes that selected
execution gap without completing D1 or authenticating a state root.

## Source and execution

| Input or result | Selected identity |
| --- | --- |
| Node | `digitalSloth/go-zenon@938fca3b7787da86827a5eb63371509b36e14761` |
| Git root tree | `f3b7947d2267ebdb806f18ff0c02bba5bffae9c4` |
| Retained source archive | 1,876,245 bytes; SHA-256 `8ca1512eff8c04ee8b6ed0ff9a5da9e3eeba518660b07833f99a6b74e1dcc3a3` |
| Normative vectors | 41,255 bytes; SHA-256 `d57aa52a683b2b768de16e6212058af9079125aca54feb2fdf007e9ba8c5568f` |
| Platform and compiler | darwin/arm64; Go 1.25.14; `CGO_ENABLED=0` |
| Selection | `go test -p 1 -json -count=1 -timeout=60s -run '^TestConformance$' ./common/trie` |
| Actual result | Exit 0; complete output; package pass; 20 test pass events; no fail or skip events |
| Named cases | All 18: SMT-001 through SMT-014, CV-PATH-1/2 and CV-APPLY-1/2 |
| Other test events | SHA3Sanity and the parent TestConformance |
| Execution gate | SHA-256 `65c865e99929b9c2112319544c270398a42685f1c7c92f19003ec61842bbe7d0` |

The source intake reconstructed every recursive Git tree hash and checked all
484 archived regular files against their Git blob identities. The node's
vector bytes also match the selected
[documentation corpus](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/artifacts/smt-v1-test-vectors.json).
The module files and original source remained unchanged. Dependency preparation
used already available modules offline; no live node or network pilot ran.

The selected node test checks original proof encoding/root reconstruction and
CompactTree output. CV-PATH-1 exercises its path-native verifier against the
double-hashed raw-key alternative; CV-PATH-2 invokes its exported RootOfLeaves
API. CV-APPLY-2 exercises the node's L1-side mini-applier projection and
CompactTree updates. It does **not** run the executor's StateDiff applier.

This local node execution supplements the
[native candidate comparison](zeno-smt-conformance.md). It does not transfer
an old revision's result, replace exact-source hosted SPV qualification or
establish full node lifecycle/recovery behavior.

## Resource outcome and preserved failure

The initial cold attempt exceeded its 384 MiB task limit. Its actual exit -9
and incomplete output remain a failed attempt; the later pass does not relabel
that evidence.

The successful attempt retained the same 384 MiB limit. It first resolved the
actual package dependencies, then removed only unnecessary ZIP copies created
by that new task. Nineteen required module archives totaled 22,628,342 bytes;
41,422,174 bytes of unused new ZIP copies were removed. Standard-library
compilation ran in separate commands before the unchanged conformance test.
Compiler/linker flags and test selection were not weakened.

The sequence took 37.206 seconds locally. The largest workspace observation
taken **after** a command was 252,008,724 bytes, about 240.3 MiB. This is not a
continuous peak measurement, a hardware performance target or measured physical
disk reclamation. The temporary caches were removed after completion, the task
closed successfully and source/output/failure evidence remains retained.

To reproduce the selected assertion scope in a checkout of the pinned node
with its dependencies available, run the selection above. A local pass on
another source, toolchain or platform is a separate attempt.

## First incoming v3 remains a separate obligation

The selected source gives these distinct rules:

- [Genesis construction](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/chain/genesis/momentum.go#L17-L25)
  creates version 1 at height 1 and bypasses ordinary momentum verification.
- [Verifier context](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/verifier/momentum.go#L35-L47)
  resolves the incoming momentum's parent store.
- [Activation](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/chain/momentum/embedded.go#L152-L172)
  is false at parent frontier height 1. Otherwise it requires an activated,
  matching spork whose EnforcementHeight is no greater than that frontier.
- [Production](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/pillar/worker_momentum.go#L14-L56)
  reads that parent frontier before constructing incoming height parent + 1.
  State-tree readiness additionally gates v3 stamping.
- [Verification](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/verifier/momentum.go#L149-L167)
  requires v3 when the parent activation predicate holds.
  [Root validation](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/verifier/momentum.go#L460-L477)
  separately requires a computed matching root.

A conditional **source inference**, not an executed network boundary, follows:
if an activated matching StateRoot spork with enforcement E is already present
in the selected parent stores, the earliest possible incoming v3 is
`max(2, E) + 1`. Availability/readiness and the other selected profile rules
still have to permit progress. An enforcement field is not itself the
incoming activation height. A producer's not-ready behavior does not authorize
a supported delay in verifier enforcement.

The profile must also check height arithmetic before deriving that boundary.
For example, E at the uint64 maximum has no representable incoming E + 1;
wrapping it to zero is not a valid profile selection.

The existing
[node activation helper](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/tests/state_root_test.go#L17-L118)
advances past the boundary before inspecting a later frontier. Its presence,
or a tri-state version selector test, does not establish the first incoming
boundary. This conformance attempt did not execute those activation tests.

The selected profile still needs actual boundary controls from v1 genesis,
early/late/unknown version refusals, schedule coverage, canonical/schema caps
and recovery qualification. The [D0-D3 roadmap](typed-state-roadmap.md) also
requires a selected genesis/anchor/profile, owned accepted-v3 header and real
typed BatchEntry consumer. No activation, consensus finality, accepted state
value, STF correctness or production readiness follows from this report.

