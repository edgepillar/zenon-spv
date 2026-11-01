# Zeno SMT vector conformance

This is D1 mathematical preparation for the selected Zeno devnet consumer. The
native candidate proof functions now have a source-pinned comparison against all
18 cases in `SMT-CONFORMANCE-V1`. This does not enable v3, construct an accepted
header, select a network profile or return `STATE_VALUE_INCLUSION`.

## Selected input

The normative vector input is
[`Zeno-L2/zeno-docs@d74ba1fc4b01583af0daf33a2dedfc84ea2b9419`](https://github.com/Zeno-L2/zeno-docs/blob/d74ba1fc4b01583af0daf33a2dedfc84ea2b9419/artifacts/smt-v1-test-vectors.json):

- Git blob: `bfb42cb31b710fbb41f07d0d606b3d40dda99afa`.
- Original length: 41,255 bytes.
- Original SHA-256: `d57aa52a683b2b768de16e6212058af9079125aca54feb2fdf007e9ba8c5568f`.

The [normalized facts](../internal/testdata/conformance/zeno-smt-v1-facts.json)
retain the case IDs, mathematical values, operation descriptions, serialized
proof bytes and expected results. Upstream explanatory prose and implementation
code are excluded. The fixture records its original source digest and its
mathematical-only scope; the test separately pins the normalized bytes.

The source intake also compared the complete `common/trie` directory entries at
`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b` and
`938fca3b7787da86827a5eb63371509b36e14761`. Their file/blob and child-tree
identities match. This source equivalence does not transfer an old execution,
recovery qualification or activation claim to the selected node revision.

## What runs

[`TestCandidateSMTZenoConformance`](../internal/proof/zeno_smt_conformance_test.go)
has one subtest for each of the 18 named vector cases. Its test-only oracle
builds a full depth-256 tree from path/value facts, traversing from the root.
The existing candidate verifier independently reconstructs a root from a bounded
proof, traversing bottom-up. These two paths must agree with the pinned expected
values.

| Obligation | Executed comparison |
| --- | --- |
| SMT-001 through SMT-014 | Expected roots, declared leaf/branch hashes, initial and resulting states, operation projections and supplied per-operation roots. |
| Serialized inclusion | All 11 supplied inclusion proofs: exact wire bytes, path, value/presence and native candidate reconstruction. |
| Serialized absence | All six supplied absence proofs, including the named absent key: exact wire bytes, path/presence and native candidate reconstruction. |
| Proof metadata | Declared length, leaf hash, bitmap and ordered nonzero siblings must agree with the serialized bytes wherever supplied. |
| CV-PATH-1 | The already-derived path matches; hashing that path again is refused by the candidate verifier. |
| CV-PATH-2 | All 14 referenced state/root cases are rebuilt by the independent oracle and consumed through generated native candidate proofs. This does not execute the node's exported `RootOfLeaves` API. |
| CV-APPLY-1 | The test-only StateDiff projection preserves a present-empty write and a distinct delete; resulting roots and native proofs must agree. |
| CV-APPLY-2 | Each supplied multi-entry diff is projected separately; the declared state/root and generated native proofs must agree after every step. This does not execute a node/executor incremental applier. |

Every state used by the oracle also supplies a generated proof for each present
key and an independently selected absent path. Present-empty remains present;
the empty subtree is zero at every depth. SHA3-256 and the two value-length
sentinels have separate checks.

Case counts, serialized-proof counts and assertion counts are different. An
18-case pass must not be reported as 18 root comparisons or as execution of all
node/executor APIs named by the specification.

## Reproduce the selected native checks

With the root module's dependencies already available:

```sh
go test -count=1 -run '^TestCandidateSMTZenoConformance$' ./internal/proof
```

The local selected run passed all 18 case subtests and their parent. Pinned
golangci-lint 2.6.2 also checked `./internal/proof`; `go mod verify` passed and
the module files stayed unchanged. These are local results for the changed test
inputs, not hosted qualification or a new runtime distribution.

The initial local attempt failed because its strict decoder had not yet mapped
the upstream proof metadata fields. That failed attempt remains preserved;
the corrected test checks those fields rather than ignoring them.

## Remaining D1 and consumer gates

The existing [candidate SMT scope](candidate-smt-proof.md) is unchanged. Its
caller-selected root is unauthenticated. A canonical mathematical match cannot
replace the StateRoot from an owned accepted header.

Still required for the selected integration:

- The D0 network/genesis/anchor, query and source/profile contract, including
  producer schedule provenance and coverage.
- The actual first-incoming-v3 transition from v1 genesis, rather than an assumed
  height derived from the spork enforcement setting.
- The selected node/executor APIs' actual conformance and lifecycle execution;
  source equivalence and a test-only projection do not close those gates.
- Agreed canonical encoding and schema-aware value/proof/cumulative-work limits.
  The candidate's local research caps are not network or BatchEntry ABI limits.
- The owned v3 RPC/authentication/context/persistence path and actual typed
  BatchEntry consumer, plus the applicable negative acceptance cases.

The selected [roadmap update](https://github.com/edgepillar/zenon-spv/pull/294)
keeps native v1/v2 inclusion independent. Consensus finality, state-transition
correctness, production state proofs and irreversible settlement remain outside
these mathematical test results.
