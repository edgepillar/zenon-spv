# Candidate Settlement BatchEntry key

The D0/D3 preparation now includes pure native helpers for a locally selected
Settlement address, domain and batch. They derive the full L1 ledger key and
its SHA3-256 SMT path. They do not select an accepted network profile or return
an accepted state value.

## Selected source mapping

The mapping is pinned to
[`digitalSloth/go-zenon@938fca3b7787da86827a5eb63371509b36e14761`](https://github.com/digitalSloth/go-zenon/tree/938fca3b7787da86827a5eb63371509b36e14761).
The source intake independently reconstructed every recursive Git tree hash
and checked the archived file bytes against their Git blob identities.

The key has this 35-byte layout:

```text
03 || Settlement address (20 bytes) || 04 || 02 || domain (u32 BE) || batch (u64 BE)
```

The layers are distinct:

- [The momentum account store](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/chain/momentum/ledger_store.go)
  prefixes the address with `03`.
- [Account storage](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/chain/account/store.go)
  adds `04` through the nested database subset.
- [BatchEntryKey](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go#L582-L588)
  adds the 13-byte application subkey: `02`, a big-endian uint32 domain and a
  big-endian uint64 batch.
- [The L1 fold](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/common/trie/momentum_fold.go#L16-L43)
  covers this storage family and hashes the complete ledger key once.

Hashing the application subkey alone, changing the family or hashing an
already-derived path produces a different query identity. The L2 path-native
adapter and its present-empty semantics remain separate from the L1 fold.

## Native interface and checks

`CandidateSettlementBatchEntryKey` returns a detached `[35]byte`.
`CandidateSettlementBatchEntryPath` returns the SHA3-256 position for the
existing path-native candidate SMT checker. Both take a raw fixed-width
`chain.Address`, `uint32` domain and `uint64` batch.

Select the expected Settlement address and query identities locally. Text
parsing, checksum checks, integer input bounds and network/profile binding
remain the caller's responsibility. A gateway must not select these expected
inputs.

[Six source-derived byte cases](../internal/testdata/conformance/settlement-batch-entry-keys.json)
cover zero/max width boundaries, the selected source's public Settlement
address, byte-order probes and another address. Python's independent
`hashlib.sha3_256` supplies the golden path digests. The native tests also
check a mathematical proof with the derived path and reject ten changed
identity/namespace/byte-order paths.

These cases are source-derived mathematical checks. They are not output from
an executed node or executor. The proof's arbitrary payload is not a decoded
BatchEntry ABI.

## Remaining acceptance

The [typed-state roadmap](typed-state-roadmap.md) still requires the selected
genesis/anchor/profile and producer schedule, an owned accepted v3 header and
its StateRoot, bounded canonical proof consumption and strict BatchEntry ABI
decoding in a real read-only consumer. The caller-selected candidate root
remains unauthenticated. No network activation, consensus finality or state-value
acceptance follows from these key helpers or their tests.
