# Chain-69 opening evidence on 27 November 2026

The selected query uses domain 1 and batch 0 on chain 69. Both runs below
selected the reference-gas renewal contract with SHA-256
`7af671795d7a9a97d57432ce1b38d490580340e7b844a083298dbcaf8a5c4fe0`.
The retained opening proof tests the selected BatchEntry key at H3, before
fixture configuration. See the [readiness ledger](typed-query-readiness.md)
for earlier executions and the remaining acceptance gates.

## Opening and terminal outcomes

| Run and exact runner revision | Opening versions | Actual terminal record |
| --- | --- | --- |
| [44961621978](https://github.com/edgepillar/zenon-spv/actions/runs/44961621978), `740518e172614f5a01da18917599c4bedc924566` | H1 v1, H2 v1, H3 v3 | `UNKNOWN` during fixture deposit. Timeout, exit 143, incomplete output. |
| [45905746425](https://github.com/edgepillar/zenon-spv/actions/runs/45905746425), `f058474d5f35cfa08cdccbf153d6fb9fbf9ab649` | H1 v1, H2 v1, H3 v3 | `UNKNOWN` during fixture configuration. Timeout, exit 143, incomplete output. |

Both archives record closure of the owned runtime. GitHub reports failure for
each workflow. The original archives and their SHA-256 digests follow.

| Archive | SHA-256 |
| --- | --- |
| [14730556980](https://github.com/edgepillar/zenon-spv/actions/runs/44961621978/artifacts/14730556980) | `737f2603f1136541c635e5552df4d6352a53d58e69088229a08bcb4275920a4c` |
| [15158177983](https://github.com/edgepillar/zenon-spv/actions/runs/45905746425/artifacts/15158177983) | `78495041b77c89845f20c5f4b1939e5bd95ae0e1303216e3f72ae4b3230276a3` |

The offline replay checked the indexed opening requests and responses. It
recomputed all six header hashes from their wire fields using 160-byte v1
preimages and 208-byte v3 preimages. OpenSSL 3.6.5 verified both original H2
and H3 signatures in each capture. The public keys derived the recorded
producer addresses. Four negative controls rejected H3 signatures over
messages with the StateRoot omitted or changed.

The captures share the selected H1 hash
`fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`.
The linked H2 and H3 identities differ between runs.

| Run | H2 hash | H3 hash |
| --- | --- | --- |
| 44961621978 | `62674faa490bea69fc92f562abcf1bb9a91da05af7b6a7117384f18c43e7be45` | `a4ac633fd459766c579326f2a1728ca5d64c9da8e10b1755d80504cd3c31053f` |
| 45905746425 | `bc5fe74547ed874e14d8a98580e6f52aaa8f64e2e7480d1b9eb14bc30c473876` | `78e7fd4a5bfe0db1efd311646051e9cc971c79ecf99963b8e033a82daeac3354` |

Both H3 roots are
`36fd7a907707f00939bb4741da5d8f3dd4fdf4200581ebe869b934a8f1981287`.
Both responses carry the same 259-byte absence proof with five siblings.
Its SHA-256 is
`5dc5adc0b21bee3b5fa405fe4c2c07e431a6bff36ce73a688f16f67e6796e37e`.
The replay derived the key from the selected Settlement address, domain and
batch. It checked the zero leaf and folded the five siblings along the local
path to each H3 root. Changing the last proof byte changed the folded root.
The replay read the retained archives in place.

## Remaining acceptance evidence

The captures provide two observed opening transitions and independently
rechecked candidate-root absence proofs. The next execution must derive its
own anchor from its opening response. D2 still requires finite producer
authorization from the selected closed-ledger range. D3 and the native host
exit require three present canonical proofs under the same header-derived
StateRoot, a completed typed BatchEntry result and all 17 stored gateway
fields matching.

The next prepared main runner is
`c64f5453521f4f334bcb6205bbe00d9adfed3980`. Its exact-source qualification
covered 44 original archives and 21 binaries. It gives the reference-gas
configuration command 660 seconds and retains selected progress on timeout.
A fresh dispatch requires its own approval. [General CI](https://github.com/edgepillar/zenon-spv/actions/runs/45911169119),
[preparation CI](https://github.com/edgepillar/zenon-spv/actions/runs/45911169178).

The consumer and parent-oracle archives use source
`58e03fa9ff58a752cfd1718245b31cba73dde473`. The 27 November metadata check
reported both archives unexpired. The earlier listed expiry is 11 December 2026
at 15:36 UTC, so the next dispatch must repeat the availability check.
[Consumer artifact](https://github.com/edgepillar/zenon-spv/actions/runs/44764773500/artifacts/14645836816),
[parent-oracle artifact](https://github.com/edgepillar/zenon-spv/actions/runs/44764773665/artifacts/14644100853).
