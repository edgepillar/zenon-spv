# Bounded candidate SMT proof sets

Status: **MATH_ONLY_SUPPORTING_PRIMITIVE**. This helper prepares the cumulative
work boundary for the [three supporting witnesses](batch-entry-domain-context.md).
It does not yet compose an owned BatchEntry query with domainRecord/domainConfig.

## One selected root and bounded work

`proof.ReadCandidateSMTProofSet` reads one to three distinct caller-selected SMT
paths against one caller-selected root. Paths are already application-key
SHA3-256 positions; this helper does not hash them again or derive ledger keys.
An empty set, repeated path, mixed-root witness or any malformed member fails
the complete call. Every error returns a nil result slice.

The caller selects positive count, proof-byte and value-byte budgets, within
these local research ceilings:

| Work | Individual ceiling | Three-proof ceiling |
| --- | ---: | ---: |
| Encoded proof bytes | 12,391 | 37,173 |
| Stored value bytes | 4,096 | 12,288 |
| Encoded siblings | 256 | 768 |

Aggregate ceilings also scale down with the selected maximum proof count. These
are upper bounds for this mathematical primitive, not selected network or
typed-query policies. The future domainConfig input should select its exact
64-byte value limit; the primitive does not infer ABI schemas from a path.
An inclusive sibling cap of zero means no encoded siblings, rather than an
unlimited cap. An empty-tree absence can satisfy that cap. Value-byte caps remain
positive even when a particular proof contains an absent or present-empty leaf.

The shared parser first checks the complete collection's raw byte budget, then
all framing, individual limits, total stored bytes and total encoded siblings.
It uses a fixed three-member internal array. Only after this preflight does it
hash leaves/branches and compare every member with the selected root/path.
Detached output slices are allocated only after all mathematical checks pass.
Encoded zero siblings still consume the work budget, even when mathematically
equivalent to omitted siblings.

The existing single-proof readers use the same framing and reconstruction
helpers. Their expected-value comparisons, detached outputs, error classes,
presence and canonical-encoding facts remain unchanged. No input may be mutated
concurrently with a read.

## Evidence and limits

Controls replay the existing 41 pinned original-node byte cases through both
single and set readers, and read distinct present/absent paths under the same
recorded roots. They cover exact and one-less individual/aggregate budgets,
zero/negative/overflow policies, duplicate/substituted paths, mixed roots,
every late-member truncation, late mathematical failure and detached outputs.
The existing original-node corpus is reused without a new node execution or
another source/archive download. Local allocation controls and bounded fuzzing
are implementation evidence; resource timings do not qualify a live workload.

The bounded local run used Go 1.25.14, darwin/arm64 and two Go workers. The
race-selected lane passed 20 test roots and 293 subtest pass events, including
8 new roots and 81 new subtests. Five seconds of targeted fuzzing exercised
145,326 inputs. Vet and the two used modules' ZIP/expanded h1 checks and
`go mod verify` passed. These local results do not replace source-specific
Linux/macOS/Windows CI and artifact qualification.

The non-race three-proof benchmark used a 100 ms target per case:

| Case | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Three matching recorded proofs | 122,978 | 224 | 4 |
| Third proof reconstructs another root | 123,947 | 0 | 0 |
| Aggregate stored-value cap exceeded | 34.01 | 0 | 0 |

The successful result owns a result slice and three detached values; the new
guarantee concerns failure paths, not a reduction in successful-output copies.
The complete local qualification took 58.2 seconds. Its largest after-phase
workspace observation was 353,392,112 bytes under a 768 MiB task limit; this is
not a continuously measured peak. Owned temporary source/module/build/fuzz data
was removed. The source inputs, actual output receipts and compressed test
binary were retained once; no new node capture or full-job logs were needed.

Presence and canonical encoding remain returned facts. An enclosing typed-query
policy must require both for all three supporting rows. A successful set read
does not establish application coverage, accepted header/height/context, a domain
identity, ABI semantics, registration rules or historical configuration. It
cannot create an owned state handle or enable production state-value acceptance.

The next integration still needs an explicit versioned context and work profile,
three locally derived keys at one owned H/hash/root/context/tip, typed decoding
and all-or-nothing consumer output. Current-H context does not establish a
batch's submission-time configuration. Selected-network capture, independent
trust inputs, independent review and authenticated distribution remain open.
