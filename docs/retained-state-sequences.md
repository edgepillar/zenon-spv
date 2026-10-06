# Retained-state operation sequences

`TestRetainedStateSequenceModel` combines retained-state operations against a
separate list model. The model stores fixture indices, the next accepted index,
W, explicit K or legacy capacity, and whether a nonempty local file was resumed.
It never calls production append, policy-capacity, header verification,
commitment verification or retained-state validation to calculate expectations.
The production API is the system under test.

The matrix has 18 cells: v1 without a profile, v1/v2 under a finite profile, or
v1/v2 with finite producer-schedule coverage; W=1/2/6; and legacy or explicit K.
Each cell runs two deterministic sequences. A fixed prefix combines startup,
whole-batch rejection after a valid prefix, unsupported versions, empty input,
save/resume, authorization before shrinking, capacity changes, omitted explicit
retention, W changes, incompatible profiles, detached-view mutation, queries,
failed saves and malformed saved input. Repeated extensions reach the finite
profile or schedule boundary. A fixed integer generator then selects 32 more
operations. No timing threshold, network or shell is used.

After every operation the test compares the exact signed retained envelopes,
ordering, capacity, tip, lookup availability and depth-eligible range. Boundary
queries mix complete, missing, corrupted and nonmember evidence and check the
outcome, reason, fault index, inclusion guarantee and exact trust set. Four
predecessor handles are checked too. Caller-owned header envelopes are mutated
after extension, and detached state views are mutated between operations.
Read-only loads must preserve the saved bytes. Policy changes must invalidate
the previous context pin; unchanged selections must keep it usable. These are
configuration-consistency checks, not input authentication.

`FuzzRetainedStateSequence` uses the same oracle with up to 96 operations and
three seed programs. Its first two bytes choose profile mode and initial W/K;
the remaining bytes encode operation and argument. Each run owns a private
temporary directory. A fixture contains 256 signed momentums; exhausting this
test fixture produces an empty extension rather than inventing more history.
The deterministic matrix is the `retained_state_sequences` offline-pilot case.

## Full-capacity operation sequences

`TestRetainedCapacitySequenceModel` reuses the independent fixture-index model
at K=16/256/4096, in all three profile/schedule modes, with W=6 or W=K-1.
These 18 cells start by filling exactly K signed headers. Each then combines
resume, invalid final envelopes after a valid prefix, full-window eviction,
tail-only authorization refusal before shrinking, omitted/invalid retention,
shrink to K=8, growth without history recovery, refill, another eviction,
W=K-1 depth, finite profile/schedule expiry and final save/resume. The same
exact envelope, query, trust and context-pin checks run after every operation;
three immutable predecessors and selected delayed targets are checked too.
Read-only load attempts must preserve saved bytes, including failed attempts.

The large fixtures contain 2*K+32 synthetic headers, with unique content at
each height. Profile and schedule coverage extend through the refill and then
expire inside a multi-header batch. An explicit reason-coverage assertion
requires that expiry path to occur. This complements the separate populated
capacity measurements; it does not measure memory, latency or a network budget.
The `retained_capacity_sequences` offline case selects this deterministic test.
The offline runner passes its selected overall `--timeout` to Go's per-package
deadline too. Its overall process context remains the bound, with the existing
ten-minute default and one-hour maximum; there is no shorter hidden five-minute
package limit. Full-capacity race instrumentation can take substantially longer
than ordinary execution. A timeout is a failed/incomplete run, never a pass.

```sh
go test -run '^TestRetainedCapacitySequenceModel$' -count=1 ./internal/verify
```

```sh
go test -run '^TestRetainedStateSequenceModel$' -count=1 ./internal/verify
go test -run '^$' -fuzz '^FuzzRetainedStateSequence$' -fuzztime=5s -parallel=1 ./internal/verify
```

All momentums, content and schedules in this harness are synthetic and use an
explicit test key. Signing and hash functions construct fixtures; the separate
list oracle checks operation semantics, not independent cryptographic bytes.
Existing node-corpus, Python and OpenSSL checks retain their separate scope.
These sequences establish no executed history, authenticated anchor/profile/
schedule, canonicality, consensus finality, activation, state-value proof,
network pilot, independent human review or release provenance.
