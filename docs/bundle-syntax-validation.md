# Bundle syntax validation reuse

The bounded file and byte entry points use a private `encoding/json` adapter.
The standard library checks the complete input's syntax, trailing bytes and
nesting depth before invoking that adapter. The adapter reuses this check for
the existing field-span decoder rather than scanning the same complete input
again. It still checks nonnegative decode limits before projecting fields.

Direct `HeaderBundle.UnmarshalJSON` calls and the standalone bounded decoder
retain their own complete standard-library syntax validation. The private
validated helper requires checked syntax and nonnegative limits; it must never
receive a stream prefix, a provider's assertion or an unchecked direct call.
Nested values retain their existing standard-library decoders and budgets.

Whole-document syntax still precedes field, duplicate and count decisions in
the file/byte loaders. Direct bounded calls retain their existing
invalid-limits-first order. Field aliases, unknown extensions, concrete errors,
transactional receivers, wire version, byte/count/work budgets and proof trust
boundaries remain unchanged. This does not accept a state root or change an
anchor, profile, schedule or context pin.

## Controls and observations

The test-only adapter retains the callback body from
`6116c0c23b7d1d6a5d111a81753bc091036759be`. It exercises the previous double
validation path while sharing unchanged field and nested decoders. Complete
projections, refusal text and concrete syntax/type/count/byte errors must match.
Additional controls cover direct public calls at every truncated prefix,
standard nesting boundaries, malformed trailing fields before early resource
or duplicate failures, invalid-limit precedence, and receiver/input ownership.
A bounded fuzz target compares both adapter paths.

The paired benchmark repeats complete flat lists for every target, including
100,000 members and four proofs. Encoding and full projection comparisons are
outside timing. It measures decoder work and cumulative Go allocation; it does
not establish peak RSS, sustainable throughput, real filesystem or network
latency, a whole-CI speedup, representative R1 capacity or production acceptance.
The existing node-derived content, signature, target, mutation and limit grids
remain separate and unchanged.

Initial local Go 1.25.14 darwin/arm64 observations used two benchmark CPUs,
three iterations per sample and three samples per mode. Median observations
were:

| Members per proof | Proofs | Double-check reference ms/op | Validated callback ms/op | Reference allocs/op | Callback allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 1 | 3.524 | 3.017 | 93 | 88 |
| 1,000 | 16 | 57.282 | 47.582 | 382 | 377 |
| 100,000 | 4 | 1,411.605 | 1,195.935 | 158 | 153 |

The largest case's cumulative allocated bytes were effectively unchanged:
59,195,184 versus 59,194,917 B/op. The observed benefit is less repeated syntax
work, rather than a large memory reduction. These short paired samples do not
predict a whole-CI or cross-platform speedup. The local proof package's 88
test/fuzz roots and 856 child pass events completed with the race detector;
a separate five-second fuzz run, configured root lint, vet and module checks
also passed. Hosted exact-source qualification is a separate gate.

Use a bounded owned workspace and cached dependencies. Keep raw diagnostics and
local CPU profiles private:

```sh
go test -race -count=1 ./internal/proof
go test -run '^$' -fuzz '^FuzzBundleSyntaxValidation$' -fuzztime=5s -parallel=2 ./internal/proof
go test -run '^$' -bench '^BenchmarkProofBundleSyntaxValidation$' -benchtime=3x -count=3 ./internal/proof
```
