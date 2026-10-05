# RPC response buffer allocation observations

The JSON-RPC client now grows its response buffer by half its current capacity,
clamping each allocation to the remaining response/range budget plus one
overflow-probe byte. The initial allocation is at most 512 bytes. Compared with
the preceding `io.ReadAll` path, fewer large buffer copies can reduce cumulative
allocation volume. `Content-Length` and other peer metadata do not select an
eager allocation, input boundary or accepted JSON value.

The existing 64 MiB combined range limit, HTTP/redirect policy, compression
setting, whole-envelope validation and result decoder remain unchanged. An
exhausted budget refuses before transport. A non-EOF read error still wins over
complete JSON or a simultaneous overflow byte; its original cause is retained
behind private ordinary formatting. Overflow leaves the result and budget
untouched. A successful read consumes its actual length from the shared budget,
including on a later JSON/envelope failure. Bodies are closed on every completed
HTTP response path. No read-error retry or partial-result acceptance is added.

`TestRPCResponseReadContract` compares accepted bytes, exact terminal errors and
consumed input against the preceding `io.LimitReader` plus `io.ReadAll` contract.
It exercises short reads, temporary empty reads, EOF with data, non-EOF errors
with data, growth/budget boundaries, closure and safe cause formatting. Complete
client calls also check ambiguous/trailing JSON, ignored length metadata and
two calls sharing a range budget. `FuzzRPCResponseRead` performs the same bounded
byte/error comparison. The offline pilot adds this contract as its 51st case.

`BenchmarkRPCResponseRead` measures a complete client call with an in-memory
HTTP transport: request creation, body reading, envelope validation, result
decoding and actual byte accounting. It compares a test-only captured parent
call body with the current call. The parent body differs only in receiver
adaptation and retains the preceding read path; envelope/result decoders are
shared. Every iteration checks exact independently selected result bytes and
the remaining budget. Samples include the existing node-derived account RPC
fixture and synthetic envelopes with 32 KiB, 1 MiB and 8 MiB of unused metadata.
Input/fixture construction is outside timing. Native Linux, macOS Intel and
Windows CI record three iterations per mode with `-benchmem`.

These are cumulative allocation and timing observations. They do not establish
peak RSS, a universally smaller retained buffer, full signature/inclusion
workflow latency, live-network performance, concurrency or consumer hardware
budgets. Growth strategies trade retained capacity against the number of copies;
small payloads can have different costs. There is no fixed allocation/timing
acceptance threshold. Existing node corpora, hash/signature oracles, trust inputs,
context pins and proof policy remain unchanged. Independent review, authenticated
distribution and real-network qualification remain separate gates.
