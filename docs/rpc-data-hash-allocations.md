# RPC data-preimage hashing allocations

The RPC account and momentum conversion paths derive `DataHash` locally from
the complete Base64 `data` preimage. Large valid values are decoded into a
small scratch buffer and fed into SHA3-256, instead of retaining the complete
decoded payload. The encoded string, JSON buffers, response and range byte
budgets remain unchanged. This does not authenticate a peer-supplied hash.

Values at most 4 KiB retain the original direct decode. Larger values use the
standard streaming Base64 decoder. An alphabet character after padding forces
the whole-value decoder, since streaming can otherwise accept independently
padded blocks across read boundaries. Streaming failures also use the original
whole-value decoder to preserve exact error types and offsets and discard the
partial hash. Malformed inputs retain the old decoded-buffer allocation
behavior; this optimization concerns valid large preimages.

`BenchmarkRPCDataHashDecode` isolates decode-plus-hash work on synthetic decoded
preimages of 32 KiB, 1 MiB and 8 MiB. Construction and expected hashes occur
outside timing. `buffer_reference` uses the exact prior `DecodeString` followed
by `sha3sum` expressions; `stream_hash` uses the current path. Every iteration
requires the identical expected hash. Both preserve standard Base64 semantics,
including CR/LF, padding and nonzero padding bits accepted by `StdEncoding`.

Linux, macOS and Windows CI record three iterations per mode with `-benchmem`.
These observations measure this hashing step's total allocation volume and
timing. They do not measure peak RSS, the complete RPC/verification workflow,
network performance or an accepting proof. No fixed allocation or latency gate
is used. Node corpus and source/report/binary checks remain separate from
independent review, authenticated network inputs and release qualification.
