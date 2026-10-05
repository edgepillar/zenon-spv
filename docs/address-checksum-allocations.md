# Address checksum allocations

RPC address and token-standard conversion validates Bech32 checksums before
packing the payload. The checksum now consumes the HRP expansion and validated
5-bit values sequentially, without retaining a concatenated input copy. Case
handling, HRP/character/checksum errors, payload packing and width checks remain
unchanged. The encoded string and decoded 5-bit values keep their existing
storage and response/range bounds.

`internal/fetch/testdata/bech32-address-vectors.json` contains 49 unique address
byte vectors and 191 address-field occurrences from seven pinned node corpora.
`python -I -B tools/check-address-checksum-vectors.py` independently recomputes
the checksum, packs the 160 payload bits and checks source pins and occurrence
counts. These vectors authenticate no network, operator or anchor.

`BenchmarkRPCAddressChecksum` compares the captured parent concatenation path
with sequential checksum parts. It measures one address, the 49 unique vectors
and the 191 recorded field occurrences, with fixture/input construction outside
timing. Every iteration requires the independently expected bytes. Linux,
macOS Intel and Windows CI record three iterations per mode with `-benchmem`.
The explicit `macos-15-intel` image provides native `darwin/amd64` qualification;
these observations do not establish hosted macOS ARM coverage for this successor.

These are isolated decoder allocation/timing observations, not peak RSS, full
RPC/verification workflow, network performance or consumer-budget qualification.
No fixed allocation or latency gate is used. Node conformance, independent
review, authenticated trust inputs and release qualification remain separate.
