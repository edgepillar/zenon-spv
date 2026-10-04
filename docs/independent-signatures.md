# Independent node-corpus signature checks

`tools/gen-node-momentum-vectors/check-signatures.py` verifies the existing
source-pinned corpus signatures with OpenSSL 3's default Ed25519 provider.
Python independently checks envelope bytes and reconstructs the SHA3-256
message before verification. The command uses existing fixture signatures;
it does not generate keys, sign, run a node/SPV executable or contact RPC.

From the repository root, with an installed OpenSSL 3 executable:

```sh
python3 -B tools/gen-node-momentum-vectors/check-signatures.py --openssl openssl
python3 -B tools/gen-node-momentum-vectors/check-signatures_test.py
```

`--openssl` accepts an executable path or a command resolved from PATH. The
backend must identify as OpenSSL 3; there is no automatic fallback or package
installation. On macOS with a keg-only Homebrew installation, pass
`--openssl "$(brew --prefix openssl@3)/bin/openssl"`. `--corpus-dir` selects a
directory containing the same seven corpus schemas. `--source-revision` can
record a caller-supplied 40-character commit; that claim is not authenticated
by the command. CI sets it to the actual job checkout revision.

## What is checked

All seven corpus files must retain the pinned node identity
`3a4131e63881058b6ce2ee81d3a41d0033fafc99`, its module version and checksum.
Input files are bounded, duplicate JSON members are refused, and every file is
snapshotted before any backend call. Existing byte oracles check the snapshots,
including Bech32 projections, full-width hashes, uint64 fields, data/content
hashes, compact content recipes, linkage and the historical genesis shape.
The checked account and momentum helpers expose their complete preimage bytes.
Account amounts retain integer types and full magnitude encodings, including
the intentionally invalid scalar vectors.

There are 91 signed fixture vectors: 79 momentums and 12 user account blocks.
Every original signature must verify. Each also has five expected rejections:
a changed digest bit, the raw serialized envelope as the message, a second
SHA3-256 hash, a changed signature bit and a noncanonical `S + L` scalar.
This produces 546 actual verification-process outcomes, including 455
signature rejections. The report separately records distinct message/key pairs;
repeated messages in different fixture positions are not described as distinct
real blocks.

Ten embedded account vectors and the historical genesis momentum must remain
unsigned. Their absence of signatures is checked explicitly; a missing user
signature does not create an unsigned exemption. Four account-amount vectors
have valid signatures over intentionally invalid scalar envelopes. They remain
invalid account envelopes and are identified separately in the report. Crypto
acceptance does not override the core verifier's amount or envelope policies.

For each original signature, OpenSSL receives a 32-byte recomputed hash as the ordinary Ed25519 message,
using `pkeyutl -verify -rawin -pubin -keyform DER` with no additional digest
option. The public key is wrapped in RFC 8410 SubjectPublicKeyInfo. A clean
environment, empty config, explicit default provider and `provider=default`
property query avoid caller configuration. Each child has a 20-second deadline.
Malformed key/signature widths are refused before backend invocation. An
arbitrary process failure or key-import diagnostic is not counted as an
expected signature rejection.

## Reports and limits

Successful stdout is a JSON report with corpus/checker SHA-256 pins, backend
version and executable hash, unsigned/invalid-scalar counts and every actual
verification exit/status and stdout/stderr hash. Diagnostics omit input values,
local paths and raw backend error text. Failed verification/deadline outcomes
retain safe partial process records and produce exit 2. Launch or final identity
failures also retain completed verification outcomes. No failure is retried.
The command's temporary public-key/message/signature files are removed on exit.

Linux, macOS and Windows CI run the controller controls and the real independent
checker. Each job uploads `independent-signatures-*` as a separate artifact;
the existing candidate/native-pilot artifacts keep their own schema. Signature
reports must be matched to the exact checkout, corpus and checker bytes when
reviewed. Python sources use explicit LF checkout attributes so their byte pins
remain identical on Windows, Linux and macOS. The executable hash does not authenticate dynamic libraries,
providers, the installation origin or source-to-binary distribution.

This is a separate Ed25519 implementation from the Go verifier, with selected
message/scalar corruption controls. It is not an exhaustive Ed25519 adversarial
suite or an independent human security review. Synthetic node-generated
fixtures do not authenticate a running network, anchor, activation profile,
producer schedule/election, canonical chain, consensus finality, state
transitions, balances or state-value proofs. Those qualification gates remain
separate from signature checks and native CI.

CLI and encoding references: [OpenSSL pkeyutl](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/),
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html),
[RFC 8032 verification](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7).
