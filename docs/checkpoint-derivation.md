# Checkpoint derivation

`tools/derive-checkpoints` prepares mainnet checkpoint candidates for release
review. It does not update the embedded list or establish checkpoint provenance.

```sh
go run ./tools/derive-checkpoints \
  --peers https://peer-a.example,https://peer-b.example \
  --heights 1000000,5000000 \
  --timeout 60s
```

The tool requires at least two distinct configured endpoint strings and heights
after genesis. Invalid, repeated, or missing heights, duplicate endpoints,
nonpositive timeouts, and positional arguments fail before RPC. `--timeout`
covers the whole collection, including all heights; it is not renewed per peer
or per height. Environment endpoints may be supplied through `ZENON_SPV_PEERS`,
but help output does not print those values.

At each height the shared multi-peer client checks the exact requested height
and count, recomputes supported momentum hashes, and requires every configured
peer to return the same hash, public key, and signature. A failed or malformed
peer aborts collection; two healthy peers out of three are not unanimity.
The agreed header must have `chain_id=1` and a valid Ed25519 signature. Both
implemented layouts, v1 and v2, can be observed; this does not authenticate
their activation rules or prove that the signing key was an elected producer.

Success writes a sorted Go declaration to stdout only after all requested
heights pass. The output begins with comments recording the external trust
boundary and can be reviewed for use in `internal/verify/checkpoints.go`.
Collection failures emit no stdout; errors exit with status 1. A stdout write
failure also fails the command, but bytes may already have reached its reader.
Do not consume incomplete output. Shell redirection may truncate a destination
before the command starts; capture to a separate file and inspect success before
replacing a previous artifact.

Runtime diagnostics use anonymous peer labels and omit configured endpoint
credentials, paths, and query parameters. The emitted declaration contains
only heights, hashes, and fixed comments. Local output failures retain causes
for programmatic inspection without printing arbitrary cause text.

Peer agreement cannot establish operator independence, network identity,
canonical history, or finality. A fully consistent fabricated chain signed by
the same claimed key can pass these observation checks. Independently justify
the endpoints, network, selected history, and distribution channel before using
a candidate as an embedded trust input. This tooling change does not refresh
or independently verify the existing historical checkpoint list.
