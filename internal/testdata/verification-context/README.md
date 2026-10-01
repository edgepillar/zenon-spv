# Verification context vectors

These synthetic configuration vectors exercise the versioned diagnostic
encoding in [verification-context.md](../../../docs/verification-context.md).
They are separate from the node-derived momentum corpus and establish no
network activation, anchor authenticity, or consensus guarantee.

- `v1.json`: synthetic chain 3 anchor, depth 2, default resource limits,
  explicit v1-only profile through height 110, authorization disabled.
- `v1-schedule-checkpoints.json`: synthetic chain 1 anchor, depth 6, default
  limits, no profile, and a required operator schedule. It includes the four
  currently embedded mainnet checkpoints. The two synthetic schedule entries
  are heights 101 and 102, timestamps 1700000010 and 1700000020, each with
  producing-address bytes `01` followed by 19 zero bytes. Coverage is 101..102.
  Its schedule hash follows the existing producer-schedule binary format.
- `v2-retention.json`: the first vector with explicit K=16. Schema 2 binds
  retained capacity independently of depth, using its own domain separator.

Expected fingerprints, and the second vector's schedule hash, were calculated
with Python SHA3-256 and big-endian integer packing. The root Go tests compare
the complete API output with these files. `python3 tools/check-verification-context.py`
independently checks all three stored context fingerprints. Do not regenerate the
expected values from the Go function being tested.
