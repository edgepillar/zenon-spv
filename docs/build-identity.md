# Build identity diagnostics

Both programs can describe their running build without reading RPC settings,
anchors, profiles, schedules, or state files:

```sh
./zenon-spv version --json
./fetch-bundle version --json
```

`--version` is an alias for `version` when it is the first argument.
Omit `--json`, or pass `--json=false`, for a short text report. The version
command accepts only its own flags; it cannot be combined with verification
or collection arguments. `version --help` prints its usage. Success exits 0,
invalid arguments exit 64, and an output failure exits 70. A closed pipe may
instead terminate the process according to the operating system's behavior.

## JSON schema 1

| Field | Meaning |
| --- | --- |
| `schema_version` | `1`; consumers should check it before interpreting the report. |
| `command` | `zenon-spv` or `fetch-bundle`, not the executable's local path. |
| `go_version` | Release/beta/RC Go version; custom or unrecognized strings become `unknown`. |
| `os`, `architecture` | The executable's Go runtime target. |
| `source` | Git build metadata, or `null` when missing, unsupported, incomplete, or ambiguous. |
| `source.vcs` | `git`. Other source systems are not reported by this schema. |
| `source.revision` | Full 40- or 64-character lowercase hexadecimal revision. |
| `source.modified` | Whether Git stamping recorded local changes at build time. |

Source metadata is read from the running binary, not from the current checkout.
An absent dirty marker is unknown, not `false`. Builds from an archive, builds
with `-buildvcs=false`, and environments without usable VCS stamping may have
`source: null`. Duplicate recognized source fields also produce `null`.

The report intentionally omits module and dependency paths, local replacements,
build flags, environment values, timestamps, and arbitrary metadata. Development
toolchain strings can contain private labels, so they are replaced with
`unknown`. Argument/output errors use fixed diagnostics. A commit hash and
the runtime target remain visible by design.

## Interpretation and validation

Record this report beside a controlled experiment's binary hash, source record,
and [verification context](verification-context.md). The report is not a binary
digest, a signed release attestation, or evidence that a build is reproducible.
An unmodified Git marker does not authenticate dependencies, ignored build
inputs, compiler flags, or the executable itself. Metadata can be forged.

Tests check missing/partial/duplicate source metadata, modified checkouts,
malformed revisions, private metadata exclusion, command parsing, and failed
output delivery. A compiled test reads each executable's embedded metadata
independently, invokes both command spellings, and checks the resulting report.
Invalid anchor settings and a counted loopback RPC endpoint confirm that the
version path does not enter configuration loading or network collection.
