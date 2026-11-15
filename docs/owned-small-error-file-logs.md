# Retain a bounded error file's first record

## Observed limitation

The single authorized [run 43682026524](https://github.com/edgepillar/zenon-spv/actions/runs/43682026524)
used source `8d5fe4e72088286b2871417d6e7894a2ba10c5d2` and contract
`6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31`.
It refused at `nodes/owned_rpc_readiness_deadline`. Domain setup, a deposit,
the selected proof and the BatchEntry consumer did not complete.

The original result is artifact `14149185522`, 352,308 bytes, SHA-256
`88f871f45dc5c7fa770759dccdb50ad1d9266a508323eb2701c8a2d0929f1227`.
The source/run/contract-bound review verified the original payload and retained
`HOSTED_RECORDED_NON_ACCEPTING_OUTCOME`. It did not execute a new consumer.

The v3 report selected byte tails for all eight file reads from the prior
running-state observations. Five reads were observed and three error-file reads
failed. One observed error tail was 213 bytes: its leading-discard count was also
213, with zero classified bytes and zero trailing-discard bytes. The conservative
tail reader therefore omitted the only record rather than guessing that a short
non-atomic read began at the start of the file.

These are retained diagnostic assertions over omitted streams. The error text
cannot be independently reconstructed from the archive. The worker/late-production
counts and nonzero cleanup exits do not establish the cause of the readiness
refusal. The terminal's owned-runtime closure remains unestablished.

## v4 selection

| Fixed file kind | Prior owned inspection | Method | Bounds |
| --- | --- | --- | --- |
| Error | Validated | Whole file from byte zero | 64 KiB TAR, 32 KiB decoded regular file |
| Run | Running, unpaused, non-restarting and non-dead positively observed | Byte tail | 32 KiB stdout |
| Run | Another validated state | Whole file | 64 KiB TAR, 32 KiB decoded regular file |
| Either | Ownership or inspection unavailable | No read | No parsed data |

The whole-file reader preserves a small error file's first record. A larger
error file remains unknown or refused under the existing caps; there is no
fallback tail, second read or cap increase. Run-file tails retain their
complete-inner-line policy. No line-only tail, configurable path, shell, host
destination, extraction, new mount, restart or unpause is introduced.

There are still at most eight file commands and seventeen read-only Docker
commands overall, with five seconds per command and 4 KiB stderr per file read.
The `owned-devnet-startup-file-logs/v4` reader binds the recorded method to the
fixed file kind and the prior typed inspection. The v1, v2 and v3 rules remain
unchanged; relabeling an old method policy as v4 is refused.

Controls cover a single 213-byte error record, privacy, oversized-file refusal
without a retry, the fixed command roster, kind/state binding and version
separation. TAR fixtures stay in memory. These controls do not establish actual
v4 Docker execution or resolve the observed node failure. Another signed
fixture needs its own source-specific authorization. Diagnostic summaries have
no header, canonicality, finality or state-value authority. Production state
proofs remain NO-GO.
