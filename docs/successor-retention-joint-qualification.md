# Joint successor retention qualification

The successor retention controls and the complete recorded reader derive the
same 32,768-height model in separate processes. In the qualified macOS job for
[main revision `834d551`](https://github.com/edgepillar/zenon-spv/actions/runs/43417753556),
these steps took about 41 and 46 seconds. They remain recorded-data checks;
running them does not execute a new reference node or qualify native resources.

The joint runner executes all 13 unchanged successor controls and then the
unchanged reader in one fresh process. It reuses only the reader's existing
single-entry cache keyed by the complete encoded presealed expectations. It
adds no table cache and changes neither the model nor the recorded inputs.

## Admission and evidence boundaries

The runner verifies separate SHA-256 pins for the successor reader, its original
test module, the complete corpus, and the recorded genesis execution evidence.
The successor path uses its own strict regular-file and JSON decoder. It does
not relabel the original corpus or substitute the original reader's report.

Admission requires an empty, one-entry cache and the complete 13-test suite.
Failures, errors, skips, expected failures, unexpected successes, early stops,
partial suites and unexpected stdout refuse the comparison. After the controls,
the runner checks the corpus identity, the presealed input digest and a seal of
the entire cached graph. The full reader must add exactly one cache hit and no
misses. The same cache function and complete graph seal are checked again after
the comparison, and every source pin is reread before stdout is released.

The original reader's stdout is emitted unchanged. A separate stderr receipt,
`recorded-successor-retention-joint-controls/v1`, records the 13 executed tests,
zero skips/failures/errors, one comparison hit, zero comparison misses and no
additional history derivation. The report and receipt retain
`consumer_result: REFUSED`; header binding, network execution, profile agreement
and production acceptance do not follow from model reuse.

The existing default remains the original 27-control qualification, including
its original receipt format. Its 19 runner controls remain in CI. Twelve added
successor runner controls use tiny graphs and source checks rather than another
long replay. The Linux and native platform CI jobs select the successor cohort;
the recorded-oracle job and every Go/native source remain unchanged.

## Reproduction

Run the combined successor qualification with the actual checkout revision:

```sh
python -I -B tools/gen-state-root-vectors/run_successor_retention_checks_test.py -v
python -I -B tools/gen-state-root-vectors/run_default_retention_checks.py --cohort successor --source-revision CHECKOUT_SHA
```

`CHECKOUT_SHA` must be the lowercase 40-character Git identity. It is a caller
label, not authentication of the checkout. Exact-source CI and artifact checks
must establish that binding separately. Omitting `--cohort` retains the original
27-control behavior. The original separate successor commands remain available:

```sh
python -I -B tools/gen-state-root-vectors/check_default_retention_successor_corpus_test.py -v
python -I -B tools/gen-state-root-vectors/check_default_retention_successor_corpus.py --source-revision CHECKOUT_SHA
```

## Finite local cost observations

Four fresh Python 3.9.6 processes on Darwin ARM64 were measured in
separate/joint/joint/separate order. Each separate sample consists of two
sequential children: the original 13 controls followed by the complete reader.
Each joint sample runs the same controls and reader together.

| Measurement | Separate | Joint |
| --- | ---: | ---: |
| Median summed child wall time | 13.92 s | 7.95 s |
| Median maximum child peak RSS | 114.27 MiB | 128.95 MiB |

Wall time fell by about 43% for this component, with about 14.67 MiB more peak
child RSS. The separate RSS figure is the larger child peak, not their sum.
Neither RSS figure includes the storage controller or total system memory.
The twelve added controller checks took 0.78 seconds in a separate single
sample; that cost is additional to the joint replay, so it is not free. These
finite local measurements are not a whole-CI speedup or a production budget.

All four samples preserved the original successor report: 2,623 bytes, SHA-256
`b1a515963b0ff197359772f1b4f3a4ce5842616c0a9c744f904910c10d0f9e6c`.
A separate default regression executed all 27 original controls and retained
the original 2,076-byte report with SHA-256
`dc189500670563c4b51c4cc4fb809eee622fc47357ac45b869fc5e615e45c80d`.
Those report identities use the qualified base revision
`834d551fc285bb2ec0cc7617e0164caa0023eadf` as the caller label; they do not qualify
the new working implementation as that revision. The working runner and added
test source digests were retained separately with actual exits and complete
stdout/stderr. CI must qualify the new revision on Linux, macOS and Windows.

No node process, signing, fixture dispatch, new resource evidence, trust input
or state-value acceptance is introduced. Existing genesis, native measurement,
consumer integration, independent review and production gates remain separate.
