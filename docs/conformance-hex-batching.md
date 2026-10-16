# Bounded complete-map hex validation

The explicit translated research recipe previously called `str.translate` for
each builtin key and value. Profiling the complete opened-file resource checker
found 9,503,342 such calls across 1,637 target validations. Its expected document
was already cached; another document or graph cache would not remove these
repeated field translations.

The same recipe now aggregates eligible fields for one translation per map.
Every callback still checks the complete prospective map. The reference producer,
recorded corpora, original checker programs and their source-input manifests
remain unchanged. This changes qualification cost, not proof acceptance.

## Admission and refusal order

Limit type/range validation, entry count and the complete hex-character count
still precede encoding checks. Only an exact builtin dictionary with 32 through
4,096 entries and at most 1,048,576 hex characters is considered for batching.
The translation table must be the ordinary exact dictionary that removes the
16 lowercase hexadecimal code points.

The earlier map count is not reused as an allocation bound. Reference-compatible
length/limit hooks can replace values after that count. Immediately before
joining, the optimizer checks the complete size of the collected exact-string
fields again. If it exceeds the hard cap, the prior pointwise path runs without
joining. This separate allocation guard does not repeat target-limit callbacks
or change their original refusal order and results.

Each eligible field must be an exact builtin string, have even length and carry
the ASCII flag. Two odd fields therefore cannot cancel when concatenated.
Non-ASCII text refuses before aggregation. The aggregate translation still
rejects uppercase, whitespace, NUL and every other non-hex ASCII character.
Empty fields retain their original meaning.

Non-builtin dictionaries or fields, smaller/larger maps, inputs above the hard
batch cap and changed translation tables use the previous pointwise path.
Fallback does not consume a non-builtin iterator or call its length/translation
hook during batch admission. Original error types, lookup order and short-circuit
behavior remain required. The exclusive serial caller and stable-checkout
requirements of the selected recipe are unchanged.

The field list borrows at most 8,192 string references. ASCII aggregation adds at
most 1 MiB of string payload; a translation result can add up to another 1 MiB,
plus Python object/list overhead. These are additional temporary allocations,
not a whole-process memory limit. No map identity cache, incremental counter,
observed-result key, cross-process cache or disk cache is introduced. There is
no new download, ZIP, extracted tree or persistent benchmark workspace.

## Validation and reproduction

```sh
python -I -B tools/gen-state-root-vectors/project_target_hex_batch_test.py -v
python -I -B tools/gen-state-root-vectors/project_target_hex_test.py -v
python -I -B tools/gen-state-root-vectors/run_target_hex.py \
  --program check_patch_file_resources.py --mode translated \
  --source-revision "$SOURCE_REVISION"
```

The new controls cover 2,610 finite ASCII/Unicode and field-boundary cases,
batch/byte limits, odd fields whose total is even, first/middle/last corruption,
reused map identities, non-builtin mapping/string/limit traces, custom type hooks
and changed translation tables. They compare standard-table behavior with the
unchanged character-iteration oracle. Separate fallback controls retain the
prior translation-table behavior. Two further controls cover post-count growth
from a limit lookup and a self-replacing length hook, including unchanged callback
traces and refusal results. The original seam controls and all 22 complete
selected checker/control programs remain required in CI.

For timing comparisons, use the same complete command in two isolated, fixed
checkouts: baseline `64589e3fac7e2a285f1f44a22c63c48f8a07a255` and the reviewed
candidate. Keep the Python version, machine and workload fixed. Alternate the
baseline and candidate across three fresh processes each; retain every actual
exit, both output streams, source pins and sample without retries or filtering.
The original checker report must be byte-identical. Its separate current
execution recipe must bind each checkout's actual optimizer bytes. Do not
replace the original recorded producer pins with the candidate's pins.

One local macOS ARM64 / Python 3.9.6 comparison retained these six observations
without retries or sample filtering:

| Selected optimizer | Complete checker seconds, in execution order | Median seconds |
| --- | --- | ---: |
| Previous pointwise translation | 2.615154, 2.746473, 2.542932 | 2.615154 |
| Bounded batching with the final allocation guard | 2.045449, 2.201453, 2.064422 | 2.064422 |

Baseline and candidate alternated in fresh child workers. This timing includes
module imports, identical preparation of the pinned previous function and the
complete existing checker main, including output formatting. It excludes
interpreter launch and task-manager capture overhead. All six original checker
reports have SHA-256
`f3c0ad3d598d0aeefa950e65c40d78420b5744d4fd36b9c4aca64609195030c5`.
The approximately 21% median decrease applies only to this bounded observation.

The tradeoff is additional temporary memory. Separate one-call `tracemalloc`
observations on 32-entry maps at the 1 MiB character ceiling reported 1,050,371
bytes for the prior path and 2,100,086 bytes for batching, for both the selected
valid and invalid workloads. Inputs and module imports preceded tracing. These
Python allocation observations exclude native allocations and are distinct from
the complete child process's high-water RSS. They do not establish a production
memory budget or a general memory reduction.

Use managed task scratch and bounded output capture for new qualification work.
Retain small reports and explicit object references; avoid repackaging source or
artifact trees. Interpreter launch, module import, checker execution and capture
overhead are different timing scopes and must be stated separately. Local elapsed
observations do not establish a native CI speedup or a production resource budget.

This research optimization changes no native verifier, trusted-state format,
header policy or state-value acceptance. Agreed commitment/profile semantics,
authenticated activation/header binding, independent consumer qualification,
review and authenticated distribution remain separate roadmap gates.
