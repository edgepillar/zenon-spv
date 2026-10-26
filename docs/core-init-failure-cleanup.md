# Experimental cleanup after failed core Init

The current experimental runtime closes its selected real ledger, cache and
consensus stores after two deliberately induced Init failures. The same store
paths then reopen successfully with LevelDB's ErrorIfMissing option. This adds
bounded evidence for the existing runtime; it selects no additional runtime
patch and does not establish arbitrary initialization recovery.

The experiment uses digitalSloth/go-zenon at
9c71ae82fc983e16f914ae085d4034030c8ebe3b, original tree
d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6, with the existing experimental runtime
tree d0d1116e23cae298d4e8f4bd604d5894ec07bebb. Three build-tagged probe files
extend the preceding build to 487 files. The complete build tree is
ac36d70bbaeefc705efd7ef63fd9085c9efa691b.

## Two real-manager conditions

Each case uses a fresh keyless core, a new empty private directory and the
selected source's embedded unsigned genesis. The fault is applied to an actual
manager or filesystem path. Init's return value is never replaced by a facade.
No core Start, Node wrapper, peer server, RPC listener, wallet or signing work
is selected.

| Condition | Before and after failed Init | After Stop |
| --- | --- | --- |
| The real ledger manager is closed before Init | Ledger unavailable; cache and consensus still open; tree unavailable | All three handles closed; tree unavailable |
| A regular file occupies the state-tree directory path | Ledger, cache and consensus remain open; tree unavailable | All three handles closed; tree unavailable |

The first Init returns the selected ledger-unavailable error. For the second,
the pinned LevelDB storage implementation returns a formatted not-directory
error without wrapping a syscall error. The privacy-preserving probe therefore
records its non-specific `other-error` class. This is a real non-nil Init error;
the report does not infer a syscall error class from its text. The fault file's
bytes, SHA-256 and identity remain unchanged.

Each Stop and subsequent sequential Stop returns nil without a panic. Direct
reads on the original consensus handle return LevelDB's closed error; the real
ledger and cache managers have no live handle. Fresh opens of the existing nom,
cache and consensus databases all succeed and close. ErrorIfMissing prevents
these probes from succeeding by creating an empty database at a wrong path.

The native probe emits observations only. The separate Python checker selects
the expected case, strict field types, handle states, reopen results, marker
identity and refusal scope. An OBSERVED status alone is insufficient.

## Retained failure and source binding

The initial qualification controller expected a syscall-class not-directory
error for the second condition. Its assertion failed, and its original task
remains FAILURE. All six supervised commands had already completed with actual
exit zero: build, binary capture, module information, two native cases and
module verification. The failure was in the caller's error-class expectation.

A separate read-only reconciliation checked the pinned LevelDB error path,
the original complete streams, all 487 initial and final source entries, the
binary digest and 30 linked module inputs against the source go.sum and their
retained archive H1 values. It then applied the documented non-specific error
contract. No native command, build or dependency transport was repeated, and
the original failure was not rewritten as success. The portable recording and
checker explicitly preserve that initial FAILURE outcome.

The [preparer](../tools/gen-state-root-vectors/prepare_core_init_failure.py),
[recording](../tools/gen-state-root-vectors/testdata/native-core-init-failure.json)
and [checker](../tools/gen-state-root-vectors/check_core_init_failure.py)
bind the source maps, native binary, actual command completion and complete
output bytes. The public preparer's source map reproduces the actual build.
Its plan consults no recording and executes nothing.

```sh
python -I -B tools/gen-state-root-vectors/prepare_core_init_failure.py plan \
  --workspace NEW_OWNED_WORKSPACE --go PINNED_GO
python -I -B tools/gen-state-root-vectors/check_core_init_failure_test.py -v
python -I -B tools/gen-state-root-vectors/check_core_init_failure.py
```

## Work and remaining limits

There is one ordinary Go 1.25.14 darwin/arm64 build with CGO enabled and two
fresh native processes. Existing verified source and dependency inputs are
reused. There is no additional race build, new external dependency transport
or repetition of the unchanged native regression graph. Earlier race and
regression results retain their own source bindings.

Native work requires the approved owned task manager, a 10 GiB free-space floor
plus allocations and reservations, a 2 GiB expected allocation and a 4 GiB task
quota. The final workspace inventory measured 337,600,593 logical bytes; this
is neither a measured peak nor a physical APFS allocation or reclaim claim.
Protected streams, binaries, source maps and unexpected-case inputs are retained
separately. Only declared generated namespaces were removed after durable child
completion and process-group checks; the owned task has no remaining scratch.

CI checks the recording on Linux, macOS Intel and Windows. These portable
readers execute no reference backend and do not demonstrate native execution on
those platforms. The experiment does not qualify arbitrary manager panics,
other Init failures, concurrent lifecycle calls, full-node restart, power loss,
representative R1 resources, authenticated activation or accepted state values.
Profile agreement, independent review and authenticated distribution remain
separate roadmap gates.
