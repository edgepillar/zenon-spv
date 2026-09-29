# State writer ownership

Stateful verification commands and `watch` take an exclusive OS advisory lock
before loading their state file. A second cooperating writer fails immediately
with operational exit 70. It does not wait, verify against a stale snapshot,
make watch RPC requests, or replace state. JSON verification reports identify
startup contention as `error.stage: "state_lock"`, with a null overall outcome,
no result rows, and `persistence: "not_attempted"`.

The lock covers the entire load/verify/save operation, or the watch loop's
lifetime. It is released before JSON report delivery, on command errors, and
when the OS closes the process's handles after normal exit or termination.
There is no PID timeout or stale-lock deletion procedure.

This enforces the existing single-writer precondition among cooperating
processes. Previously, a watch process could load height 4006, a concurrent
verification could save height 4009, and the watch's later caught-up save
could replace that file with its old height-4006 snapshot. Atomic rename alone
does not prevent this lost update.

## Paths and companion files

For a state path such as `trusted-state.json`, the lock lives in the persistent
companion `trusted-state.json.lock`. New Unix lock files use mode `0600`.
The lock file carries no state or PID record and is not truncated, rewritten,
or removed when ownership is released. Existing companion contents and inode
identity are preserved. An unlocked companion left after a crash is reusable.

**Do not delete or replace the companion file while a writer may be running.**
Otherwise a new process could lock a different inode at the same name. Protect
the containing directory and keep state paths and parent directories stable.
Parent symlinks are resolved for the lock namespace so ordinary parent aliases
cannot bypass ownership. Stateful writers refuse final state/lock symlinks,
directories, and other nonregular files. State filenames ending in `.lock`
(case insensitive) are reserved, preventing one writer from replacing another
writer's companion as its own state payload.

Windows additionally refuses final names with trailing dots/spaces, colons,
or tildes, and reserved device names. This excludes alternate data streams
and DOS short-name aliases whose appended companion path could identify a
different lock namespace.
The device-name rule covers names before an extension, such as `COM1.json`
and `NUL.backup.json`, even on Windows versions that permit these as files.
This deliberately keeps the restriction consistent across hosts; see the
[Windows naming guidance](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions).

The parent directory must already exist. A missing state file can still be
initialized by a successful verification, but a missing parent or unavailable
lock fails before state loading. In particular, a nonexistent parent now
produces a setup error rather than an accepted verification followed by a save
failure. Invalid state, rejected/refused evidence, or later persistence errors
may leave an unlocked companion file; they do not create accepted state.

`--retained-only` queries take no writer lock and create no companion. They
read one trusted local snapshot and never save it. They can run while a writer
is active, subject to the existing filesystem replacement and provenance
boundaries. They make no claim to observe the newest tip.

## Application and platform boundaries

`syncer.Loop.Run` holds the same lock, including with a custom persistence
adapter. An adapter must still honor its documented state/path contract.
The low-level `VerifiedState.Save` and `SaveHeaderState` functions keep their
existing caller-managed ownership precondition. Embedders implementing a
read/modify/save operation must hold `statelock.Acquire(path)` for its entire
duration, not just for the final save.

The implemented backends use `flock` on Linux/macOS and `LockFileEx` on Windows.
Other platforms fail stateful writer startup instead of silently omitting
coordination; ephemeral verification and retained-only queries remain
available. Tests exercise process exclusion, normal exit, forced termination,
parent aliases, unsafe paths, and lock-file preservation. CI runs the full suite
on native Linux, macOS, and Windows runners, including the compiled CLI writer
regression. Linux also runs the race detector and lint. Cross-compilation alone
does not establish runtime or filesystem behavior. A passing native job covers
its hosted runner environment, not arbitrary network filesystems or storage
hardware; tests requiring unavailable symlink privileges report a skip.

Normal release explicitly unlocks before closing the handle. Windows can
delay OS cleanup after termination, so a brief contention error after a
process exits is still possible; never remove the companion to force access.
See Microsoft's [LockFileEx lifetime guidance](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex#remarks).

Locks are advisory. Older binaries, direct saves without ownership, arbitrary
filesystem writers, and tampering with the directory can bypass this protocol.
Filesystem locking semantics must support the selected OS primitive. This
does not authenticate state provenance, prevent rollback by an external writer,
or change the existing [save/durability boundary](watch-persistence.md).

If releasing a lock reports an error, a verification command returns exit 70
at `state_lock`; it may already have accepted evidence or saved state. Watch
also reports release errors. No release or output failure rolls back a
completed save.
