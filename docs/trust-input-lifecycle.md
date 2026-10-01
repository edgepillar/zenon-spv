# Trust-input lifecycle

Input validation and matching fingerprints prevent configuration mistakes;
neither authenticates the inputs. The [operator pilot](operator-pilot.md)
requires explicit anchor/profile/schedule, retention/depth selection, and the
reviewed context pin throughout initialization, restart and proof queries.

## Record origins privately

For each input, preserve exact bytes, a SHA-256 digest, acquisition method,
source identity, review date, covered network/heights, and the operator's reason
for trusting it. Record dependencies: the profile's exact anchor, schedule
chain and coverage, and the source/binary that created saved state. Keep peer
URLs, credentials, paths, free-form source notes and raw diagnostics private.
Digest agreement identifies bytes; it is not independent authentication.

Anchor acceptance must be established independently of the peer supplying
candidate history. A collector-exported checkpoint is an observation until
that external trust decision exists. Profiles attest incoming momentum version
rules; do not copy a spork height without its preceding-frontier semantics.
Schedules attest per-height timestamp/producer triples; RPC agreement alone
does not prove elections. Saved windows require protected local provenance,
including rollback/substitution protection outside this verifier.

## Routine restart

Use the same files, binary record, explicit K/W and saved context pin. Do not
regenerate a pin automatically from whatever files happen to be present.
Inspect the state and required coverage before another bounded watch step.
Profile expiry or missing schedule coverage must remain REFUSED/setup failure;
never recover by removing a profile, schedule, retention option or context pin.
State revalidation covers all stored headers before any resizing.

## Controlled renewal

1. Stop the active writer cleanly and wait for lock release. Preserve the
   old state, inputs, context, source/binary records and complete outcomes in
   protected storage. Never remove or replace a live companion lock file.
2. Establish provenance for replacement inputs. Compare network/anchor and
   all overlapping schedule triples against the old reviewed selection.
   Investigate disagreements; a new filename or valid JSON is not approval.
3. For a schedule extension under the same anchor/profile, preserve the
   existing retained slots and cover all planned new heights. Review the new
   `inspect-config` context and pin. `inspect-state` with those settings must
   reauthorize the entire saved window before the next bounded watch step.
4. An anchor or profile change, including profile coverage extension or its
   source label, is incompatible with existing state. Build a separate state
   from an independently trusted anchor with the new profile and schedule;
   verify the required history again. Do not edit persisted profile fields or
   clear state in place to bypass a mismatch. Keep the old state available
   for its original query range and audit record.
5. A K/W change requires reviewing its new context and effective query range.
   Explicit K can resize retained availability; increasing it does not restore
   old headers. A smaller K is applied only after full saved-window checks.
6. Record the transition's old/new identities, observed overlap, outcomes and
   limits. Resume with one bounded `watch --once`, then inspect persisted state.
   Keep verification, save success and report delivery distinct. A failure
   after rename can make bytes visible despite uncertain durability; reconcile
   actual state before retrying, rather than inferring success from a partial log.

There is no automatic trust renewal, rollback guarantee, profile migration,
or canonical-chain handoff in this procedure. A separately trusted anchor does
not prove continuity with an old evicted history. Preserve that remaining
external assumption explicitly; overlapping internally consistent headers are
useful observations, not independent finality evidence.
