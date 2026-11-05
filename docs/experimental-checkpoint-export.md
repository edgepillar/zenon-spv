# Experimental checkpoint export

The explicit **export-experimental-batch-context-state** command runs the same
three-witness query as query-experimental-batch-context. It emits a checkpoint
only after the configured headers, separate local request, all three proofs,
source rules and typed consumer result pass. Configuration, anchor, finite
producer schedule and both expected context pins remain independently selected.
It performs no RPC or local state-file write.

Standard output contains one existing version-4 experimental checkpoint.
Standard error contains the normal query report with the typed result and a
state_output receipt. Existing inspection/query commands retain their output
channels and read-only behavior. Export uses their same arguments and bounded
provider schema; it is not a general header-only checkpoint command.

## Capture and consume

Use a new caller-owned private directory and unique output names. Select the
configuration, request and both context fingerprints before collecting the
provider document. The shell owns output files; the command does not create,
replace or remove them. This example enables shell no-clobber and stops on an
unsuccessful command:

~~~sh
set -euC
test -n "$PRIVATE"
test -d "$PRIVATE"
test -n "$HEADER_CONTEXT"
test -n "$QUERY_CONTEXT"

zenon-spv export-experimental-batch-context-state \
  --config "$PRIVATE/config.json" \
  --request "$PRIVATE/request.json" \
  --expect-header-context "$HEADER_CONTEXT" \
  --expect-query-context "$QUERY_CONTEXT" \
  "$PRIVATE/provider.json" \
  > "$PRIVATE/header-checkpoint.json" \
  2> "$PRIVATE/export-report.json"

jq -e '.exit_code == 0 and .status == "matched" and .state_output.complete == true' \
  "$PRIVATE/export-report.json"
STATE_SHA=$(jq -er '.state_output.sha256' "$PRIVATE/export-report.json")
~~~

Retain the actual successful exit and complete capture of both channels.
The receipt identifies the emitted bytes with SHA-256 and their exact byte count.
A provider's receipt or a digest computed from an arbitrary file does not supply
trusted local provenance.

Prepare a subsequent provider document with the existing collector's paired
continuation selectors for the saved tip and unchanged anchor. Keep the exact
locally selected query/tip identities. At that tip, the collector omits headers
and still reads the three selected witnesses. Then the existing query can
consume the locally produced checkpoint:

~~~sh
zenon-spv query-experimental-batch-context \
  --config "$PRIVATE/config.json" \
  --request "$PRIVATE/request.json" \
  --expect-header-context "$HEADER_CONTEXT" \
  --expect-query-context "$QUERY_CONTEXT" \
  --trusted-state "$PRIVATE/header-checkpoint.json" \
  --expect-state-sha256 "$STATE_SHA" \
  "$PRIVATE/proof-only-provider.json"
~~~

For successor headers or a changed query, select a new consistent request and
bounded continuation range. A stale/pruned identity or mismatched pin remains a
refusal. Re-export may also select the explicit trusted-state pair; it never
rewrites that input file or fabricates an extension for a proof-only query.

## Output and trust boundaries

The checkpoint uses the existing format zenon-experimental-v3-owned-state/v1
and numeric version 4. The 8 MiB encoding cap, retained-header limit and strict
trusted import remain unchanged. Native v1/v2 state readers continue to refuse
this separate format.

The Go WriteCheckpoint method shares the existing Save encoder and substitutes
the fixed label "exported experimental checkpoint" for the informational Source
text. This prevents private operator provenance from entering the exported
artifact. Source labels do not select verification behavior or context identity.
Save preserves its original label and existing file schema. No state handle or
input file is mutated by export.

A short/failed checkpoint write exits 70 with checkpoint_output_incomplete and
no successful state_output receipt. Partial bytes may remain in the caller's
capture. If the checkpoint completes but writing the diagnostic receipt fails,
the command also fails: a parseable checkpoint alone is not successful command
completion. Preserve failed output honestly and use fresh names for a later
attempt.

The existing exit meanings apply before export: 1 rejects evidence/identity,
2 refuses unavailable/absent/unsupported scope, 64 rejects arguments, and 70
reports operational/encoding failure. Those refusals emit no checkpoint.
A requested gateway comparison remains informational; a stored-field mismatch
does not replace the proven historical row or invalidate accepted headers.

Checkpoint provenance remains external. Import rechecks the exact digest,
configured profile/policy/context, retained hashes, signatures, producer policy
and links; it cannot reconstruct evicted ancestry or authenticate its own file
origin. Export supplies no additional canonicality, finality, STF, network
activation or production state-value guarantee. Controlled export/import/CLI
tests do not close selected-network consumer or release acceptance gates.
