# Read-only devnet resource preflight

This tool records whether a selected Linux environment currently meets a
declared resource envelope for a future owned Zeno devnet experiment. It starts
no container, node, wallet, signer, transaction, VM or deployment. Resource
eligibility supplies no setup authority and does not qualify a real consumer
query, source provenance, producer authorization, canonicality or finality.

The separate workflow runs the controls on Linux, macOS and Windows. Only its
Linux job reads an actual Docker environment. The Linux label is
`ubuntu-24.04`, a full standard hosted VM. The
[GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
advertises 4 CPUs, 16 GB RAM and 14 GB SSD for a public repository. A label does
not guarantee the free space required by this experiment. Standard public
runners are free; [larger runners have separate billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

## Invocation and limits

Run the read-only observation against an explicitly selected existing workspace:

`python -I -B tools/devnet-preflight/preflight.py --workspace <path>`

The defaults select a 10 GiB free-space floor plus an 8 GiB expected allocation,
four available CPU affinities, 12 GiB available memory, an observed empty Docker
engine, Docker 20.10 or newer, Compose 2.20 or newer and cgroup v2. The expected
allocation is a caller-selected budget, not a measured peak or protocol limit.
The floor cannot be lowered below 10 GiB. Other active reservations must be
included in the selected expected allocation before any actual workload.

An observation can complete with `eligible: false`. Exit 0 means the resource
observation completed; it does not authorize or start work. Add
`--require-eligible` to obtain exit 2 when a complete observation is ineligible.
Unknown or incomplete observations return exit 70; invalid arguments return 64.
Each child command has a 10-second deadline and separate 16 KiB stream caps.
Timeouts and output limits stop only the spawned client process. The tool never
stops a daemon or targets another process by name, port or group.

The report contains sanitized hardware numbers, normalized tool versions,
individual checks, source/tool identifiers and actual command exit/capture
outcomes. It omits workspace paths, endpoints and raw command errors. The
optional `--report <path>` exclusively creates a new mode-0600 file; existing
files are refused. Any failed or partial output remains unusable regardless of
whether some JSON bytes exist.

## Qualification boundary

These are observations and necessary preconditions, not disk reservations,
OS-enforced aggregate quotas, executor enforcement or proof that the workload
will fit. An empty engine does not authenticate its ownership. A future runtime
must preserve the chosen floor and reservations, bound its writes and duration,
track only its owned resources and retain failures honestly. Do not delete
unrelated runner software or lower a refused budget to force eligibility.

The workflow uploads one small controls artifact per platform; its Linux
artifact also contains the resource observation. No images, package caches,
source trees, databases or candidate binary archives are added to these
artifacts. The workflow has no service-launch or signing path.

The actual six-service devnet, supported v1/v3 transition, independently
selected anchor/profile/finite schedule/context, same-root three-witness query,
strict ABI result and retained consumer evidence remain separate work. The
existing native v1/v2 path, representative R1 measurements, authenticated
election/fork choice, Bitcoin/Portal and production release gates remain
independent.
