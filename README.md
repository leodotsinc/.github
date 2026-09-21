
The deploy transport accepts an optional `maintenance_artifact` from the same
workflow run (default file `maintenance-context.json`). The action's optional
`maintenance-file` adds a closed `maintenance` identity envelope only for
`pluggy-mcp` or `blog`: exact baseline, PR head/tree, merged commit, policy, monthly window,
and evidence/release run. The context is capped at 16 KiB, checked against the
release manifest and sent through the existing SSH stdin envelope. It contains
no credentials, commands, paths or authorization booleans. The protected host
still decides qualification, freshness, locks, backups and permission to mutate;
transport validation is not that decision. Without the optional artifact, all
existing release callers retain their current protocol. The job token stays in
the existing ephemeral stdin credential line and is never put in the context.

Blog additionally requires `control_sha256`, the exact control configuration hash.
It preserves separate identities for the installed baseline, trusted producer,
reviewed head, merged release, source CI run and release run. Only the protected
host can accept the pinned control-only baseline-to-producer difference and prove
the reviewed and released trees match. Pluggy retains its original same-producer
baseline and same-run evidence contract. This extension enables no service by itself.

This adoption belongs to [cloudbox-infra PR #11](https://github.com/leodots/cloudbox-infra/pull/11).
