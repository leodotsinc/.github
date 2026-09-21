
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

### Locked maintenance validator

`package.json` pins the existing Renovate validator; `package-lock.json` records
its complete npm graph and integrity values. Mend's npm manager updates the
manifest and lock together; the existing weekly lock maintenance also discovers
transitive changes. These pull requests retain normal review and CI gates.
Do not reintroduce a floating `npx` download or enable dependency lifecycle hooks.

The hosted `Maintenance contracts` job installs with `npm ci --ignore-scripts`,
validates the preset with network sockets blocked and no inherited credentials,
and generates a CycloneDX source SBOM from the exact lock on every run. The SBOM
is normalized and checked against all locked package hashes, then retained with
official npm advisory results for seven days under the run/attempt identity.
There is no separately committed SBOM requiring another bot or an AI-generated
update. CI fails for high/critical npm advisories or unavailable advisory results.
This does not replace image scans or qualify the deployment executor.

To reproduce after a reviewed manifest edit, use Node 24.14.1 and run
`npm install --package-lock-only --ignore-scripts --no-audit --no-fund`, then the
same CI steps. A mismatch makes `npm ci` fail; CI never edits or commits the lock.
The published Renovate package does not include optional native RE2: the validator
warns that it uses JavaScript RegExp. This preserves the previous CLI limitation;
validation of new custom regex managers requires explicit RE2 qualification.
