
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

### Source SBOM vulnerability gate

`actions/maintenance-scan` accepts exactly one of `image` (existing immutable
image path) or `sbom` (a local CycloneDX 1.5 JSON file). Source SBOMs are limited
to PyPI/npm library components. The caller must first validate the SBOM against
its manifest/lock; the scanner cannot prove that an omitted lock dependency
exists. The shared validator does this with `toolchain_inventory.py`; infra's
Python producer independently checks both qualified wheel resolutions.

The same checksum-pinned Trivy 0.74.0 and database freshness limit of 24 hours
apply (see the opt-in stale window below). The SBOM is copied into a private temporary snapshot, hashed, and checked
again after scanning. Each expected normalized PURL/name/version must appear in
the proper Trivy ecosystem result, including development/transitive packages.
Missing or unknown coverage, input drift, unavailable scanner/database and
malformed output fail closed; high, critical or unknown severity blocks CI.
Only the optional source-root component can be omitted from registry coverage.
Input is capped at 8 MiB/10,000 components, output at 64 MiB/10,000 findings,
and execution at 360 seconds (Trivy's own timeout is five minutes), without
wrapper retries. The SBOM scanner child receives only PATH and a temporary HOME.

The `security.json` receipt records the source SBOM SHA-256 and covered count,
not a fictitious image digest. The shared npm job retains it with the raw scan
and lock-derived SBOM for seven days. Existing pinned image callers remain
unchanged until a separately reviewed pin update. This does not inventory
Python/Node executables, OS packages, native libraries embedded in wheels, or
Trivy itself, and does not replace official advisory review or a runtime scan.
These limits matter because [Trivy documents reduced accuracy for third-party
SBOMs](https://trivy.dev/docs/latest/target/sbom/). PURL mapping is checked against
[the pinned decoder](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/purl/purl.go).

### Opt-in stale database window

By default the database must be at most 24 hours old (`DATABASE_FRESH_HOURS`)
and anything older fails closed, exactly as before. A caller may set
`stale_db_warn_hours` to an integer from 24 to 168 (`STALE_DB_WARN_MAX_HOURS`).
A database older than 24 hours but within that limit is then accepted: the scan
runs and findings are judged by the selected `vulnerability_policy` exactly as
with a fresh database, while a GitHub Actions warning and a step summary note
report the stale age. The receipt of an opted-in caller adds
`database_stale_warn_hours`, `database_stale` and `database_age_hours`; default
receipts are unchanged. A database older than the limit, missing or unparseable
metadata, naive or future timestamps, an invalid limit, or an unwritable step
summary still fail closed with `SCANNER_OR_COVERAGE_UNAVAILABLE`.

Only `cloudbox-infra`'s own source check and this repository's own maintenance
check use this window (72 hours), under the owner's 2026-10-08 approval prompted
by the stalled upstream database
([aquasecurity/trivy-db#698](https://github.com/aquasecurity/trivy-db/issues/698)).
All other callers keep the strict limit; existing SHA-pinned callers are
unaffected until they update.

### Explicit vulnerability advisory mode

The new scanner defaults to `vulnerability_policy: advisory`. HIGH, CRITICAL
or UNKNOWN findings keep the same severity counts, findings, subject identity,
and raw report hash. Findings
then return `status: warning`, `policy: advisory`, a GitHub Actions warning,
and a successful process exit. A clean scan still returns `passed` with the
advisory policy identified. A caller that requires vulnerability gating must
explicitly set `vulnerability_policy: strict`; these findings then return
`blocked` and fail the action. Consumers must accept the distinct warning
receipt; they must not rewrite it as a vulnerability-free pass.

Both modes fail closed on scanner execution errors, stale or missing database,
malformed or incomplete reports, missing package coverage, identity mismatch,
and other validation errors. Existing SHA-pinned callers retain their previous
behavior until they update their pin. The shared maintenance contracts job
explicitly selects advisory for its own source-lock scan. Each application must
review its local receipt validators when adopting the new scanner; updating a
pin alone may be insufficient. Pluggy owns its risk decision and pins its
adopted scanner commit.

The central repository's npm audit uses advisory reporting under the owner's
2026-10-05 approval. `tools/npm_audit_policy.py` retains the complete npm JSON
and writes a separate warning summary. It accepts npm's finding exit only when
the versioned report, package coverage, severity counts and exit status agree.
Network/tool failures, malformed JSON, missing coverage and inconsistent
evidence still fail. The source SBOM Trivy step also selects advisory under the
same approval; its raw report, coverage and warning status remain in artifacts.
