# Cloudbox deploy transport

This action sends a release manifest over an app-specific forced SSH key. The
server descriptor and helper authorize the app, image and operation. The client
validates an app identifier (`[a-z0-9][a-z0-9-]{0,62}`); adding an approved app does
not require editing a client allowlist. No remote command or helper path is sent.

The registry token only enters SSH stdin, never argv or the manifest. Host keys
must be pinned. Temporary private keys and known_hosts files are removed on exit.

The result file is written before failing the step for a valid gateway refusal.
Only public error codes, a safe checkpoint reference and allowlisted evidence
fields are retained. Raw stderr and unknown response fields are not printed or
uploaded. Success requires `ok: true`, `status: verified`, zero SSH exit status and
the exact requested release identity/digest. This preserves the release document
used by Blog and Meeting's post-deploy publication jobs.
The reusable workflow exposes `result_artifact` with a run/attempt-specific name.
Consumers download that output, so retrying a failed rollout keeps earlier
failure evidence and cannot collide with an immutable artifact from another attempt.

A timeout, disconnect, malformed result or conflicting SSH/result status records
`runtime_state: unknown` and `automatic_retry_safe: false`. This is not proof of
rollback or of an unchanged host. Inspect the server's current release/checkpoint
before deciding whether to retry the original manifest. The transport waits at
most 50 minutes; its reusable workflow allows 55 minutes to retain evidence.

The common action expects the single-image gateway result contract. GameDex HQ
uses the same input envelope but keeps its native four-image gateway and result
adapter in its own repository. Do not replace that adapter with this action.

Run `python3 -m unittest actions/cloudbox-deploy/test_send.py -v` from the repository
root. Publish the action commit first, then pin that SHA in the reusable workflow;
publish that workflow commit before updating callers. Never replace pins with
`main` to work around this publication order.
