#!/usr/bin/env python3
"""Send a release through an app-specific forced SSH command.

The registry token is read only from the environment and sent as the first
stdin line. It is never added to argv, the release JSON, or a file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


ALLOWED_APPS = {"pluggy-mcp", "blog", "meeting-ai", "gamedex-hq"}


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\x00" in value:
        raise SystemExit(f"missing or invalid environment variable: {name}")
    return value


def load_release(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise SystemExit("release manifest must be a JSON object")
    forbidden = {"token", "password", "secret", "private_key"}
    if forbidden.intersection(value):
        raise SystemExit("release manifest contains a forbidden secret field")
    return value


def main() -> None:
    app = required("CLOUDBOX_APP_ID")
    if app not in ALLOWED_APPS:
        raise SystemExit("application is not allowlisted")

    release = load_release(Path(required("CLOUDBOX_RELEASE_FILE")))
    token = required("CLOUDBOX_REGISTRY_TOKEN")
    if "\n" in token or "\r" in token:
        raise SystemExit("registry token must be one line")

    envelope = {
        "schema_version": 1,
        "app": app,
        "action": "deploy",
        "registry_username": required("CLOUDBOX_REGISTRY_USERNAME"),
        "release": release,
    }
    payload = token.encode() + b"\n" + json.dumps(
        envelope, separators=(",", ":"), sort_keys=True
    ).encode() + b"\n"

    host = required("CLOUDBOX_VPS_HOST")
    port = required("CLOUDBOX_SSH_PORT")
    user = required("CLOUDBOX_DEPLOY_USER")
    if not port.isdigit():
        raise SystemExit("SSH port must be numeric")

    with tempfile.TemporaryDirectory(prefix="cloudbox-ssh-") as temp:
        ssh_dir = Path(temp)
        ssh_dir.chmod(stat.S_IRWXU)
        key = ssh_dir / "deploy_key"
        known_hosts = ssh_dir / "known_hosts"
        key.write_text(required("CLOUDBOX_DEPLOY_KEY").rstrip() + "\n", encoding="utf-8")
        known_hosts.write_text(required("CLOUDBOX_KNOWN_HOSTS").rstrip() + "\n", encoding="utf-8")
        key.chmod(stat.S_IRUSR | stat.S_IWUSR)
        known_hosts.chmod(stat.S_IRUSR | stat.S_IWUSR)

        command = [
            shutil.which("ssh") or "ssh",
            "-T",
            "-i", str(key),
            "-p", port,
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "ClearAllForwardings=yes",
            f"{user}@{host}",
        ]
        completed = subprocess.run(command, input=payload, capture_output=True, check=False)

    stdout = completed.stdout.decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(f"deploy gateway failed ({completed.returncode}): {stderr[-1000:]}")
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise SystemExit("deploy gateway did not return JSON") from error
    if not isinstance(result, dict) or result.get("app") != app:
        raise SystemExit("deploy gateway returned an invalid result")
    Path(required("CLOUDBOX_RESULT_FILE")).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"app": app, "status": result.get("status", "unknown")}, sort_keys=True))


if __name__ == "__main__":
    main()
