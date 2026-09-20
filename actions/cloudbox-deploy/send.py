#!/usr/bin/env python3
"""Send a release through an app-specific forced SSH command.

The registry token is read only from the environment and sent as the first
stdin line. It is never added to argv, the release JSON, or a file.
"""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


APP_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,90}\Z")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
MAX_OUTPUT = 65536
# Longer than the gateway's bounded login + pull + inspect + helper execution.
SSH_TIMEOUT = 3000


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def contains_secret_field(value):
    if isinstance(value, dict):
        return any(key.lower() in {"token", "password", "secret", "private_key"}
                   or contains_secret_field(item) for key, item in value.items())
    return isinstance(value, list) and any(contains_secret_field(item) for item in value)


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\x00" in value:
        raise SystemExit(f"missing or invalid environment variable: {name}")
    return value


def load_release(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise SystemExit("release manifest must be a JSON object")
    if contains_secret_field(value):
        raise SystemExit("release manifest contains a forbidden secret field")
    return value


def sanitized_result(stdout, app, release, token):
    """Accept the host's public result contract; never persist arbitrary output."""
    if len(stdout) > MAX_OUTPUT or token.encode() in stdout:
        raise ValueError("unsafe gateway result")
    value = json.loads(stdout, object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or type(value.get("ok")) is not bool
            or value.get("app", app) != app or contains_secret_field(value)):
        raise ValueError("invalid gateway result")
    result = {"app": app, "ok": value["ok"]}
    if value["ok"]:
        verified = value.get("release")
        if not isinstance(verified, dict) or value.get("status") != "verified":
            raise ValueError("deploy did not verify a release")
        identity = {key: item for key, item in verified.items() if key != "deployment"}
        expected = {key: item for key, item in release.items() if key != "deployment"}
        deployment = verified.get("deployment")
        if (identity != expected or not isinstance(deployment, dict)
                or set(deployment) != {"status", "deployed_at", "verified_at", "observed_image"}
                or deployment["status"] != "verified"
                or deployment["observed_image"] != release.get("image")
                or any(not isinstance(deployment[key], str) or not TIMESTAMP.fullmatch(deployment[key])
                       for key in ("deployed_at", "verified_at"))):
            raise ValueError("verified release identity mismatch")
        deployed_at, verified_at = (datetime.fromisoformat(deployment[key].replace("Z", "+00:00"))
                                   for key in ("deployed_at", "verified_at"))
        if verified_at < deployed_at:
            raise ValueError("verification precedes deployment")
        result.update(status="verified", release=verified)
    else:
        error = value.get("error")
        if error is None and value.get("status") == "needs_bootstrap":
            error = "NEEDS_BOOTSTRAP"
        if not isinstance(error, str) or not ERROR_CODE.fullmatch(error):
            raise ValueError("invalid public error code")
        result.update(status="failed", error=error)
    # These are public booleans produced by existing helpers. Unknown fields and
    # free-form reason/log strings never cross into uploaded evidence.
    for key in ("already_verified", "offsite_capture_verified", "restore_verified"):
        if type(value.get(key)) is bool:
            result[key] = value[key]
    checkpoint = value.get("checkpoint")
    if (isinstance(checkpoint, str)
            and re.fullmatch(r"/(?:srv|root/infra-changes)/[A-Za-z0-9_./-]{1,250}", checkpoint)
            and all(segment not in ("", ".", "..") for segment in checkpoint.split("/")[1:])):
        result["checkpoint"] = checkpoint
    return result


def record_result(path, result):
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("app", "ok", "status", "error")
                      if key in result}, sort_keys=True))


def transport_failure(path, app, error, returncode=None):
    result = {"app": app, "ok": False, "status": "unknown", "error": error,
              "runtime_state": "unknown", "automatic_retry_safe": False}
    if returncode is not None:
        result["ssh_exit_code"] = returncode
    record_result(path, result)
    raise SystemExit(error)


def main() -> None:
    app = required("CLOUDBOX_APP_ID")
    if not APP_ID.fullmatch(app):
        raise SystemExit("invalid application id")
    # Authorization lives in the server's descriptor and app-specific forced key.
    # The client accepts identifiers, never a remote command or helper path.
    result_path = Path(required("CLOUDBOX_RESULT_FILE"))

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
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise SystemExit("SSH port must be between 1 and 65535")
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,252}", host)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user)):
        raise SystemExit("invalid SSH host or user")

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
            "-o", "ConnectTimeout=30",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=20",
            f"{user}@{host}",
        ]
        try:
            completed = subprocess.run(command, input=payload, capture_output=True,
                                       check=False, timeout=SSH_TIMEOUT)
        except subprocess.TimeoutExpired:
            transport_failure(result_path, app, "SSH_TIMEOUT_RUNTIME_STATE_UNKNOWN")
        except OSError:
            transport_failure(result_path, app, "SSH_UNAVAILABLE_RUNTIME_STATE_UNKNOWN")
    try:
        result = sanitized_result(completed.stdout, app, release, token)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        transport_failure(result_path, app, "INVALID_GATEWAY_RESULT_RUNTIME_STATE_UNKNOWN",
                          completed.returncode)
    if result["ok"] and completed.returncode != 0:
        transport_failure(result_path, app, "SSH_RESULT_CONFLICT_RUNTIME_STATE_UNKNOWN",
                          completed.returncode)
    result["ssh_exit_code"] = completed.returncode
    record_result(result_path, result)
    if not result["ok"]:
        raise SystemExit(result["error"])


if __name__ == "__main__":
    main()
