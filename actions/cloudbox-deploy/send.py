#!/usr/bin/env python3
"""Send a release through an app-specific forced SSH command.

The registry token is read only from the environment and sent as the first
stdin line. It is never added to argv, the release JSON, or a file.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
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


MAINTENANCE_KEYS = {
    "schema_version", "app", "mode", "request_id", "policy_sha256",
    "baseline_receipt_sha256", "source_pr", "head_sha", "merged_sha", "tree_sha",
    "delta_sha256", "window", "expires_at", "base_manifest", "producer_commit",
    "evidence_run_id", "release_run_id",
}
GENERIC_MAINTENANCE_KEYS = MAINTENANCE_KEYS | {
    "infra_commit", "config_sha256", "host_contract_sha256", "source_proof",
}
MAX_MAINTENANCE = 16384


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def load_maintenance(path, app, release):
    """Transport a closed identity envelope; only the protected host authorizes it."""
    def require(condition):
        if not condition:
            raise ValueError("invalid maintenance context")

    def sha(value, size=40):
        return isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % size, value)

    def timestamp(value):
        require(isinstance(value, str) and len(value) <= 40)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(parsed.tzinfo is not None)
        return parsed

    require(isinstance(app, str) and APP_ID.fullmatch(app) and path.is_file() and not path.is_symlink())
    with path.open("rb") as stream:
        raw = stream.read(MAX_MAINTENANCE + 1)
    require(len(raw) <= MAX_MAINTENANCE)
    def invalid_constant(_):
        raise ValueError("invalid maintenance context")
    value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if app not in {"pluggy-mcp", "blog"}:
        return generic_maintenance(value, app, release, require, sha, timestamp)
    expected_keys = MAINTENANCE_KEYS | ({"control_sha256"} if app == "blog" else set())
    require(isinstance(value, dict) and set(value) == expected_keys)
    if app == "blog":
        require(sha(value["control_sha256"], 64))
    require(not contains_secret_field(value))
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["app"] == app and value["mode"] == "monthly")
    for key in ("request_id", "policy_sha256", "baseline_receipt_sha256", "delta_sha256"):
        require(sha(value[key], 64))
    for key in ("head_sha", "merged_sha", "tree_sha", "producer_commit"):
        require(sha(value[key]))
    source = value["source_pr"]
    require(isinstance(source, dict) and set(source) == {"number", "base_sha", "head_sha", "tree_sha"})
    require(type(source["number"]) is int and 0 < source["number"] <= 2**53 - 1)
    require(source["base_sha"] == value["producer_commit"] and source["head_sha"] == value["head_sha"]
            and source["tree_sha"] == value["tree_sha"])
    base = value["base_manifest"]
    require(isinstance(base, dict) and base.get("service") == app and sha(base.get("git_sha")))
    # Blog may have a separately pinned control configuration on the producer.
    # The host proves its exact limited delta; transport must retain the real A/B.
    if app == "pluggy-mcp":
        require(base["git_sha"] == value["producer_commit"])
    require(isinstance(base.get("deployment"), dict) and base["deployment"].get("status") == "verified")
    require(canonical_hash(base) == value["baseline_receipt_sha256"])
    require(canonical_hash({"app": app, "baseline_receipt_sha256": value["baseline_receipt_sha256"],
                            "head_sha": value["head_sha"], "tree_sha": value["tree_sha"]}) == value["request_id"])
    require(release.get("service") == app and release.get("git_sha") == value["merged_sha"])
    require(type(value["release_run_id"]) is int and 0 < value["release_run_id"] <= 2**53 - 1
            and type(value["evidence_run_id"]) is int and 0 < value["evidence_run_id"] <= 2**53 - 1)
    if app == "pluggy-mcp":
        require(value["evidence_run_id"] == value["release_run_id"])
    require(str(release.get("build", {}).get("id")) == str(value["release_run_id"]))
    window = value["window"]
    require(isinstance(window, dict) and set(window) == {"start", "end", "timezone"}
            and window["timezone"] == "America/Sao_Paulo")
    require(timestamp(window["start"]) < timestamp(value["expires_at"]) <= timestamp(window["end"]))
    return value


def generic_maintenance(value, app, release, require, sha, timestamp):
    """Identity-only common transport. Registration/authorization is host-owned."""
    require(isinstance(value, dict) and set(value) == GENERIC_MAINTENANCE_KEYS and not contains_secret_field(value))
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and
            value['app'] == app and value['mode'] == 'monthly')
    for key in ('request_id', 'policy_sha256', 'baseline_receipt_sha256', 'delta_sha256', 'config_sha256', 'host_contract_sha256'):
        require(sha(value[key], 64))
    for key in ('infra_commit', 'head_sha', 'merged_sha', 'tree_sha', 'producer_commit'):
        require(sha(value[key]))
    for key in ('source_pr', 'evidence_run_id', 'release_run_id'):
        require(type(value[key]) is int and 0 < value[key] <= 2**53 - 1)
    proof = value['source_proof']
    require(isinstance(proof, dict) and set(proof) == {'run_id', 'run_attempt', 'artifact_id', 'digest'})
    require(all(type(proof[key]) is int and 0 < proof[key] <= 2**53 - 1 for key in ('run_id', 'run_attempt', 'artifact_id')) and
            isinstance(proof['digest'], str) and re.fullmatch(r'sha256:[a-f0-9]{64}', proof['digest']))
    # GitHub supplies these immutable caller identities. Inputs cannot select a
    # repository, workflow branch or remote executable. The host verifies the
    # precise registered workflow/code and the scoped forced key independently.
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    require(re.fullmatch(r'(?:leodots|leodotsinc)/[A-Za-z0-9_.-]+', repository) and
            repository.split('/')[1] not in {'.', '..'})
    caller = os.environ.get('GITHUB_WORKFLOW_REF', '')
    require(re.fullmatch(re.escape(repository) + r'/\.github/workflows/[A-Za-z0-9_-]+\.ya?ml@refs/heads/main', caller))
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main' and
            os.environ.get('GITHUB_SHA') == os.environ.get('GITHUB_WORKFLOW_SHA') == value['producer_commit'] and
            os.environ.get('GITHUB_RUN_ID') == str(value['release_run_id']) and os.environ.get('GITHUB_RUN_ATTEMPT') == '1')
    base = value['base_manifest']
    require(isinstance(base, dict) and base.get('service') == app and
            base.get('source_repository') == release.get('source_repository') and
            isinstance(base.get('deployment'), dict) and base['deployment'].get('status') == 'verified')
    require(canonical_hash(base) == value['baseline_receipt_sha256'])
    require(canonical_hash({key: value[key] for key in ('app', 'baseline_receipt_sha256', 'head_sha', 'tree_sha')}) == value['request_id'])
    require(release.get('service') == app and isinstance(release.get('deployment'), dict) and
            release['deployment'].get('status') == 'built')
    kind = release.get('application_kind')
    require(kind in {'first_party', 'third_party'} and base.get('application_kind') == kind)
    if kind == 'first_party':
        require(sha(base.get('git_sha')) and base.get('source_repository') == 'https://github.com/' + repository and
                release.get('git_sha') == value['merged_sha'] and isinstance(release.get('build'), dict) and
                str(release['build'].get('id')) == str(value['release_run_id']) and
                type(release['build'].get('attempt')) is int and release['build']['attempt'] == 1)
    else:
        # The recipe/CI commit is bound above. An upstream image has its own
        # optional revision and no local build; root registration still checks
        # its source, image origins and qualified data helper independently.
        require(all(v is None or sha(v) for v in (base.get('git_sha'), release.get('git_sha'))) and
                release.get('build') is None and base.get('build') is None and
                isinstance(release.get('source_repository'), str) and
                re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', release['source_repository']))
    window = value['window']
    require(isinstance(window, dict) and set(window) == {'start', 'end', 'timezone'} and
            window['timezone'] == 'America/Sao_Paulo')
    start, end, expiry = timestamp(window['start']), timestamp(window['end']), timestamp(value['expires_at'])
    require(start < expiry <= end and end - start <= timedelta(hours=2))
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
        if "server_info" in value:
            server = value["server_info"]
            if (not isinstance(server, dict) or not isinstance(server.get("name"), str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", server["name"])
                    or server.get("version") != release.get("release_version")
                    or (app == "pluggy-mcp" and server["name"] != "pluggy")):
                raise ValueError("server identity mismatch")
            result["server_info"] = {"name": server["name"], "version": server["version"]}
    else:
        error = value.get("error")
        if error is None and value.get("status") == "needs_bootstrap":
            error = "NEEDS_BOOTSTRAP"
        if not isinstance(error, str) or not ERROR_CODE.fullmatch(error):
            raise ValueError("invalid public error code")
        result.update(status="failed", error=error)
    # These are public booleans produced by existing helpers. Unknown fields and
    # free-form reason/log strings never cross into uploaded evidence.
    for key in ("already_verified", "offsite_capture_verified", "restore_verified", "catalog_reconciled"):
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
    maintenance_file = os.environ.get("CLOUDBOX_MAINTENANCE_FILE", "")
    if maintenance_file:
        envelope["maintenance"] = load_maintenance(Path(maintenance_file), app, release)
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
