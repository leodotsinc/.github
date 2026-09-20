import importlib.util
import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("cloudbox_send", Path(__file__).with_name("send.py"))
send = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(send)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.manifest = {
            "service": "pluggy-mcp", "git_sha": "b" * 40,
            "image": "ghcr.io/leodots/pluggy-mcp@sha256:" + "a" * 64,
            "deployment": {"status": "built", "deployed_at": None,
                           "verified_at": None, "observed_image": None},
        }
        self.release = self.root / "release.json"
        self.release.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.result = self.root / "result.json"
        self.env = {
            "CLOUDBOX_APP_ID": "pluggy-mcp", "CLOUDBOX_RELEASE_FILE": str(self.release),
            "CLOUDBOX_VPS_HOST": "example.invalid", "CLOUDBOX_SSH_PORT": "22",
            "CLOUDBOX_DEPLOY_USER": "deploy", "CLOUDBOX_DEPLOY_KEY": "PRIVATE",
            "CLOUDBOX_KNOWN_HOSTS": "HOSTKEY", "CLOUDBOX_REGISTRY_TOKEN": "TOKEN_VALUE",
            "CLOUDBOX_REGISTRY_USERNAME": "github-actions[bot]",
            "CLOUDBOX_RESULT_FILE": str(self.result),
        }
        self.success = {"ok": True, "status": "verified", "release": copy.deepcopy(self.manifest)}
        self.success["release"]["deployment"] = {
            "status": "verified", "deployed_at": "2026-09-19T01:02:03.123456Z",
            "verified_at": "2026-09-19T01:02:04.123456Z", "observed_image": self.manifest["image"],
        }

    def execute(self, value=None, code=0, raw=None, exception=None, expect_error=None):
        output = io.StringIO()
        completed = mock.Mock(returncode=code,
                              stdout=raw if raw is not None else json.dumps(value).encode(),
                              stderr=b"UNCONTROLLED PRIVATE SECRET TOKEN_VALUE\n")
        with mock.patch.object(send.subprocess, "run", return_value=completed,
                               side_effect=exception) as run, \
                mock.patch.dict(send.os.environ, self.env, clear=True), \
                contextlib.redirect_stdout(output):
            if expect_error:
                with self.assertRaisesRegex(SystemExit, expect_error):
                    send.main()
            else:
                send.main()
        self.assertNotIn("TOKEN_VALUE", output.getvalue())
        self.assertNotIn("UNCONTROLLED", output.getvalue())
        if self.result.exists():
            self.assertNotIn("TOKEN_VALUE", self.result.read_text())
            self.assertNotIn("UNCONTROLLED", self.result.read_text())
        return run

    def evidence(self):
        return json.loads(self.result.read_text())

    def test_release_rejects_nested_secret_fields_and_duplicate_keys(self):
        for value in ({"token": "bad"}, {"build": {"Password": "bad"}}, {"files": [{"secret": "bad"}]}):
            self.release.write_text(json.dumps(value))
            with self.assertRaises(SystemExit):
                send.load_release(self.release)
        self.release.write_text('{"image":"a","image":"b"}')
        with self.assertRaises(ValueError):
            send.load_release(self.release)

    def test_token_only_enters_stdin_and_temporary_credentials_are_removed(self):
        run = self.execute(self.success)
        args = run.call_args.args[0]
        stdin = run.call_args.kwargs["input"]
        self.assertNotIn("TOKEN_VALUE", " ".join(args))
        self.assertTrue(stdin.startswith(b"TOKEN_VALUE\n"))
        envelope = json.loads(stdin.split(b"\n", 2)[1])
        self.assertNotIn("TOKEN_VALUE", json.dumps(envelope))
        self.assertEqual(args[-1], "deploy@example.invalid")
        self.assertFalse(Path(args[args.index("-i") + 1]).exists())
        self.assertEqual(run.call_args.kwargs["timeout"], send.SSH_TIMEOUT)
        self.assertEqual(self.evidence()["status"], "verified")
        self.assertEqual(self.evidence()["release"], self.success["release"])

    def test_new_app_uses_same_transport_without_client_allowlist(self):
        self.env["CLOUDBOX_APP_ID"] = "new-worker"
        run = self.execute(self.success)
        self.assertEqual(json.loads(run.call_args.kwargs["input"].split(b"\n")[1])["app"], "new-worker")
        self.assertEqual(self.evidence()["app"], "new-worker")

    def test_invalid_app_ids_never_reach_ssh(self):
        for app in ("../blog", "blog;id", "Blog", "-oProxyCommand=id", "a" * 64):
            self.env["CLOUDBOX_APP_ID"] = app
            run = self.execute(expect_error="invalid application id")
            run.assert_not_called()

    def test_nonzero_gateway_failure_retains_public_error_before_failing(self):
        self.execute({"ok": False, "error": "ROLLOUT_FAILED_PREVIOUS_RUNTIME_VERIFIED",
                      "checkpoint": "/srv/blog/checkpoints/20260919", "reason": "UNCONTROLLED"},
                     code=2, expect_error="ROLLOUT_FAILED")
        self.assertEqual(self.evidence()["error"], "ROLLOUT_FAILED_PREVIOUS_RUNTIME_VERIFIED")
        self.assertEqual(self.evidence()["checkpoint"], "/srv/blog/checkpoints/20260919")
        self.assertEqual(self.evidence()["ssh_exit_code"], 2)
        self.assertNotIn("reason", self.evidence())

    def test_zero_exit_does_not_override_declared_failure(self):
        self.execute({"ok": False, "error": "WRONG_RELEASE_SOURCE"}, expect_error="WRONG_RELEASE_SOURCE")
        self.assertFalse(self.evidence()["ok"])

    def test_host_checkpoint_is_retained_but_traversal_is_not(self):
        for checkpoint, expected in (("/root/infra-changes/blog-20260919T010203", True),
                                     ("/root/infra-changes/../secrets", False),
                                     ("/srv/./secrets", False), ("/etc/passwd", False)):
            self.execute({"ok": False, "error": "ROLLOUT_FAILED", "checkpoint": checkpoint},
                         code=2, expect_error="ROLLOUT_FAILED")
            self.assertEqual("checkpoint" in self.evidence(), expected)

    def test_bootstrap_refusal_is_structured_without_free_form_reason(self):
        self.execute({"ok": False, "status": "needs_bootstrap", "reason": "UNCONTROLLED"},
                     code=2, expect_error="NEEDS_BOOTSTRAP")
        self.assertEqual(self.evidence()["error"], "NEEDS_BOOTSTRAP")

    def test_nonzero_success_is_unknown_never_success(self):
        self.execute(self.success, code=255, expect_error="SSH_RESULT_CONFLICT")
        self.assertEqual(self.evidence()["runtime_state"], "unknown")

    def test_malformed_or_injected_results_do_not_persist_raw_output(self):
        values = [b"not json UNCONTROLLED", b'{"ok":true,"ok":false}', b"[1]", b"x" * 65537,
                  b'{"ok":false,"error":"TOKEN_VALUE"}', b'{"ok":false,"error":"bad message"}',
                  b'{"ok":false,"error":"DENIED","app":"other"}',
                  b'{"ok":true,"status":"ready"}', b'{"status":"verified"}']
        for raw in values:
            with self.subTest(raw=raw[:50]):
                self.execute(raw=raw, code=2, expect_error="INVALID_GATEWAY_RESULT")
                self.assertEqual(self.evidence()["status"], "unknown")

    def test_wrong_release_or_digest_does_not_claim_verified(self):
        for field, value in (("git_sha", "c" * 40), ("image", "wrong"), ("secret", "private")):
            candidate = copy.deepcopy(self.success)
            candidate["release"][field] = value
            self.execute(candidate, expect_error="INVALID_GATEWAY_RESULT")
        candidate = copy.deepcopy(self.success)
        candidate["release"]["deployment"]["observed_image"] = "wrong"
        self.execute(candidate, expect_error="INVALID_GATEWAY_RESULT")

    def test_timeout_and_launch_error_are_unknown_without_retry_claim(self):
        for exception, code in ((subprocess.TimeoutExpired("ssh", 3000, output=b"TOKEN_VALUE"), "SSH_TIMEOUT"),
                                (OSError("TOKEN_VALUE"), "SSH_UNAVAILABLE")):
            self.execute(exception=exception, expect_error=code)
            self.assertEqual(self.evidence()["runtime_state"], "unknown")
            self.assertFalse(self.evidence()["automatic_retry_safe"])

    def test_invalid_or_reversed_timestamps_fail_closed(self):
        for verified_at in ("2026-19-19T01:02:04Z", "2026-09-19T01:02:01Z", "not a date"):
            candidate = copy.deepcopy(self.success)
            candidate["release"]["deployment"]["verified_at"] = verified_at
            self.execute(candidate, expect_error="INVALID_GATEWAY_RESULT")


if __name__ == "__main__":
    unittest.main()
