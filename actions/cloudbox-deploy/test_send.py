import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("cloudbox_send", Path(__file__).with_name("send.py"))
send = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(send)


class TransportTests(unittest.TestCase):
    def test_release_rejects_secret_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.json"
            path.write_text(json.dumps({"token": "bad"}), encoding="utf-8")
            with self.assertRaises(SystemExit):
                send.load_release(path)

    @mock.patch.object(send.subprocess, "run")
    def test_token_only_enters_stdin(self, run):
        run.return_value = mock.Mock(returncode=0, stdout=b'{"app":"pluggy-mcp","status":"ok"}\n', stderr=b"")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release.json"
            result = root / "result.json"
            release.write_text('{"digest":"sha256:' + "a" * 64 + '"}\n', encoding="utf-8")
            env = {
                "CLOUDBOX_APP_ID": "pluggy-mcp",
                "CLOUDBOX_RELEASE_FILE": str(release),
                "CLOUDBOX_VPS_HOST": "example.invalid",
                "CLOUDBOX_SSH_PORT": "22",
                "CLOUDBOX_DEPLOY_USER": "deploy",
                "CLOUDBOX_DEPLOY_KEY": "PRIVATE",
                "CLOUDBOX_KNOWN_HOSTS": "HOSTKEY",
                "CLOUDBOX_REGISTRY_TOKEN": "TOKEN_VALUE",
                "CLOUDBOX_REGISTRY_USERNAME": "github-actions[bot]",
                "CLOUDBOX_RESULT_FILE": str(result),
            }
            with mock.patch.dict(send.os.environ, env, clear=True):
                send.main()
            args = run.call_args.args[0]
            stdin = run.call_args.kwargs["input"]
            self.assertNotIn("TOKEN_VALUE", " ".join(args))
            self.assertTrue(stdin.startswith(b"TOKEN_VALUE\n"))
            envelope = json.loads(stdin.split(b"\n", 2)[1])
            self.assertNotIn("TOKEN_VALUE", json.dumps(envelope))
            self.assertEqual(json.loads(result.read_text())["status"], "ok")


if __name__ == "__main__":
    unittest.main()
