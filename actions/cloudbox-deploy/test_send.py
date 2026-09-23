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
            "service": "pluggy-mcp", "git_sha": "b" * 40, "release_version": "0.4.0",
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

    def test_reconciliation_receipt_preserves_only_validated_handshake_fields(self):
        value = {**self.success, "catalog_reconciled": True,
                 "server_info": {"name": "pluggy", "version": "0.4.0", "extra": "UNCONTROLLED"}}
        self.execute(value)
        self.assertEqual(self.evidence()["server_info"], {"name": "pluggy", "version": "0.4.0"})
        self.assertTrue(self.evidence()["catalog_reconciled"])
        for server in ({"name": "other", "version": "0.4.0"}, {"name": "pluggy", "version": "0.3.0"}):
            self.execute({**value, "server_info": server}, expect_error="INVALID_GATEWAY_RESULT")


if __name__ == "__main__":
    unittest.main()


class MaintenanceTransportTests(TransportTests):
    def setUp(self):
        super().setUp()
        self.manifest['build'] = {'id': '1234', 'attempt': 1}
        self.release.write_text(json.dumps(self.manifest))
        self.success['release']['build'] = copy.deepcopy(self.manifest['build'])
        base = copy.deepcopy(self.manifest)
        base['git_sha'] = 'c'*40
        base['deployment'] = copy.deepcopy(self.success['release']['deployment'])
        self.context = {
            'schema_version': 1, 'app': 'pluggy-mcp', 'mode': 'monthly',
            'request_id': '', 'policy_sha256': '1'*64,
            'baseline_receipt_sha256': send.canonical_hash(base),
            'source_pr': {'number': 9, 'base_sha': 'c'*40, 'head_sha': 'd'*40, 'tree_sha': 'e'*40},
            'head_sha': 'd'*40, 'merged_sha': 'b'*40, 'tree_sha': 'e'*40,
            'delta_sha256': '2'*64, 'window': {'start': '2026-10-01T10:00:00-03:00',
            'end': '2026-10-01T12:00:00-03:00', 'timezone': 'America/Sao_Paulo'},
            'expires_at': '2026-10-01T10:59:00-03:00', 'base_manifest': base,
            'producer_commit': 'c'*40, 'evidence_run_id': 1234, 'release_run_id': 1234,
        }
        self.context['request_id'] = send.canonical_hash({k:self.context[k] for k in
            ('app', 'baseline_receipt_sha256', 'head_sha', 'tree_sha')})
        self.context_file = self.root/'maintenance-context.json'
        self.context_file.write_text(json.dumps(self.context))

    def test_optional_context_is_stdin_only_and_matches_release(self):
        self.env['CLOUDBOX_MAINTENANCE_FILE'] = str(self.context_file)
        run = self.execute(self.success)
        payload = run.call_args.kwargs['input']
        envelope = json.loads(payload.split(b'\n', 2)[1])
        self.assertEqual(envelope['maintenance'], self.context)
        self.assertNotIn('TOKEN_VALUE', json.dumps(envelope))
        self.assertNotIn('maintenance', self.evidence())

    def test_absence_preserves_original_envelope(self):
        run = self.execute(self.success)
        self.assertNotIn('maintenance', json.loads(run.call_args.kwargs['input'].split(b'\n')[1]))

    def test_refuses_unknown_fields_cross_identity_urgency_and_malformed_inputs_before_ssh(self):
        changes = [
            ('app', 'blog'), ('mode', 'urgent'), ('schema_version', True),
            ('request_id', '9'*64), ('policy_sha256', 'not-a-hash'),
            ('merged_sha', 'f'*40), ('head_sha', 'f'*40), ('producer_commit', 'f'*40),
            ('evidence_run_id', 999), ('release_run_id', True), ('extra', True),
            ('window', {'start':'2026-10-01T10:00:00', 'end':'2026-10-01T12:00:00', 'timezone':'America/Sao_Paulo'}),
            ('expires_at', '2026-10-01T12:01:00-03:00'),
            ('base_manifest', dict(self.context['base_manifest'], token='forbidden')),
        ]
        for key, value in changes:
            with self.subTest(field=key):
                item = copy.deepcopy(self.context);item[key] = value
                self.context_file.write_text(json.dumps(item))
                with self.assertRaises((ValueError, TypeError)):
                    send.load_maintenance(self.context_file, 'pluggy-mcp', self.manifest)
        self.context_file.write_text(json.dumps(self.context))
        with self.assertRaises(ValueError): send.load_maintenance(self.context_file, 'blog', self.manifest)
        for raw in ('{' + ' '*16384 + '}', '{"schema_version":1,"schema_version":1}', '{"x":NaN}'):
            self.context_file.write_text(raw)
            with self.assertRaises(ValueError): send.load_maintenance(self.context_file, 'pluggy-mcp', self.manifest)

    def test_rejected_context_never_opens_transport(self):
        self.context['mode'] = 'urgent'
        self.context_file.write_text(json.dumps(self.context))
        self.env['CLOUDBOX_MAINTENANCE_FILE'] = str(self.context_file)
        with mock.patch.dict(send.os.environ, self.env, clear=True), mock.patch.object(send.subprocess, 'run') as run:
            with self.assertRaises(ValueError): send.main()
        run.assert_not_called()
        self.assertFalse(self.result.exists())

    def test_blog_keeps_real_baseline_producer_and_source_ci_identities(self):
        context = copy.deepcopy(self.context)
        context.update(app='blog', control_sha256='3'*64, producer_commit='f'*40, evidence_run_id=456)
        context['source_pr']['base_sha'] = context['producer_commit']
        context['base_manifest']['service'] = 'blog'
        context['baseline_receipt_sha256'] = send.canonical_hash(context['base_manifest'])
        context['request_id'] = send.canonical_hash({k:context[k] for k in
            ('app', 'baseline_receipt_sha256', 'head_sha', 'tree_sha')})
        release = {**self.manifest, 'service': 'blog'}
        self.context_file.write_text(json.dumps(context))
        self.assertEqual(send.load_maintenance(self.context_file, 'blog', release), context)
        changes = [('control_sha256', None), ('control_sha256', 'not-a-hash'),
                   ('evidence_run_id', True), ('evidence_run_id', 0),
                   ('source_pr', {**context['source_pr'], 'base_sha': '0'*40}),
                   ('base_manifest', {**context['base_manifest'], 'git_sha': 'invalid'}),
                   ('authorized', True)]
        for key, value in changes:
            item = copy.deepcopy(context)
            if value is None: item.pop(key)
            else: item[key] = value
            self.context_file.write_text(json.dumps(item))
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                send.load_maintenance(self.context_file, 'blog', release)

    def test_blog_control_extension_cannot_relax_pluggy_or_other_apps(self):
        for change in ({'control_sha256': '3'*64}, {'evidence_run_id': 456},
                       {'producer_commit': 'f'*40, 'source_pr': {**self.context['source_pr'], 'base_sha': 'f'*40}}):
            self.context_file.write_text(json.dumps({**self.context, **change}))
            with self.subTest(change=change), self.assertRaises(ValueError):
                send.load_maintenance(self.context_file, 'pluggy-mcp', self.manifest)
        self.context_file.write_text(json.dumps(self.context))
        with self.assertRaises(ValueError):
            send.load_maintenance(self.context_file, 'meeting-ai', self.manifest)


class GenericMaintenanceTransportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = MaintenanceTransportTests('test_absence_preserves_original_envelope')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)

    def configure(self, app='meeting-ai', repository='leodotsinc/meeting-ai'):
        f = self.fixture
        release = copy.deepcopy(f.manifest)
        release.update(application_kind='first_party', service=app, source_repository='https://github.com/'+repository,
                       image='ghcr.io/'+repository+'@sha256:'+'a'*64, build={'id':'1234','attempt':1})
        context = copy.deepcopy(f.context)
        context.update(app=app, infra_commit='9'*40, config_sha256='3'*64, host_contract_sha256='4'*64,
                       source_pr=123, evidence_run_id=5678, producer_commit='f'*40,
                       source_proof={'run_id':5678,'run_attempt':2,'artifact_id':9012,'digest':'sha256:'+'5'*64})
        context['base_manifest'].update(application_kind='first_party', service=app, source_repository=release['source_repository'])
        context['baseline_receipt_sha256'] = send.canonical_hash(context['base_manifest'])
        context['request_id'] = send.canonical_hash({k:context[k] for k in
            ('app','baseline_receipt_sha256','head_sha','tree_sha')})
        f.manifest=release;f.release.write_text(json.dumps(release));f.context_file.write_text(json.dumps(context))
        f.env.update(CLOUDBOX_APP_ID=app,CLOUDBOX_MAINTENANCE_FILE=str(f.context_file),
            GITHUB_REPOSITORY=repository,GITHUB_WORKFLOW_REF=repository+'/.github/workflows/maintenance.yml@refs/heads/main',
            GITHUB_REF='refs/heads/main',GITHUB_SHA='f'*40,GITHUB_WORKFLOW_SHA='f'*40,GITHUB_RUN_ID='1234',GITHUB_RUN_ATTEMPT='1')
        f.success={'ok':True,'status':'verified','release':copy.deepcopy(release)}
        f.success['release']['deployment']=copy.deepcopy(f.context['base_manifest']['deployment'])
        f.success['release']['deployment']['observed_image']=release['image']
        return context

    def test_meeting_and_new_apps_use_same_closed_stdin_protocol_without_client_allowlist(self):
        for app, repo in [('meeting-ai','leodotsinc/meeting-ai'),('new-reviewed-app','leodots/new-reviewed-app')]:
            with self.subTest(app=app):
                context=self.configure(app,repo);f=self.fixture
                run=f.execute(f.success)
                token, body = run.call_args.kwargs['input'].split(b'\n',2)[:2]
                self.assertEqual(token,b'TOKEN_VALUE')
                self.assertEqual(json.loads(body)['maintenance'],context)
                self.assertNotIn('TOKEN_VALUE',str(run.call_args.args))
                self.assertNotIn('TOKEN_VALUE',json.dumps(f.evidence()))
                self.assertNotIn('maintenance',f.evidence())

    def test_third_party_transport_keeps_upstream_revision_separate_from_recipe_commit(self):
        context = self.configure('third-service', 'leodots/cloudbox-infra'); f = self.fixture
        for manifest in (f.manifest, context['base_manifest']):
            manifest.update(application_kind='third_party', git_sha=None, build=None,
                            source_repository='https://github.com/upstream/third-service')
        context['source_proof']['run_id'] = 5679  # Native pipelines may use a separate source proof run.
        context['baseline_receipt_sha256'] = send.canonical_hash(context['base_manifest'])
        context['request_id'] = send.canonical_hash({k: context[k] for k in
            ('app', 'baseline_receipt_sha256', 'head_sha', 'tree_sha')})
        f.context_file.write_text(json.dumps(context))
        with mock.patch.dict(send.os.environ, f.env, clear=True):
            self.assertEqual(send.load_maintenance(f.context_file, 'third-service', f.manifest), context)
            for delta in ({'build': {'id':'1234','attempt':1}}, {'git_sha':'invalid'},
                          {'source_repository':'https://github.com/other/source'}, {'application_kind':'first_party'}):
                with self.subTest(delta=delta), self.assertRaises(ValueError):
                    send.load_maintenance(f.context_file, 'third-service', {**f.manifest, **delta})

    def test_generic_context_authenticates_caller_repository_workflow_source_and_attempt(self):
        self.configure();f=self.fixture
        for key,bad in [('GITHUB_REPOSITORY','leodotsinc/other'),('GITHUB_REPOSITORY','outside/new'),
                        ('GITHUB_WORKFLOW_REF','leodotsinc/meeting-ai/.github/workflows/maintenance.yml@refs/heads/feature'),
                        ('GITHUB_WORKFLOW_REF','leodotsinc/other/.github/workflows/maintenance.yml@refs/heads/main'),
                        ('GITHUB_REF','refs/tags/v1'),('GITHUB_SHA','a'*40),('GITHUB_WORKFLOW_SHA','a'*40),
                        ('GITHUB_RUN_ID','999'),('GITHUB_RUN_ATTEMPT','2')]:
            with self.subTest(key=key,bad=bad),mock.patch.dict(send.os.environ,{**f.env,key:bad},clear=True), \
                 mock.patch.object(send.subprocess,'run') as run:
                with self.assertRaises(ValueError):send.main()
                run.assert_not_called()
        with mock.patch.dict(send.os.environ,{},clear=True):
            with self.assertRaises(ValueError):send.load_maintenance(f.context_file,'meeting-ai',f.manifest)

    def test_generic_context_refuses_identity_drift_controls_and_unbound_source_proof(self):
        original=self.configure();f=self.fixture
        changes=[('app','other'),('mode','urgent'),('source_pr',True),('source_pr',{}),
                 ('config_sha256','bad'),('host_contract_sha256','bad'),('infra_commit','bad'),
                 ('source_proof',dict(original['source_proof'],run_id=0)),
                 ('source_proof',dict(original['source_proof'],run_attempt=True)),
                 ('source_proof',dict(original['source_proof'],digest='sha256:'+'0'*63)),
                 ('source_proof',dict(original['source_proof'],authorized=True)),
                 ('base_manifest',dict(original['base_manifest'],source_repository='https://github.com/leodots/other')),
                 ('request_id','0'*64),('merged_sha','a'*40),('host','example.invalid'),
                 ('command','true'),('helper_path','/bin/true'),('control_sha256','0'*64),('authorized',True)]
        for key,bad in changes:
            f.context_file.write_text(json.dumps({**original,key:bad}))
            with self.subTest(key=key),mock.patch.dict(send.os.environ,f.env,clear=True),mock.patch.object(send.subprocess,'run') as run:
                with self.assertRaises(ValueError):send.main()
                run.assert_not_called()

    def test_release_and_baseline_must_bind_the_same_app_repository_and_built_run(self):
        original=self.configure();f=self.fixture
        for changes in ({'service':'other'},{'source_repository':'https://github.com/leodots/other'},
                        {'git_sha':'a'*40},{'build':{'id':'999','attempt':1}},
                        {'build':{'id':'1234','attempt':True}},{'deployment':{'status':'verified'}}):
            with self.subTest(changes=changes),mock.patch.dict(send.os.environ,f.env,clear=True):
                with self.assertRaises(ValueError):send.load_maintenance(f.context_file,'meeting-ai',{**f.manifest,**changes})
        for changes in ({'deployment':{'status':'built'}},{'service':'other'},{'git_sha':'bad'}):
            changed=copy.deepcopy(original);changed['base_manifest'].update(changes)
            changed['baseline_receipt_sha256']=send.canonical_hash(changed['base_manifest'])
            changed['request_id']=send.canonical_hash({k:changed[k] for k in ('app','baseline_receipt_sha256','head_sha','tree_sha')})
            f.context_file.write_text(json.dumps(changed))
            with self.subTest(changes=changes),mock.patch.dict(send.os.environ,f.env,clear=True):
                with self.assertRaises(ValueError):send.load_maintenance(f.context_file,'meeting-ai',f.manifest)


class WorkflowArtifactTests(unittest.TestCase):
    def test_fixed_artifact_naming_accepts_new_app_but_refuses_paths_and_cross_app_inputs(self):
        workflow=(Path(__file__).resolve().parents[2]/'.github/workflows/deploy.yml').read_text()
        step=workflow.split('      - name: Validate optional maintenance artifact identity\n',1)[1].split('      - name:',1)[0]
        script='\n'.join(line[10:] for line in step.split('        run: |\n',1)[1].splitlines() if line.startswith('          '))
        for app,artifact,file,valid in [('pluggy-mcp','pluggy-maintenance-context','maintenance-context.json',True),
                                      ('blog','blog-maintenance-context','maintenance-context.json',True),
                                      ('meeting-ai','meeting-ai-maintenance-context','maintenance-context.json',True),
                                      ('new-reviewed-app','new-reviewed-app-maintenance-context','maintenance-context.json',True),
                                      ('meeting-ai','blog-maintenance-context','maintenance-context.json',False),
                                      ('../other','../other-maintenance-context','maintenance-context.json',False),
                                      ('meeting-ai','meeting-ai-maintenance-context','../maintenance-context.json',False),
                                      ('x;true','x;true-maintenance-context','maintenance-context.json',False)]:
            with self.subTest(app=app,artifact=artifact,file=file):
                result=send.subprocess.run(['/bin/bash','-c',script],env={'APP_ID':app,'ARTIFACT_NAME':artifact,'ARTIFACT_FILE':file},capture_output=True)
                self.assertEqual(result.returncode==0,valid)
        self.assertIn('actions/cloudbox-deploy@76a15c62a4f019febef9fcee811e6dca6ac7d9a6',workflow)
        self.assertNotIn('github-token:',workflow.split('      - name: Download same-run maintenance context')[1].split('      - name:',1)[0])
