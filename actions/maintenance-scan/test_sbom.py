import contextlib
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

s = importlib.util.spec_from_file_location('scan', Path(__file__).with_name('scan.py'))
scan = importlib.util.module_from_spec(s); s.loader.exec_module(scan)


def component(name='packaging', version='26.3', ecosystem='pypi'):
    purl = f'pkg:{ecosystem}/{name.replace("@", "%40")}@{version}'
    return {'type': 'library', 'name': name, 'version': version, 'purl': purl, 'bom-ref': purl}


def document():
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'components': [component(), component('pyyaml', '6.0.3')]}


def report_for(sbom, path):
    return {'SchemaVersion': 2, 'Trivy': {'Version': '0.74.0'}, 'ArtifactType': 'cyclonedx',
            'ArtifactName': str(path), 'Results': [{'Class': 'lang-pkgs', 'Type': 'python-pkg',
            'Packages': [{'Name': c['name'], 'Version': c['version'], 'Identifier': {'PURL': c['purl']}}
                         for c in sbom['components']]}]}


class SbomTests(unittest.TestCase):
    def setUp(self):
        self.sbom = document()
        self.now = datetime(2026, 9, 21, tzinfo=timezone.utc)
        self.db = {'UpdatedAt': self.now.isoformat()}
        self.report = report_for(self.sbom, '/private/source.json')

    def evaluate(self):
        return scan.evaluate_sbom(self.report, self.db, self.now, self.sbom, 'a' * 64, '/private/source.json')

    def test_complete_inventory_has_hash_and_no_fake_image(self):
        result = self.evaluate()
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['components_covered'], 2)
        self.assertEqual(result['sbom_sha256'], 'a' * 64)
        self.assertNotIn('image', result)
        self.assertFalse(result['official_advisories_checked'])

    def test_missing_changed_extra_or_duplicate_packages_refused(self):
        rows = self.report['Results'][0]['Packages']
        cases = [rows[:1], rows + [rows[0]], rows + [{'Name':'absent', 'Version':'1', 'Identifier': {'PURL':'pkg:pypi/absent@1'}}],
                 [dict(rows[0], Version='99'), rows[1]]]
        for packages in cases:
            with self.subTest(packages=packages):
                self.report['Results'][0]['Packages'] = packages
                with self.assertRaises(ValueError): self.evaluate()

    def test_missing_purl_version_and_unsupported_ecosystem_refused(self):
        for key in ('purl', 'version', 'name'):
            sbom = document(); sbom['components'][0].pop(key)
            with self.assertRaises(ValueError): scan.sbom_components(sbom)
        for value in ('pkg:maven/example@1', 'pkg:pypi/packaging@26.3?arch=any'):
            self.sbom['components'][0]['purl'] = value
            with self.assertRaises(ValueError): scan.sbom_components(self.sbom)

    def test_input_duplicate_nested_excluded_and_vex_refused(self):
        for mutate in (lambda x: x['components'].append(x['components'][0]),
                       lambda x: x['components'][0].update(components=[component()]),
                       lambda x: x['components'][0].update(scope='excluded'),
                       lambda x: x.update(vulnerabilities=[{'analysis': {'state': 'not_affected'}}])):
            sbom = document(); mutate(sbom)
            with self.assertRaises(ValueError): scan.sbom_components(sbom)

    def test_pypi_normalization_and_scoped_npm(self):
        row = component('@scope/name', '1.2.3', 'npm')
        self.assertEqual(scan.package_identity(row['purl'], row['name'], row['version']), ('npm', '@scope/name', '1.2.3'))
        self.assertEqual(scan.package_identity('pkg:pypi/some-name@1', 'Some_Name', '1'), ('pypi', 'some-name', '1'))

    def test_optional_root_never_substitutes_dependency(self):
        root = component('private-source', '1.0.0', 'npm')
        self.sbom['metadata'] = {'component': root}
        package = report_for({'components': [root]}, '/private/source.json')['Results'][0]['Packages'][0]
        self.report['Results'].append({'Class': 'lang-pkgs', 'Type': 'node-pkg', 'Packages': [package]})
        self.assertEqual(self.evaluate()['status'], 'passed')
        self.report['Results'][0]['Packages'].pop(0)
        with self.assertRaises(ValueError): self.evaluate()

    def test_stale_future_naive_database_and_report_identity_refused(self):
        for date in (self.now - timedelta(hours=24, seconds=1), self.now + timedelta(seconds=1), self.now.replace(tzinfo=None)):
            self.db['UpdatedAt'] = date.isoformat()
            with self.assertRaises(ValueError): self.evaluate()
        self.db['UpdatedAt'] = self.now.isoformat()
        for key, value in (('ArtifactName', '/swapped.json'), ('ArtifactType', 'container_image'), ('Trivy', {'Version':'unknown'})):
            original = self.report[key]; self.report[key] = value
            with self.assertRaises(ValueError): self.evaluate()
            self.report[key] = original

    def test_unknown_or_mismatched_ecosystem_result_refused(self):
        for kind in ('unknown', 'node-pkg', None):
            self.report['Results'][0]['Type'] = kind
            with self.assertRaises(ValueError): self.evaluate()

    def test_high_critical_and_unknown_block_medium_reported(self):
        for severity in ('HIGH', 'CRITICAL', 'UNKNOWN', 'unrecognized', 'MEDIUM'):
            self.report['Results'][0]['Vulnerabilities'] = [{'Severity': severity}]
            self.assertEqual(self.evaluate()['status'], 'passed' if severity == 'MEDIUM' else 'blocked')

    def test_bounded_files_and_strict_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(ValueError): scan.decode(raw)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'input'; path.write_bytes(b'12345')
            with self.assertRaises(ValueError): scan.read_bounded(path, 4)
            link = Path(tmp)/'link'; link.symlink_to(path)
            with self.assertRaises(OSError): scan.read_bounded(link, 8)
            fifo = Path(tmp)/'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): scan.read_bounded(fifo, 8)

    def run_cli(self, behavior='success'):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'source.json'; source.write_text(json.dumps(document()))
            raw = source.read_bytes(); cache = root/'cache'; (cache/'db').mkdir(parents=True)
            (cache/'db/metadata.json').write_text(json.dumps({'UpdatedAt':datetime.now(timezone.utc).isoformat()}))
            out = root/'out'; out.mkdir()
            (out/'trivy-sbom.json').write_text('{}')  # a previous result must never be trusted
            argv = ['scan.py', '--trivy', '/verified/trivy', '--sbom', str(source), '--cache', str(cache), '--output', str(out)]
            calls = []
            def runner(command, env):
                kwargs = {"env": env}
                calls.append((command, kwargs))
                self.assertFalse((out/'trivy-sbom.json').exists())
                self.assertEqual(command[1], 'sbom')
                self.assertEqual(set(kwargs['env']), {'PATH','HOME'})
                self.assertNotIn('MODEL_API_KEY', kwargs['env'])
                target = Path(command[-1]); self.assertEqual(target.read_bytes(), raw)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                if behavior == 'timeout': raise subprocess.TimeoutExpired(command, 360)
                if behavior == 'missing': return b''
                report = report_for(document(), target)
                if behavior == 'incomplete': report['Results'][0]['Packages'].pop()
                if behavior == 'mutate-input': source.write_text('{}')
                if behavior == 'mutate-snapshot': target.write_text('{}')
                return json.dumps(report).encode()
            with patch('sys.argv', argv), patch.dict(os.environ, {'MODEL_API_KEY':'synthetic-secret','TRIVY_IGNORE_UNFIXED':'true'}), patch.object(scan, 'bounded_scan', side_effect=runner), contextlib.redirect_stdout(io.StringIO()) as stdout:
                result = scan.main()
            evidence = json.loads((out/'security.json').read_text())
            self.assertEqual(len(calls), 1)
            self.assertNotIn('synthetic-secret', stdout.getvalue())
            self.assertFalse(list(out.glob('cloudbox-scan-*')))
            self.assertEqual(evidence['sbom_sha256'], hashlib.sha256(raw).hexdigest())
            return result, evidence

    def test_cli_nominal_scrubs_environment_and_binds_bytes(self):
        code, result = self.run_cli()
        self.assertEqual(code, 0); self.assertEqual(result['status'], 'passed')

    def test_cli_missing_timeout_incomplete_and_drift_never_green(self):
        for behavior in ('missing','timeout','incomplete','mutate-input','mutate-snapshot'):
            with self.subTest(behavior=behavior):
                code, result = self.run_cli(behavior)
                self.assertEqual(code, 1); self.assertEqual(result['status'], 'unknown')

    def test_real_subprocess_output_cap_timeout_exit_and_clean_environment(self):
        clean = {'PATH': os.defpath, 'HOME': '/nonexistent'}
        out = scan.bounded_scan([sys.executable, '-c', 'import os; print(os.environ.get("MODEL_API_KEY","absent"))'], clean, timeout=3)
        self.assertEqual(out.strip(), b'absent')
        with self.assertRaises(ValueError):
            scan.bounded_scan([sys.executable, '-c', 'print("x"*5000)'], clean, timeout=3, limit=100)
        with self.assertRaises(subprocess.TimeoutExpired):
            scan.bounded_scan([sys.executable, '-c', 'import time;time.sleep(10)'], clean, timeout=0.02)
        with self.assertRaises(subprocess.CalledProcessError):
            scan.bounded_scan([sys.executable, '-c', 'raise SystemExit(4)'], clean, timeout=3)

    def test_image_cli_preserves_existing_credential_transport_and_identity_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cache = root/'cache'; (cache/'db').mkdir(parents=True)
            (cache/'db/metadata.json').write_text(json.dumps({'UpdatedAt':datetime.now(timezone.utc).isoformat()}))
            image = 'sha256:' + 'a' * 64
            argv = ['scan.py','--trivy','/verified/trivy','--image',image,'--cache',str(cache),'--output',str(root/'out')]
            def runner(command, **kwargs):
                self.assertEqual(command[1], 'image')
                self.assertNotIn('env', kwargs)  # existing image callers supply ephemeral DOCKER_CONFIG
                Path(command[command.index('--output')+1]).write_text(json.dumps({'SchemaVersion':2,
                    'Metadata':{'ImageID':image}, 'Results':[{'Packages':[{'Name':'synthetic'}]}]}))
            with patch('sys.argv',argv), patch.object(scan.subprocess,'run',side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scan.main(),0)
            status=json.loads((root/'out/security.json').read_text())
            self.assertEqual(status['image'],image); self.assertNotIn('sbom_sha256',status)

    def test_cli_xor_refuses_before_scanner(self):
        for targets in ([], ['--image','sha256:'+'a'*64,'--sbom','input.json']):
            with patch('sys.argv', ['scan.py','--trivy','trivy','--cache','cache','--output','out'] + targets), patch.object(scan.subprocess, 'run') as runner, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): scan.main()
                runner.assert_not_called()


if __name__ == '__main__': unittest.main()
