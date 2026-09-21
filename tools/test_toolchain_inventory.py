import base64
import copy
import json
from pathlib import Path
import unittest

import toolchain_inventory as inventory


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {'name': 'synthetic-tools', 'version': '1.0.0', 'private': True,
                         'devDependencies': {'renovate': '44.104.2'}}
        self.lock = {'lockfileVersion': 3, 'packages': {'': {'devDependencies': self.manifest['devDependencies']},
            'node_modules/renovate': {'version': '44.104.2', 'resolved': 'https://registry.npmjs.org/renovate/-/renovate-44.104.2.tgz',
                                      'integrity': 'sha512-' + base64.b64encode(b'a' * 64).decode()}}}
        self.sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'serialNumber': 'variable',
            'metadata': {'timestamp': 'variable', 'component': {'name': 'checkout-directory', 'version': '1.0.0', 'bom-ref': 'root'}},
            'components': [{'name': 'renovate', 'version': '44.104.2', 'bom-ref': 'renovate',
                            'hashes': [{'alg': 'SHA-512', 'content': (b'a' * 64).hex()}]}],
            'dependencies': [{'ref': 'root', 'dependsOn': ['renovate']}, {'ref': 'renovate', 'dependsOn': []}]}

    def generate(self):
        return inventory.canonical_sbom(self.manifest, self.lock, self.sbom, json.dumps(self.lock).encode())

    def test_npm_volatile_fields_do_not_change_reproducible_inventory(self):
        first = self.generate()
        self.sbom['serialNumber'] = 'other'; self.sbom['metadata']['timestamp'] = 'later'
        self.sbom['metadata']['component']['name'] = 'different-directory'
        self.assertEqual(first, self.generate())
        self.assertEqual('synthetic-tools', json.loads(first)['metadata']['component']['name'])

    def test_forged_or_incomplete_inventory_refuses(self):
        for change in ('hash', 'missing', 'version', 'dependency'):
            original = copy.deepcopy(self.sbom)
            if change == 'hash': self.sbom['components'][0]['hashes'][0]['content'] = '00' * 64
            if change == 'missing': self.sbom['components'] = []
            if change == 'version': self.sbom['components'][0]['version'] = '999.0.0'
            if change == 'dependency': self.sbom['dependencies'][0]['dependsOn'] = ['absent']
            with self.subTest(change=change), self.assertRaises(ValueError): self.generate()
            self.sbom = original

    def test_unknown_registry_hooks_or_manifest_drift_refuse(self):
        for change in ('registry', 'integrity', 'version', 'scripts'):
            original, manifest = copy.deepcopy(self.lock), copy.deepcopy(self.manifest)
            if change == 'registry': self.lock['packages']['node_modules/renovate']['resolved'] = 'https://example.invalid/a.tgz'
            if change == 'integrity': self.lock['packages']['node_modules/renovate']['integrity'] = 'sha512-AAAA'
            if change == 'version': self.manifest['devDependencies']['renovate'] = '44.104.3'
            if change == 'scripts': self.manifest['scripts'] = {'postinstall': 'untrusted'}
            with self.subTest(change=change), self.assertRaises(ValueError): self.generate()
            self.lock, self.manifest = original, manifest

    def test_real_lock_and_workflow_preserve_readonly_bounded_no_model_path(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / 'package.json').read_text())
        lock = json.loads((root / 'package-lock.json').read_text())
        self.assertGreater(len(inventory.locked_components(manifest, lock)), 500)
        workflow = (root / '.github/workflows/maintenance-check.yml').read_text()
        for expected in ('npm ci --ignore-scripts', 'npm sbom --package-lock-only', 'deny-network.cjs',
                         'npm audit --package-lock-only --audit-level=high', 'retention-days: 7',
                         'timeout-minutes: 10', 'contents: read', 'env -i PATH='):
            self.assertIn(expected, workflow)
        self.assertNotIn('contents: write', workflow)
        self.assertNotIn('npx ', workflow)
        self.assertIn('npm', json.loads((root / 'renovate.json').read_text())['enabledManagers'])


if __name__ == '__main__':
    unittest.main()
