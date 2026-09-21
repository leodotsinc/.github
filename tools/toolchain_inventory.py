#!/usr/bin/env python3
"""Validate the source lock and canonicalize npm's per-run SBOM; no network/code execution."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


def locked_components(manifest, lock):
    if (manifest.get('private') is not True or manifest.get('scripts') or
            set(manifest.get('devDependencies', {})) != {'renovate'} or
            not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', manifest['devDependencies']['renovate']) or
            lock.get('lockfileVersion') != 3 or
            lock.get('packages', {}).get('', {}).get('devDependencies') != manifest['devDependencies']):
        raise ValueError('MANIFEST_LOCK_DRIFT')
    expected = set()
    for path, row in lock['packages'].items():
        if not path:
            continue
        url = urlsplit(row.get('resolved', ''))
        integrity = row.get('integrity', '')
        if (not path.startswith('node_modules/') or row.get('link') or url.scheme != 'https' or
                url.hostname != 'registry.npmjs.org' or url.username or url.password or url.port or
                url.query or url.fragment or not integrity.startswith('sha512-')):
            raise ValueError('UNTRUSTED_LOCK_SOURCE')
        try:
            digest = base64.b64decode(integrity[7:], validate=True)
        except ValueError as error:
            raise ValueError('INVALID_INTEGRITY') from error
        if len(digest) != 64:
            raise ValueError('INVALID_INTEGRITY')
        name = row.get('name', path.rsplit('node_modules/', 1)[-1])
        expected.add((name, row['version'], digest.hex()))
    renovate = lock['packages'].get('node_modules/renovate', {})
    if renovate.get('version') != manifest['devDependencies']['renovate']:
        raise ValueError('RENOVATE_IDENTITY_DRIFT')
    return expected


def canonical_sbom(manifest, lock, raw, lock_bytes):
    expected = locked_components(manifest, lock)
    sbom = copy.deepcopy(raw)
    if sbom.get('bomFormat') != 'CycloneDX' or sbom.get('specVersion') != '1.5':
        raise ValueError('UNEXPECTED_SBOM_FORMAT')
    observed = set()
    refs = set()
    for row in sbom.get('components', []):
        hashes = [h['content'] for h in row.get('hashes', []) if h.get('alg') == 'SHA-512']
        if len(hashes) != 1 or row['bom-ref'] in refs:
            raise ValueError('SBOM_COMPONENT_IDENTITY')
        refs.add(row['bom-ref'])
        observed.add((row['name'], row['version'], hashes[0]))
    if observed != expected:
        raise ValueError('SBOM_LOCK_COMPONENT_DRIFT')
    metadata = sbom['metadata']
    if metadata['component']['version'] != manifest['version']:
        raise ValueError('SBOM_ROOT_DRIFT')
    # npm labels the root with the checkout directory name; this is not identity.
    metadata['component']['name'] = manifest['name']
    sbom.pop('serialNumber', None)
    metadata.pop('timestamp', None)
    metadata.setdefault('properties', []).extend([
        {'name': 'cloudbox:package-lock-sha256', 'value': hashlib.sha256(lock_bytes).hexdigest()},
        {'name': 'cloudbox:scope', 'value': 'Resolved source lock, including dev/platform-optional packages; not an installed-image SBOM or security verdict.'}])
    refs.add(metadata['component']['bom-ref'])
    if {row['ref'] for row in sbom.get('dependencies', [])} != refs:
        raise ValueError('SBOM_DEPENDENCY_GRAPH_INCOMPLETE')
    for row in sbom['dependencies']:
        if not set(row.get('dependsOn', [])) <= refs:
            raise ValueError('SBOM_DEPENDENCY_REFERENCE_UNKNOWN')
        row['dependsOn'] = sorted(row.get('dependsOn', []))
    sbom['components'].sort(key=lambda r: r['bom-ref'])
    sbom['dependencies'].sort(key=lambda r: r['ref'])
    return json.dumps(sbom, sort_keys=True, indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = Path('package-lock.json').read_bytes()
    result = canonical_sbom(json.loads(Path('package.json').read_text()), json.loads(raw),
                            json.loads(args.input.read_text()), raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result)


if __name__ == '__main__':
    main()
