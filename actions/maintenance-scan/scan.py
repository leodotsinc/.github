#!/usr/bin/env python3
"""Fail-closed Trivy wrapper. No AI, secrets scan, advisory waiver or silent skip."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import resource
import stat
import tempfile
from urllib.parse import unquote
from pathlib import Path
import re
import subprocess


def evaluate(report, metadata, observed, expected):
    if not isinstance(report, dict) or report.get('SchemaVersion') != 2:
        raise ValueError('SCAN_SCHEMA_UNKNOWN')
    if not re.fullmatch(r'(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[a-f0-9]{64}', expected):
        raise ValueError('IMMUTABLE_IMAGE_REQUIRED')
    image_metadata = report.get('Metadata', {})
    identities = {image_metadata.get('ImageID'), *image_metadata.get('RepoDigests', [])}
    if expected not in identities:
        raise ValueError('SCAN_IMAGE_MISMATCH')
    status = summarize(report, metadata, observed)
    status['image'] = expected
    return status


def summarize(report, metadata, observed):
    updated = datetime.fromisoformat(metadata['UpdatedAt'].replace('Z', '+00:00'))
    if updated.tzinfo is None or not timedelta(0) <= observed - updated <= timedelta(hours=24):
        raise ValueError('VULNERABILITY_DATABASE_STALE')
    results = report.get('Results')
    if not isinstance(results, list) or not results or not any(r.get('Packages') for r in results):
        raise ValueError('PACKAGE_COVERAGE_UNKNOWN')
    findings = []
    counts = {s: 0 for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')}
    for result in results:
        for vulnerability in result.get('Vulnerabilities') or []:
            findings.append({key: str(vulnerability.get(key, ''))[:500] for key in
                             ('VulnerabilityID', 'PkgName', 'InstalledVersion', 'FixedVersion', 'Severity')})
            counts[vulnerability.get('Severity', 'UNKNOWN') if vulnerability.get('Severity') in counts else 'UNKNOWN'] += 1
    return {'schema_version': 1, 'observed_at': observed.isoformat(),
            'database_updated_at': updated.isoformat(), 'counts': counts, 'findings': findings,
            'status': 'blocked' if counts['CRITICAL'] or counts['HIGH'] or counts['UNKNOWN'] else 'passed',
            'packages': sum(len(r.get('Packages') or []) for r in results),
            'official_advisories_checked': False,
            'boundary': 'Image vulnerability scan only; upstream advisories, other build stages and rollout require separate evidence.'}


# Source-lock scanning is deliberately restricted to the two qualified ecosystems.
SBOM_LIMIT = 8 * 1024 * 1024
REPORT_LIMIT = 64 * 1024 * 1024
PACKAGE_LIMIT = 10000


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read_bounded(path, limit):
    # Never accept a pipe/device, symlink, or an unbounded JSON input.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or Path(path).is_symlink() or info.st_size > limit:
            raise ValueError('SCAN_FILE_INVALID')
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('SCAN_FILE_TOO_LARGE')
    return raw


def package_identity(purl, name, version):
    if not all(isinstance(v, str) and v and len(v) <= 500 for v in (purl, name, version)):
        raise ValueError('SBOM_PACKAGE_IDENTITY_UNKNOWN')
    match = re.fullmatch(r'pkg:(pypi|npm)/([^?#]+)@([^@/?#]+)', purl)
    if not match or unquote(match[3]) != version:
        raise ValueError('SBOM_PACKAGE_IDENTITY_UNKNOWN')
    ecosystem, encoded = match[1], unquote(match[2])
    if ecosystem == 'pypi':
        normalized = lambda v: re.sub(r'[-_.]+', '-', v).lower()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name) or normalized(encoded) != normalized(name):
            raise ValueError('SBOM_PACKAGE_IDENTITY_UNKNOWN')
        name = normalized(name)
    elif (not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*', name) or encoded != name):
        raise ValueError('SBOM_PACKAGE_IDENTITY_UNKNOWN')
    return ecosystem, name, version


def sbom_components(sbom):
    if (not isinstance(sbom, dict) or sbom.get('bomFormat') != 'CycloneDX' or
            sbom.get('specVersion') != '1.5' or sbom.get('vulnerabilities')):
        raise ValueError('SBOM_SCHEMA_UNKNOWN')
    rows = sbom.get('components')
    if not isinstance(rows, list) or not 0 < len(rows) <= PACKAGE_LIMIT:
        raise ValueError('SBOM_COVERAGE_UNKNOWN')
    expected, refs = set(), set()
    for row in rows:
        if (not isinstance(row, dict) or row.get('type') != 'library' or row.get('components') or
                not isinstance(row.get('bom-ref'), str) or row['bom-ref'] in refs or row.get('scope') == 'excluded'):
            raise ValueError('SBOM_COMPONENT_UNKNOWN')
        refs.add(row['bom-ref'])
        identity = package_identity(row.get('purl'), row.get('name'), row.get('version'))
        if identity in expected:
            raise ValueError('SBOM_DUPLICATE_COMPONENT')
        expected.add(identity)
    # npm includes the private source root; it is not a registry dependency and
    # Trivy versions can include or omit it. All lock components remain required.
    root = sbom.get('metadata', {}).get('component', {})
    optional_root = set()
    if root.get('purl'):
        optional_root.add(package_identity(root['purl'], root.get('name'), root.get('version')))
    return expected, optional_root


def evaluate_sbom(report, metadata, observed, sbom, digest, snapshot):
    expected, optional_root = sbom_components(sbom)
    if (not isinstance(report, dict) or report.get('SchemaVersion') != 2 or
            report.get('Trivy', {}).get('Version') != '0.74.0' or
            report.get('ArtifactType') != 'cyclonedx' or report.get('ArtifactName') != str(snapshot) or
            not re.fullmatch(r'[a-f0-9]{64}', digest)):
        raise ValueError('SCAN_SBOM_IDENTITY_MISMATCH')
    results = report.get('Results')
    if not isinstance(results, list) or not results or len(results) > PACKAGE_LIMIT:
        raise ValueError('SBOM_COVERAGE_UNKNOWN')
    seen = set()
    findings_count = 0
    for result in results:
        if not isinstance(result, dict) or result.get('Class') != 'lang-pkgs':
            raise ValueError('SBOM_COVERAGE_UNKNOWN')
        packages = result.get('Packages')
        if not isinstance(packages, list) or not packages or len(packages) > PACKAGE_LIMIT:
            raise ValueError('SBOM_COVERAGE_UNKNOWN')
        for package in packages:
            identity = package_identity(package.get('Identifier', {}).get('PURL'), package.get('Name'), package.get('Version'))
            if result.get('Type') != {'pypi': 'python-pkg', 'npm': 'node-pkg'}[identity[0]]:
                raise ValueError('SBOM_ECOSYSTEM_SCAN_UNKNOWN')
            if identity in seen:
                raise ValueError('SBOM_DUPLICATE_PACKAGE')
            seen.add(identity)
        vulns = result.get('Vulnerabilities') or []
        if not isinstance(vulns, list) or not all(isinstance(v, dict) for v in vulns):
            raise ValueError('VULNERABILITY_RESULT_UNKNOWN')
        findings_count += len(vulns)
    if findings_count > PACKAGE_LIMIT or not expected <= seen or not seen <= expected | optional_root:
        raise ValueError('SBOM_PACKAGE_COVERAGE_MISMATCH')
    # Reuse the existing DB freshness/severity gate without presenting a fake
    # image identity to the caller: only the common findings are retained.
    status = summarize(report, metadata, observed)
    status.update({'subject': 'source_sbom', 'sbom_sha256': digest,
                   'components_expected': len(expected), 'components_covered': len(expected),
                   'boundary': 'Source-lock PyPI/npm packages only. No installed-runtime, native bundled library, OS or upstream advisory qualification.'})
    return status


def child_file_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (REPORT_LIMIT, REPORT_LIMIT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--trivy', required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--image')
    target.add_argument('--sbom', type=Path)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.output = args.output.resolve()
    report = args.output / ('trivy-sbom.json' if args.sbom else 'trivy-image.json')
    config = args.output / 'empty-trivy.yaml'; config.write_text('{}\n')
    status = {'status': 'unknown', 'observed_at': datetime.now(timezone.utc).isoformat()}
    if args.image:
        status['image'] = args.image
    else:
        status['subject'] = 'source_sbom'
    try:
        with tempfile.TemporaryDirectory(prefix='cloudbox-scan-', dir=args.output) as private:
            options = {}
            if args.sbom:
                raw = read_bounded(args.sbom, SBOM_LIMIT)
                sbom = decode(raw)
                sbom_components(sbom)
                digest = hashlib.sha256(raw).hexdigest()
                status['sbom_sha256'] = digest
                snapshot = Path(private) / 'source.json'
                snapshot.write_bytes(raw); snapshot.chmod(0o600)
                mode, target = 'sbom', str(snapshot)
                options = {'env': {'PATH': os.defpath, 'HOME': private}, 'preexec_fn': child_file_limit}
            else:
                if not re.fullmatch(r'(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[a-f0-9]{64}', args.image):
                    raise ValueError('IMMUTABLE_IMAGE_REQUIRED')
                mode, target = 'image', args.image
            report.unlink(missing_ok=True)
            command = [args.trivy, mode, '--config', str(config), '--cache-dir', str(args.cache.resolve()),
                       '--disable-telemetry', '--scanners', 'vuln', '--list-all-pkgs', '--ignorefile', '/dev/null',
                       '--ignore-unfixed=false', '--format', 'json', '--timeout', '5m',
                       '--output', str(report), target]
            subprocess.run(command, check=True, timeout=360, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
            report_raw = read_bounded(report, REPORT_LIMIT)
            metadata = decode(read_bounded(args.cache / 'db/metadata.json', 16384))
            observed = datetime.now(timezone.utc)
            if args.sbom:
                if read_bounded(snapshot, SBOM_LIMIT) != raw or read_bounded(args.sbom, SBOM_LIMIT) != raw:
                    raise ValueError('SBOM_CHANGED_DURING_SCAN')
                status = evaluate_sbom(decode(report_raw), metadata, observed, sbom, digest, snapshot)
            else:
                status = evaluate(decode(report_raw), metadata, observed, args.image)
            status['report_sha256'] = hashlib.sha256(report_raw).hexdigest()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        # Never reuse a partially successful verdict after any post-scan error.
        status['status'] = 'unknown'
        status['reason'] = 'SCANNER_OR_COVERAGE_UNAVAILABLE'
    (args.output / 'security.json').write_text(json.dumps(status, indent=2) + '\n')
    print(json.dumps(status))
    return 0 if status['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
