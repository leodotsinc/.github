#!/usr/bin/env python3
"""Fail-closed Trivy wrapper. No AI, secrets scan, advisory waiver or silent skip."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
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
    updated = datetime.fromisoformat(metadata['UpdatedAt'].replace('Z', '+00:00'))
    if updated.tzinfo is None or not timedelta(0) <= observed - updated <= timedelta(hours=24):
        raise ValueError('VULNERABILITY_DATABASE_STALE')
    results = report.get('Results')
    if not isinstance(results, list) or not results or not any(r.get('Packages') for r in results):
        raise ValueError('PACKAGE_COVERAGE_UNKNOWN')
    counts = {s: 0 for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')}
    for result in results:
        for vulnerability in result.get('Vulnerabilities') or []:
            counts[vulnerability.get('Severity', 'UNKNOWN') if vulnerability.get('Severity') in counts else 'UNKNOWN'] += 1
    return {'schema_version': 1, 'image': expected, 'observed_at': observed.isoformat(),
            'database_updated_at': updated.isoformat(), 'counts': counts,
            'status': 'blocked' if counts['CRITICAL'] or counts['HIGH'] or counts['UNKNOWN'] else 'passed',
            'packages': sum(len(r.get('Packages') or []) for r in results),
            'official_advisories_checked': False,
            'boundary': 'Image vulnerability scan only; upstream advisories, other build stages and rollout require separate evidence.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--trivy', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = args.output / 'trivy-image.json'
    config = args.output / 'empty-trivy.yaml'; config.write_text('{}\n')
    status = {'status': 'unknown', 'image': args.image, 'observed_at': datetime.now(timezone.utc).isoformat()}
    try:
        if not re.fullmatch(r'(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[a-f0-9]{64}', args.image):
            raise ValueError('IMMUTABLE_IMAGE_REQUIRED')
        command = [args.trivy, 'image', '--config', str(config), '--cache-dir', str(args.cache),
                   '--scanners', 'vuln', '--list-all-pkgs', '--ignorefile', '/dev/null',
                   '--ignore-unfixed=false', '--format', 'json', '--timeout', '5m',
                   '--output', str(report), args.image]
        subprocess.run(command, check=True, timeout=360, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        status = evaluate(json.loads(report.read_text()),
                          json.loads((args.cache / 'db/metadata.json').read_text()),
                          datetime.now(timezone.utc), args.image)
        status['report_sha256'] = hashlib.sha256(report.read_bytes()).hexdigest()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        status['reason'] = 'SCANNER_OR_COVERAGE_UNAVAILABLE'
    (args.output / 'security.json').write_text(json.dumps(status, indent=2) + '\n')
    print(json.dumps(status))
    return 0 if status['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
