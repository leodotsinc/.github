#!/usr/bin/env python3
"""Retain npm audit findings as warnings; reject unusable audit evidence."""
import argparse
import json
from pathlib import Path
import subprocess

SEVERITIES = ('info', 'low', 'moderate', 'high', 'critical')


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('NPM_AUDIT_DUPLICATE_KEY')
            value[key] = item
        return value
    def invalid(_):
        raise ValueError('NPM_AUDIT_NONFINITE_JSON')
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError('NPM_AUDIT_REPORT_TOO_LARGE')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def validate(report, returncode):
    if returncode not in (0, 1) or not isinstance(report, dict) or 'error' in report:
        raise ValueError('NPM_AUDIT_TECHNICAL_FAILURE')
    if report.get('auditReportVersion') != 2:
        raise ValueError('NPM_AUDIT_SCHEMA_UNKNOWN')
    findings = report.get('vulnerabilities')
    metadata = report.get('metadata')
    if not isinstance(metadata, dict):
        raise ValueError('NPM_AUDIT_COVERAGE_UNKNOWN')
    counts = metadata.get('vulnerabilities')
    if not isinstance(findings, dict) or not isinstance(counts, dict):
        raise ValueError('NPM_AUDIT_COVERAGE_UNKNOWN')
    observed = dict.fromkeys(SEVERITIES, 0)
    for name, value in findings.items():
        if not isinstance(value, dict) or value.get('name') != name or value.get('severity') not in observed:
            raise ValueError('NPM_AUDIT_FINDING_INVALID')
        if not isinstance(value.get('via'), list) or not value['via'] or not isinstance(value.get('nodes'), list) or not value['nodes']:
            raise ValueError('NPM_AUDIT_FINDING_INVALID')
        observed[value['severity']] += 1
    expected = {**observed, 'total': len(findings)}
    if set(counts) != set(expected) or any(type(v) is not int or v < 0 for v in counts.values()) or counts != expected:
        raise ValueError('NPM_AUDIT_COUNTS_INVALID')
    # npm uses exit 1 for findings at/above the explicitly requested high level.
    if returncode != int(bool(observed['high'] or observed['critical'])):
        raise ValueError('NPM_AUDIT_EXIT_MISMATCH')
    dependencies = metadata.get('dependencies')
    if not isinstance(dependencies, dict) or type(dependencies.get('total')) is not int or dependencies['total'] <= 0:
        raise ValueError('NPM_AUDIT_COVERAGE_UNKNOWN')
    return {'schema_version': 1, 'policy': 'advisory', 'status': 'warning' if findings else 'passed', 'counts': counts}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(['npm', 'audit', '--package-lock-only', '--audit-level=high', '--json', '--registry=https://registry.npmjs.org'], stdout=subprocess.PIPE, check=False, timeout=180)
    (root / 'npm-audit.json').write_bytes(result.stdout)
    try:
        report = decode(result.stdout)
        summary = validate(report, result.returncode)
    except (ValueError, TypeError, KeyError) as error:
        print('NPM_AUDIT_UNUSABLE: ' + str(error))
        return 1
    (root / 'npm-audit-summary.json').write_text(json.dumps(summary, sort_keys=True) + '\n')
    if summary['status'] == 'warning':
        print('::warning title=npm vulnerability findings accepted by advisory policy::' + json.dumps(summary['counts'], sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
