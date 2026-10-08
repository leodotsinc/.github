import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

s = importlib.util.spec_from_file_location('scan', Path(__file__).with_name('scan.py'))
scan = importlib.util.module_from_spec(s); s.loader.exec_module(scan)

IMAGE = 'sha256:' + 'a' * 64
HOUR = timedelta(hours=1)
SECOND = timedelta(seconds=1)


def image_report(severity=None):
    result = {'Packages': [{'Name': 'synthetic'}]}
    if severity:
        result['Vulnerabilities'] = [{'VulnerabilityID': 'CVE-test', 'Severity': severity}]
    return {'SchemaVersion': 2, 'Metadata': {'ImageID': IMAGE}, 'Results': [result]}


class FreshnessBandTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)

    def evaluate(self, age, warn_hours=None, policy='strict', severity=None):
        db = {'UpdatedAt': (self.now - age).isoformat()}
        return scan.evaluate(image_report(severity), db, self.now, IMAGE, policy, warn_hours)

    def test_constants_bound_the_window(self):
        self.assertEqual(scan.DATABASE_FRESH_HOURS, 24)
        self.assertEqual(scan.STALE_DB_WARN_MAX_HOURS, 168)

    def test_default_keeps_strict_limit_and_receipt_shape(self):
        result = self.evaluate(24 * HOUR)
        self.assertEqual(result['status'], 'passed')
        for key in ('database_stale', 'database_stale_warn_hours', 'database_age_hours'):
            self.assertNotIn(key, result)
        with self.assertRaisesRegex(ValueError, 'VULNERABILITY_DATABASE_STALE'):
            self.evaluate(24 * HOUR + SECOND)

    def test_fresh_band_with_opt_in_is_not_stale(self):
        for age in (timedelta(0), 23 * HOUR, 24 * HOUR):
            with self.subTest(age=age):
                result = self.evaluate(age, 72)
                self.assertEqual(result['status'], 'passed')
                self.assertFalse(result['database_stale'])
                self.assertEqual(result['database_stale_warn_hours'], 72)

    def test_stale_band_runs_and_is_flagged(self):
        for age in (24 * HOUR + SECOND, 48 * HOUR, 72 * HOUR):
            with self.subTest(age=age):
                result = self.evaluate(age, 72)
                self.assertEqual(result['status'], 'passed')
                self.assertTrue(result['database_stale'])
                self.assertEqual(result['database_age_hours'], round(age.total_seconds() / 3600, 2))

    def test_stale_band_findings_still_block_exactly_as_before(self):
        for severity in ('HIGH', 'CRITICAL', 'UNKNOWN', 'unrecognized'):
            with self.subTest(severity=severity):
                fresh = self.evaluate(HOUR, None, 'strict', severity)
                stale = self.evaluate(48 * HOUR, 72, 'strict', severity)
                self.assertEqual(fresh['status'], 'blocked')
                self.assertEqual(stale['status'], 'blocked')
                self.assertEqual(stale['counts'], fresh['counts'])
                self.assertEqual(stale['findings'], fresh['findings'])
                # The opt-in never changes the advisory policy verdict either.
                self.assertEqual(self.evaluate(48 * HOUR, 72, 'advisory', severity)['status'], 'warning')
        self.assertEqual(self.evaluate(48 * HOUR, 72, 'strict', 'MEDIUM')['status'], 'passed')

    def test_beyond_limit_future_naive_missing_and_unparseable_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'VULNERABILITY_DATABASE_STALE'):
            self.evaluate(72 * HOUR + SECOND, 72)
        with self.assertRaisesRegex(ValueError, 'VULNERABILITY_DATABASE_STALE'):
            self.evaluate(169 * HOUR, 168)
        with self.assertRaisesRegex(ValueError, 'VULNERABILITY_DATABASE_STALE'):
            self.evaluate(-SECOND, 72)
        for metadata in ({'UpdatedAt': (self.now - 48 * HOUR).replace(tzinfo=None).isoformat()},
                         {}, {'UpdatedAt': 'not-a-date'}, {'UpdatedAt': ''}, {'UpdatedAt': 1}, None, []):
            with self.subTest(metadata=metadata):
                with self.assertRaises((ValueError, KeyError, TypeError, AttributeError)):
                    scan.evaluate(image_report(), metadata, self.now, IMAGE, 'strict', 72)

    def test_invalid_window_values_refused(self):
        for value in ('', '0', '23', '169', '1000', '72.0', ' 72', '72 ', '+72', '-72', '072', 'abc', '٧٢', None, 72):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'STALE_DB_WARN_HOURS_INVALID'):
                    scan.stale_db_warn_hours(value)
        for value in ('24', '72', '168'):
            self.assertEqual(scan.stale_db_warn_hours(value), int(value))
        for value in (23, 169, True, 72.0, '72'):
            with self.subTest(direct=value):
                with self.assertRaisesRegex(ValueError, 'STALE_DB_WARN_HOURS_INVALID'):
                    self.evaluate(HOUR, value)


class FreshnessCliTests(unittest.TestCase):
    def run_cli(self, age, extra=(), severity=None, policy='strict'):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cache = root / 'cache'; (cache / 'db').mkdir(parents=True)
            if age is not None:
                updated = datetime.now(timezone.utc) - age
                (cache / 'db/metadata.json').write_text(json.dumps({'UpdatedAt': updated.isoformat()}))
            summary = root / 'summary.md'; summary.write_text('')
            argv = ['scan.py', '--trivy', '/verified/trivy', '--image', IMAGE, '--cache', str(cache),
                    '--output', str(root / 'out'), '--vulnerability-policy', policy, *extra]
            calls = []
            def runner(command, **kwargs):
                calls.append(command)
                Path(command[command.index('--output') + 1]).write_text(json.dumps(image_report(severity)))
            with patch('sys.argv', argv), patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}), \
                    patch.object(scan.subprocess, 'run', side_effect=runner), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                code = scan.main()
            evidence = json.loads((root / 'out/security.json').read_text())
            return code, evidence, stdout.getvalue(), summary.read_text(), calls

    def test_default_rejects_stale_database_without_warning(self):
        code, evidence, out, summary, _ = self.run_cli(48 * HOUR)
        self.assertEqual((code, evidence['status'], evidence['reason']), (1, 'unknown', 'SCANNER_OR_COVERAGE_UNAVAILABLE'))
        self.assertNotIn('::warning', out); self.assertEqual(summary, '')

    def test_fresh_database_with_opt_in_has_no_warning(self):
        code, evidence, out, summary, _ = self.run_cli(HOUR, ['--stale-db-warn-hours=72'])
        self.assertEqual((code, evidence['status'], evidence['database_stale']), (0, 'passed', False))
        self.assertNotIn('::warning', out); self.assertEqual(summary, '')

    def test_stale_band_passes_with_annotation_and_summary(self):
        code, evidence, out, summary, _ = self.run_cli(48 * HOUR, ['--stale-db-warn-hours=72'])
        self.assertEqual((code, evidence['status'], evidence['database_stale']), (0, 'passed', True))
        self.assertIn('::warning title=Stale vulnerability database accepted::', out)
        self.assertIn('Stale vulnerability database', summary)
        self.assertIn('72h', summary)

    def test_stale_band_findings_still_fail(self):
        code, evidence, out, summary, _ = self.run_cli(48 * HOUR, ['--stale-db-warn-hours=72'], 'CRITICAL')
        self.assertEqual((code, evidence['status']), (1, 'blocked'))
        self.assertIn('::warning title=Stale vulnerability database accepted::', out)

    def test_beyond_limit_and_missing_metadata_fail_closed(self):
        for age in (72 * HOUR + timedelta(minutes=1), None):
            with self.subTest(age=age):
                code, evidence, out, summary, _ = self.run_cli(age, ['--stale-db-warn-hours=72'])
                self.assertEqual((code, evidence['status'], evidence['reason']), (1, 'unknown', 'SCANNER_OR_COVERAGE_UNAVAILABLE'))
                self.assertNotIn('::warning', out)

    def test_invalid_window_fails_closed_before_scanner(self):
        for value in ('23', '169', 'abc', '72.5', '-1'):
            with self.subTest(value=value):
                code, evidence, out, summary, calls = self.run_cli(HOUR, [f'--stale-db-warn-hours={value}'])
                self.assertEqual((code, evidence['status'], evidence['reason']), (1, 'unknown', 'SCANNER_OR_COVERAGE_UNAVAILABLE'))
                self.assertEqual(calls, [])

    def test_unwritable_summary_fails_closed(self):
        with patch.object(scan, 'open', side_effect=OSError('read-only'), create=True):
            code, evidence, out, summary, _ = self.run_cli(48 * HOUR, ['--stale-db-warn-hours=72'])
        self.assertEqual((code, evidence['status']), (1, 'unknown'))


if __name__ == '__main__': unittest.main()
