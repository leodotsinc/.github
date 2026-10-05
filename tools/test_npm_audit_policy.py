import copy
import unittest
from npm_audit_policy import decode, validate


class AuditPolicyTests(unittest.TestCase):
    def report(self, severity=None):
        counts = dict.fromkeys(('info', 'low', 'moderate', 'high', 'critical'), 0)
        findings = {}
        if severity:
            counts[severity] = 1
            findings['package'] = {'name': 'package', 'severity': severity, 'via': [{'source': 1, 'name': 'package', 'dependency': 'package', 'title': 'test advisory', 'url': 'https://github.com/advisories/test', 'range': '<=1', 'severity': severity}], 'nodes': ['node_modules/package']}
        counts['total'] = len(findings)
        return {'auditReportVersion': 2, 'vulnerabilities': findings, 'metadata': {'vulnerabilities': counts, 'dependencies': {'total': 1}}}

    def test_valid_findings_remain_warnings(self):
        for severity in ('info', 'low', 'moderate', 'high', 'critical'):
            report = self.report(severity)
            original = copy.deepcopy(report)
            result = validate(report, int(severity in ('high', 'critical')))
            self.assertEqual(result['status'], 'warning')
            self.assertEqual(result['counts'], report['metadata']['vulnerabilities'])
            self.assertEqual(report, original)
        self.assertEqual(validate(self.report(), 0)['status'], 'passed')

    def test_technical_errors_and_inconsistent_reports_block(self):
        cases = [(self.report('high'), 2), (self.report(), 1), (self.report('high'), 0), ({'error': {'code': 'ENETWORK'}}, 1)]
        for field, value in [('auditReportVersion', 1), ('vulnerabilities', []), ('metadata', {}), ('metadata', None)]:
            report = self.report('high'); report[field] = value; cases.append((report, 1))
        report = self.report('high'); report['metadata']['vulnerabilities']['high'] = True; cases.append((report, 1))
        report = self.report('high'); report['metadata']['vulnerabilities']['total'] = 2; cases.append((report, 1))
        report = self.report('high'); report['vulnerabilities']['package']['nodes'] = []; cases.append((report, 1))
        report = self.report('high'); report['vulnerabilities']['package']['nodes'] = [None]; cases.append((report, 1))
        report = self.report('high'); report['vulnerabilities']['package']['via'] = [None]; cases.append((report, 1))
        for report, code in cases:
            with self.subTest(report=report, code=code), self.assertRaises(ValueError):
                validate(report, code)

    def test_malformed_json_blocks(self):
        for raw in (b'{', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode(raw)
