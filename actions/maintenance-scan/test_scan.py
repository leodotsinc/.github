import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import unittest
s=importlib.util.spec_from_file_location('scan',Path(__file__).with_name('scan.py'))
scan=importlib.util.module_from_spec(s);s.loader.exec_module(scan)
class ScanTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,9,21,tzinfo=timezone.utc)
        self.image='sha256:'+'a'*64
        self.report={'SchemaVersion':2,'Metadata':{'ImageID':self.image},'Results':[{'Packages':[{'Name':'synthetic'}]}]}
        self.db={'UpdatedAt':self.now.isoformat()}
    def test_known_packages_and_fresh_database(self):
        self.assertEqual(scan.evaluate(self.report,self.db,self.now,self.image)['status'],'passed')
    def test_unknown_not_clean(self):
        for results in ([],None,[{}]):
            self.report['Results']=results
            with self.assertRaises(ValueError):scan.evaluate(self.report,self.db,self.now,self.image)
    def test_stale_db_and_different_image_refused(self):
        self.db['UpdatedAt']='2026-09-01T00:00:00Z'
        with self.assertRaises(ValueError):scan.evaluate(self.report,self.db,self.now,self.image)
        with self.assertRaises(ValueError):scan.evaluate(self.report,self.db,self.now,'sha256:'+'b'*64)
    def test_unknown_high_and_critical_block(self):
        for severity in ('HIGH','CRITICAL','UNKNOWN','unrecognized'):
            self.report['Results'][0]['Vulnerabilities']=[{'Severity':severity}]
            self.assertEqual(scan.evaluate(self.report,self.db,self.now,self.image,'strict')['status'],'blocked')
            self.assertEqual(scan.evaluate(self.report,self.db,self.now,self.image)['status'],'warning')
    def test_advisory_preserves_findings_and_marks_warning(self):
        for severity in ('HIGH','CRITICAL','UNKNOWN','unrecognized'):
            with self.subTest(severity=severity):
                self.report['Results'][0]['Vulnerabilities']=[{'VulnerabilityID':'CVE-test','PkgName':'fixture','InstalledVersion':'1.0','Severity':severity}]
                result=scan.evaluate(self.report,self.db,self.now,self.image,'advisory')
                self.assertEqual(result['status'],'warning')
                self.assertEqual(result['policy'],'advisory')
                self.assertEqual(result['findings'][0]['VulnerabilityID'],'CVE-test')
                self.assertEqual(result['counts']['UNKNOWN' if severity=='unrecognized' else severity],1)
    def test_advisory_still_rejects_unknown_scan_or_policy(self):
        with self.assertRaises(ValueError):
            scan.evaluate(self.report,{'UpdatedAt':'2026-09-01T00:00:00Z'},self.now,self.image,'advisory')
        with self.assertRaises(ValueError):
            scan.evaluate(self.report,self.db,self.now,'sha256:'+'b'*64,'advisory')
        with self.assertRaises(ValueError):
            scan.evaluate({'SchemaVersion':1},self.db,self.now,self.image,'advisory')
        with self.assertRaises(ValueError):
            scan.evaluate(self.report,self.db,self.now,self.image,'unknown')
if __name__=='__main__':unittest.main()
