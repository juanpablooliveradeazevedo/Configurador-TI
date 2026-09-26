import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from desenvolvimento import package_deployments_2b as package
from licensing.contracts import Denied
from test_fleet_2b import Fixture
class PackagingTests(unittest.TestCase):
    def test_four_source_packages_import_and_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            for profile in package.PROFILE_ENTRY:
                path=package.package(profile,tmp)
                with zipfile.ZipFile(path) as z:
                    self.assertIsNone(z.testzip());names=z.namelist()
                    for name in names:self.assertFalse(package.prohibited(profile,name.replace('/','.').removesuffix('.py')))
                    dest=Path(tmp)/profile;z.extractall(dest)
                    manifest=json.loads(z.read('release-manifest.json'));self.assertEqual('2B',manifest['phase_id']);self.assertEqual('INTERNAL',manifest['release_channel'])
                    for row in json.loads(z.read('source-inventory.json'))['files']:self.assertEqual(row['sha256'],hashlib.sha256(z.read(row['path'])).hexdigest())
                if profile=='Technician':continue
                cmd={'Agent':['-m','agent','smoke'],'Backend':['-m','control_plane.fleet_cli','--help'],'Central':['-m','central_web','--help']}[profile]
                out=subprocess.run([sys.executable,*cmd],cwd=dest,capture_output=True,text=True,shell=False,timeout=15)
                self.assertEqual(0,out.returncode,out.stderr)
    def test_packages_repeatable_and_runtime_data_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            first=package.package('Agent',tmp).read_bytes();second=package.package('Agent',tmp).read_bytes();self.assertEqual(first,second)
            with zipfile.ZipFile(package.package('Backend',tmp)) as z:
                self.assertFalse(any(Path(n).suffix in ('.db','.bin','.pem','.key') for n in z.namelist()))
    def test_forbidden_import_fails_closed(self):
        with patch.object(package,'imports',return_value=['control_plane.service']):
            with self.assertRaises(Denied):package.source_files('Agent')
    def test_agent_no_inbound_listener_or_shell(self):
        root=package.ROOT/'agent'
        for p in root.glob('*.py'):
            tree=ast.parse(p.read_text())
            for node in ast.walk(tree):
                if isinstance(node,ast.Call):
                    self.assertNotIn(getattr(node.func,'attr',''),('listen','bind','PopenServer','eval','exec'))
                    for k in node.keywords:
                        if k.arg=='shell':self.assertIsInstance(k.value,ast.Constant);self.assertIs(k.value.value,False)
    def test_central_has_no_repository_import(self):
        for path in package.source_files('Central'):
            self.assertFalse(any(package.prohibited('Central',n) for n in package.imports(path)))
    def test_service_static_least_privilege(self):
        text=(package.ROOT/'agent/windows_service.py').read_text();self.assertIn('NT AUTHORITY',text);self.assertIn('LocalService',text);self.assertIn('IsUserAnAdmin',text);self.assertNotIn("'runas'",text)
    @unittest.skipUnless(os.name!='nt','Non-Windows gate')
    def test_native_build_requires_windows(self):
        with self.assertRaises(Denied):package.agent_build('unused')
class LimitsTests(Fixture,unittest.TestCase):
    def setUp(self):self.setup()
    def tearDown(self):self.teardown()
    def test_symlink_root_rejected(self):
        if os.name=='nt':self.skipTest('Native symlink permissions require Windows QA')
        from agent.runtime import Agent
        link=self.root/'link';link.symlink_to(self.root/'agent',target_is_directory=True)
        with self.assertRaises(Denied):Agent(link,self.config,transport=self.direct)
    def test_agent_action_history_bound(self):
        self.queue();envelope=self.claim()
        with patch.object(self.a.engine.store,'list_action_runs',return_value=[{'id':'existing'}]):self.a._execute(envelope)
        self.assertEqual(60,self.a.engine.monitor.interval_seconds)
    def test_entitlement_storage_short_lived_for_agent(self):
        self.queue();self.claim();rows=self.p.repo.list('entitlement');self.assertTrue(rows);self.assertLessEqual(rows[0]['expires'],self.clock()+300)
        self.clock.advance(301);self.f.cleanup();self.assertEqual([],self.p.repo.list('entitlement'));self.assertEqual([],self.p.repo.list('lease'))
if __name__=='__main__':unittest.main()
