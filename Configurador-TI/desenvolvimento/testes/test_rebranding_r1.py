"""Distribution branding gate and coordinated public identifier contracts."""
import io
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile
from desenvolvimento.scan_branding import scan,require_clean

class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.marker=bytes((67,83,84,73)).decode('ascii')

    def test_text_bom_and_both_utf16_orders(self):
        for i,enc in enumerate(('utf-8','utf-8-sig','utf-16-le','utf-16-be')):
            p=self.root/f'case{i}.txt';p.write_bytes(self.marker.swapcase().encode(enc))
            self.assertGreater(scan(p)['text_occurrences'],0)
            with self.assertRaisesRegex(ValueError,'BRANDING_SCAN_FAILED'):require_clean(p)

    def test_paths_and_binary_strings(self):
        folder=self.root/self.marker.lower();folder.mkdir()
        (folder/'asset.bin').write_bytes(b'\x01\xff'+self.marker.encode()+b'\x00')
        result=scan(folder)
        self.assertGreater(result['path_occurrences'],0)
        self.assertGreater(result['binary_occurrences'],0)

    def test_nested_zip_entries_and_text(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr(self.marker+'/entry.txt',self.marker.lower())
        outer=self.root/'outer.zip'
        with zipfile.ZipFile(outer,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('inner.zip',stream.getvalue())
        result=scan(outer)
        self.assertEqual(2,result['nested_archives'])
        self.assertGreater(result['text_occurrences'],0)
        self.assertGreater(result['path_occurrences'],0)

    def test_broken_archive_fails_closed(self):
        p=self.root/'broken.zip';p.write_bytes(b'not an archive')
        self.assertEqual('FAIL',scan(p)['status'])
        self.assertTrue(scan(p)['errors'])

    def test_clean_input_and_visual_inventory(self):
        (self.root/'readme.md').write_text('Configurador TI')
        (self.root/'capture.png').write_bytes(b'visual fixture')
        r=require_clean(self.root)
        self.assertEqual('PASS',r['status']);self.assertEqual(1,len(r['visual_assets']))

    def test_portable_packaging_rejects_contaminated_readme(self):
        from desenvolvimento.build_portatil import build_portable
        exe=self.root/'ConfiguradorTI.exe';data=bytearray(128)
        data[:2]=b'MZ';struct.pack_into('<I',data,60,64);data[64:68]=b'PE\x00\x00';exe.write_bytes(data)
        readme=self.root/'LEIA-ME.txt';readme.write_text(self.marker)
        with self.assertRaisesRegex(ValueError,'BRANDING_SCAN_FAILED'):
            build_portable(exe,readme,self.root/'out')
        self.assertFalse((self.root/'out').exists())

class ContractTests(unittest.TestCase):
    def test_build_service_and_identity_names_are_coordinated(self):
        import build_config,release_metadata
        from agent.windows_service import SERVICE_NAME
        from licensing.contracts import ISSUER,AUDIENCE
        self.assertEqual('ConfiguradorTI',build_config.OUTPUT_NAME)
        self.assertEqual('ConfiguradorTIAgent',SERVICE_NAME)
        self.assertEqual('Configurador TI',release_metadata.PRODUCT_SHORT)
        self.assertEqual('configurador-ti-control-plane',ISSUER)
        self.assertEqual('configurador-ti-client',AUDIENCE)
        self.assertIn('ConfiguradorTI/ConfiguradorTI.exe',build_config.get_profile('DEV').expected_artifacts)

    def test_browser_accepts_only_new_cookie_name(self):
        from central_web.server import CentralServer
        with CentralServer(('127.0.0.1',0),None) as server:
            sid,_=server.browser_session(None)
            self.assertEqual(sid,server.browser_session('configurador_ti_session='+sid)[0])
            retired=bytes((99,115,116,105)).decode('ascii')
            self.assertNotEqual(sid,server.browser_session(retired+'='+sid)[0])

if __name__=='__main__':unittest.main()
