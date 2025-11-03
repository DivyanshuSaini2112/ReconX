import unittest
import os
import shutil
from reconx.modules import nmap, subenum, dirfuzz, whatweb, nikto, ffuf

class TestParsers(unittest.TestCase):

    def setUp(self):
        self.output_dir = 'tests/tmp'
        os.makedirs(self.output_dir, exist_ok=True)
        self.sample_nmap_file = 'tests/sample_nmap.xml'
        self.sample_subdomains_file = 'tests/sample_subdomains.txt'
        self.sample_dirfuzz_file = 'tests/sample_dirfuzz.txt'
        self.sample_whatweb_file = 'tests/sample_whatweb.json'
        self.sample_nikto_file = 'tests/sample_nikto.txt'
        self.sample_ffuf_file = 'tests/sample_ffuf.json'

    def test_nmap_parser(self):
        scanner = nmap.NmapScanner('localhost', 'default', self.output_dir)
        scanner.output_file = self.sample_nmap_file
        parsed_data = scanner.parse_results()
        self.assertIsNotNone(parsed_data)
        self.assertEqual(len(parsed_data), 1)
        host = parsed_data[0]
        self.assertEqual(host['ip'], '127.0.0.1')
        self.assertEqual(len(host['ports']), 2)
        self.assertEqual(host['ports'][0]['portid'], '22')
        self.assertEqual(host['ports'][1]['portid'], '80')

    def test_subdomain_parser(self):
        scanner = subenum.SubdomainScanner('example.com', self.output_dir)
        scanner.output_file = self.sample_subdomains_file
        parsed_data = scanner.parse_results()
        self.assertIsNotNone(parsed_data)
        self.assertEqual(len(parsed_data), 3)
        self.assertIn('test.example.com', parsed_data)

    def test_dirfuzz_parser(self):
        scanner = dirfuzz.DirectoryFuzzer('http://example.com', 'default', None, 10, self.output_dir)
        scanner.output_file = self.sample_dirfuzz_file
        parsed_data = scanner.parse_results()
        self.assertIsNotNone(parsed_data)
        self.assertEqual(len(parsed_data), 3)
        self.assertIn('/admin', parsed_data)

    def test_whatweb_parser(self):
        scanner = whatweb.WhatWebScanner('http://example.com', self.output_dir)
        scanner.output_file = self.sample_whatweb_file
        parsed_data = scanner.parse_results()
        self.assertIsNotNone(parsed_data)
        self.assertEqual(len(parsed_data), 1)
        self.assertEqual(parsed_data[0]['target'], 'http://example.com')
        self.assertIn('Apache', parsed_data[0]['plugins'])

    def test_nikto_parser(self):
        scanner = nikto.NiktoScanner('http://example.com', 'default', self.output_dir)
        scanner.output_file = self.sample_nikto_file
        parsed_data = scanner.parse_results()
        self.assertIsNotNone(parsed_data)
        self.assertEqual(len(parsed_data), 3)
        self.assertTrue(any('X-Frame-Options' in s for s in parsed_data))

    def test_ffuf_parser(self):
        scanner = ffuf.FfufFuzzer('http://example.com', None, 10, self.output_dir)
        scanner.output_file = self.sample_ffuf_file
        parsed_data = scanner.parse_results()
        self.assertIsNotNone(parsed_data)
        self.assertEqual(len(parsed_data), 2)
        self.assertIn('admin', parsed_data)
        self.assertIn('images', parsed_data)

    def tearDown(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)

if __name__ == '__main__':
    unittest.main()
