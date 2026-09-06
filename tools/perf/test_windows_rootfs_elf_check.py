"""Offline dependency gate: real tiny ext4/ELF fixtures, no mounted images."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "windows-rootfs-elf-check.py"
SPEC = importlib.util.spec_from_file_location("rootfs_elf_check", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


class PolicyTests(unittest.TestCase):
    def test_command_strings_reject_injection_and_tokens(self):
        for path in ('/a\nb', '/a"b', '/a b', '/a\\b', '/a;b', '$LIB/a', ''):
            with self.subTest(path=path), self.assertRaises(gate.Failure):
                gate.safe_path(path)

    def test_dynamic_search_requires_known_absolute_context(self):
        self.assertEqual(gate.directories('$ORIGIN/../lib', '/opt/bin/lib.so'), ('/opt/bin/../lib',))
        self.assertEqual(gate.directories('/opt/lib:/usr/lib64', None), ('/opt/lib', '/usr/lib64'))
        for value in ('$ORIGIN/lib', '$LIB', '/lib64:', 'relative'):
            with self.subTest(value=value), self.assertRaises(gate.Failure):
                gate.directories(value, None)

    def test_readelf_errors_fail_closed(self):
        output = subprocess.CompletedProcess([], 0, 'not an ELF header', '')
        with patch.object(gate, 'run', return_value=output), self.assertRaises(gate.Failure):
            gate.inspect(Path('/unused'))

    def test_debugfs_zero_exit_error_is_not_success(self):
        image = object.__new__(gate.Image)
        image.path = Path('/unused')
        for diagnostic in ('Filesystem not open', 'bad metadata checksum'):
            output = subprocess.CompletedProcess([], 0, '', 'debugfs 1.47.2\n' + diagnostic)
            with patch.object(gate, 'run', return_value=output), self.assertRaises(gate.Failure):
                image.request('stat /')


@unittest.skipUnless(all(shutil.which(tool) for tool in ('gcc', 'mke2fs', 'debugfs', 'readelf')),
                     'requires gcc, mke2fs, debugfs and readelf')
class Ext4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='windows-elf-fixtures-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.base = Path(cls.tmp.name)
        cls.build = cls.base / 'build'
        cls.build.mkdir()
        sources = {'leaf': 'int leaf(void) { return 7; }',
                   'middle': 'extern int leaf(void); int middle(void) { return leaf(); }',
                   'root': 'extern int middle(void); int main(void) { return middle(); }'}
        for name, text in sources.items():
            (cls.build / f'{name}.c').write_text(text)
        cls.command('gcc', '-nostdlib', '-shared', '-fPIC', '-Wl,-soname,libleaf.so',
                    '-o', cls.build / 'libleaf.so', cls.build / 'leaf.c')
        cls.command('gcc', '-nostdlib', '-shared', '-fPIC', '-Wl,-soname,libmiddle.so',
                    '-o', cls.build / 'libmiddle.so', cls.build / 'middle.c',
                    '-L' + str(cls.build), '-lleaf')
        cls.command('gcc', '-nostdlib', '-Wl,-e,main', '-Wl,--dynamic-linker=/lib64/ld-test.so',
                    '-o', cls.build / 'root', cls.build / 'root.c',
                    '-L' + str(cls.build), '-lmiddle', '-Wl,--allow-shlib-undefined')

    @staticmethod
    def command(*args):
        subprocess.run([str(arg) for arg in args], check=True, capture_output=True)

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(prefix='case-', dir=self.base)
        self.addCleanup(self.tmpdir.cleanup)
        self.work = Path(self.tmpdir.name)
        self.tree = self.work / 'tree'
        libs = self.tree / 'usr/lib64'
        libs.mkdir(parents=True)
        (self.tree / 'lib64').symlink_to('usr/lib64')
        shutil.copyfile(self.build / 'libleaf.so', libs / 'libleaf-real.so')
        (libs / 'libleaf.so').symlink_to('/usr/lib64/libleaf-real.so')
        shutil.copyfile(self.build / 'libmiddle.so', libs / 'libmiddle.so')
        shutil.copyfile(self.build / 'libleaf.so', libs / 'ld-test.so')
        self.extracted = self.work / 'extract'
        self.extracted.mkdir()
        self.image_path = self.work / 'root.img'

    def image(self):
        with self.image_path.open('wb') as image:
            image.truncate(16 * 1024 * 1024)
        self.command('mke2fs', '-q', '-t', 'ext4', '-F', '-d', self.tree, self.image_path)
        return gate.Image(self.image_path, self.extracted)

    def test_recursive_closure_interpreter_symlinks_and_image_unchanged(self):
        image = self.image()
        before = hashlib.sha256(self.image_path.read_bytes()).digest()
        with patch.object(gate, 'run', wraps=gate.run) as commands:
            reports = gate.check(image, [self.build / 'root', self.build / 'libmiddle.so'])
        for call in commands.call_args_list:
            argv = call.args[0]
            self.assertIn(argv[0], ('debugfs', 'readelf'))
            if argv[0] == 'debugfs':
                self.assertEqual(argv[1], '-R')
                self.assertTrue(argv[2].startswith(('stat /', 'dump <')))
                self.assertNotIn('-w', argv)
        self.assertTrue(any('libmiddle.so -> libleaf.so' in row for row in reports))
        self.assertTrue(any('ld-test.so =>' in row for row in reports))
        self.assertTrue(any('=> /usr/lib64/libleaf-real.so' in row for row in reports))
        self.assertEqual(before, hashlib.sha256(self.image_path.read_bytes()).digest())
        self.assertTrue(all(path.name.startswith('inode-') for path in self.extracted.iterdir()))

    def test_positive_control_missing_transitive_library(self):
        (self.tree / 'usr/lib64/libleaf-real.so').unlink()
        with self.assertRaisesRegex(gate.Failure, 'missing dependency: .*libmiddle.so -> libleaf.so'):
            gate.check(self.image(), [self.build / 'root'])

    def test_missing_interpreter(self):
        (self.tree / 'usr/lib64/ld-test.so').unlink()
        with self.assertRaisesRegex(gate.Failure, 'missing dependency: .*ld-test.so'):
            gate.check(self.image(), [self.build / 'root'])

    def root_with_path(self, tag):
        root = self.work / 'root-with-path'
        self.command('gcc', '-nostdlib', '-Wl,-e,main', '-Wl,--dynamic-linker=/lib64/ld-test.so',
                     '-o', root, self.build / 'root.c', '-L' + str(self.build), '-lmiddle',
                     '-Wl,--allow-shlib-undefined', '-Wl,-rpath,/opt/lib',
                     '-Wl,--enable-new-dtags' if tag == 'runpath' else '-Wl,--disable-new-dtags')
        (self.tree / 'opt/lib').mkdir(parents=True)
        (self.tree / 'usr/lib64/libleaf.so').unlink()
        (self.tree / 'usr/lib64/libleaf-real.so').rename(self.tree / 'opt/lib/libleaf.so')
        return root

    def test_rpath_reaches_transitive_dependency(self):
        root = self.root_with_path('rpath')
        reports = gate.check(self.image(), [root])
        self.assertTrue(any('libmiddle.so -> libleaf.so => /opt/lib/libleaf.so' in row for row in reports))

    def test_runpath_does_not_leak_into_transitive_dependency(self):
        root = self.root_with_path('runpath')
        with self.assertRaisesRegex(gate.Failure, 'missing dependency: .*libmiddle.so -> libleaf.so'):
            gate.check(self.image(), [root])

    def test_guest_origin_runpath_is_resolved_inside_image(self):
        (self.tree / 'usr/lib64/private').mkdir()
        (self.tree / 'usr/lib64/libleaf.so').unlink()
        (self.tree / 'usr/lib64/libleaf-real.so').rename(self.tree / 'usr/lib64/private/libleaf.so')
        self.command('gcc', '-nostdlib', '-shared', '-fPIC', '-Wl,-soname,libmiddle.so',
                     '-o', self.tree / 'usr/lib64/libmiddle.so', self.build / 'middle.c',
                     '-L' + str(self.build), '-lleaf', '-Wl,-rpath,$ORIGIN/private')
        reports = gate.check(self.image(), [self.build / 'root'])
        self.assertTrue(any('=> /usr/lib64/private/libleaf.so' in row for row in reports))

    def test_absolute_symlink_never_uses_host_library(self):
        link = self.tree / 'usr/lib64/libleaf.so'
        link.unlink()
        link.symlink_to(self.build / 'libleaf.so')
        with self.assertRaisesRegex(gate.Failure, 'missing dependency'):
            gate.check(self.image(), [self.build / 'root'])

    def test_symlink_parent_escape_rejected(self):
        link = self.tree / 'usr/lib64/libleaf.so'
        link.unlink()
        link.symlink_to('../../../host-library.so')
        with self.assertRaisesRegex(gate.Failure, 'escapes root'):
            gate.check(self.image(), [self.build / 'root'])

    def test_symlink_loop_rejected(self):
        link = self.tree / 'usr/lib64/libleaf.so'
        link.unlink()
        link.symlink_to('libleaf.so')
        with self.assertRaisesRegex(gate.Failure, 'symlink loop'):
            gate.check(self.image(), [self.build / 'root'])

    def test_long_symlink_uses_owned_inode_dump(self):
        link = self.tree / 'usr/lib64/libleaf.so'
        link.unlink()
        link.symlink_to('./' * 40 + 'libleaf-real.so')
        self.assertTrue(gate.check(self.image(), [self.build / 'root']))

    def test_corrupt_dependency_is_not_presence_success(self):
        (self.tree / 'usr/lib64/libleaf-real.so').write_bytes(b'not an ELF')
        with self.assertRaisesRegex(gate.Failure, 'readelf'):
            gate.check(self.image(), [self.build / 'root'])

    def test_wrong_machine_dependency_rejected(self):
        lib = self.tree / 'usr/lib64/libleaf-real.so'
        content = bytearray(lib.read_bytes())
        content[18:20] = (183 if content[18:20] == b'\x3e\0' else 62).to_bytes(2, 'little')
        lib.write_bytes(content)
        with self.assertRaisesRegex(gate.Failure, 'ABI mismatch'):
            gate.check(self.image(), [self.build / 'root'])

    def test_image_change_detected(self):
        image = self.image()
        st = self.image_path.stat()
        os.utime(self.image_path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
        with self.assertRaisesRegex(gate.Failure, 'image changed'):
            image.unchanged()

    def test_cli_repeatable_elf_and_temporary_cleanup(self):
        self.image()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = gate.main(['--image', str(self.image_path), '--elf', str(self.build / 'root'),
                                '--elf', str(self.build / 'libmiddle.so'), '--temp-dir', str(self.extracted)])
        self.assertEqual(status, 0)
        self.assertIn('PASS: 2 ELF roots', output.getvalue())
        self.assertEqual(list(self.extracted.iterdir()), [])

    def test_cli_missing_library_fails_and_cleans_temporary(self):
        (self.tree / 'usr/lib64/libmiddle.so').unlink()
        self.image()
        with contextlib.redirect_stderr(io.StringIO()) as output:
            status = gate.main(['--image', str(self.image_path), '--elf', str(self.build / 'root'),
                                '--temp-dir', str(self.extracted)])
        self.assertEqual(status, 1)
        self.assertIn('missing dependency', output.getvalue())
        self.assertEqual(list(self.extracted.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
