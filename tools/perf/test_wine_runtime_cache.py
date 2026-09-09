"""Run the real runtime builder against a tiny source/archive/toolchain fixture."""
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


BUILDER = Path(__file__).resolve().parents[1] / 'build-wine-runtime.sh'


class RuntimeCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='oxide-wine-cache-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.write('tools/build-wine-runtime.sh', BUILDER.read_text(), executable=True)
        self.write('tools/wine-version', '11.16\n')
        self.write('headers.rpm', 'headers-v1')
        self.write('upstream/wine-11.16/VERSION', 'Wine version 11.16\n')
        self.write('upstream/wine-11.16/value', 'original\n')
        self.write('upstream/wine-11.16/configure', '#!/bin/sh\nprintf configured > Makefile\n', executable=True)
        self.archive()
        self.write('bin/clang', '#!/bin/sh\nexit 0\n', executable=True)
        self.write('bin/rpm2cpio', '#!/bin/sh\ncat "$1"\n', executable=True)
        self.write('bin/cpio', '#!/bin/sh\nmkdir -p usr/x86_64-w64-mingw32/sys-root/mingw/include\ncat > usr/header-input\n', executable=True)
        self.write('bin/nm', '#!/bin/sh\nprintf "wine_oxide_attach_thread\\n"\n', executable=True)
        self.write('bin/make', '''#!/usr/bin/env python3
import os, sys
from pathlib import Path
args = sys.argv[1:]
if 'install' in args:
    dest = Path(next(a.split('=', 1)[1] for a in args if a.startswith('DESTDIR='))) / 'usr/local'
    value = (Path(os.environ['OXIDE_WINE_WORK']) / 'wine-11.16/value').read_text()
    for name in ('lib/wine/x86_64-windows/notepad.exe', 'lib/wine/x86_64-windows/ntdll.dll',
                 'lib/wine/x86_64-unix/ntdll.so', 'lib/wine/x86_64-unix/win32u.so', 'share/wine/nls/test.nls'):
        p = dest / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)
''', executable=True)
        (self.root / 'patches').mkdir()
        self.env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                        OXIDE_WINE_WORK=str(self.root / 'work'), OXIDE_WINE_OUT=str(self.root / 'out'),
                        OXIDE_WINE_TARBALL=str(self.root / 'source.tar.xz'),
                        OXIDE_MINGW_HEADERS_RPM=str(self.root / 'headers.rpm'),
                        OXIDE_WINE_PATCH_DIR=str(self.root / 'patches'), OXIDE_WINE_JOBS='1')

    def write(self, name, value, executable=False):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        if executable:
            path.chmod(0o755)
        return path

    def archive(self):
        with tarfile.open(self.root / 'source.tar.xz', 'w:xz') as archive:
            archive.add(self.root / 'upstream/wine-11.16', arcname='wine-11.16')

    def patch(self, value):
        self.write('patches/0001-value.patch',
                   '--- a/value\n+++ b/value\n@@ -1 +1 @@\n-original\n+' + value + '\n')

    def run_builder(self, expected=0):
        run = subprocess.run([str(self.root / 'tools/build-wine-runtime.sh')],
                             env=self.env, text=True, capture_output=True)
        self.assertEqual(run.returncode, expected, run.stdout + run.stderr)
        if not expected:
            return (self.root / 'out/x86_64-windows/notepad.exe').read_text()

    def test_patch_edit_removal_and_unchanged_build(self):
        self.patch('first')
        self.assertEqual(self.run_builder(), 'first\n')
        marker = self.write('work/build-11.16/keep', 'unchanged')
        self.assertEqual(self.run_builder(), 'first\n')
        self.assertTrue(marker.exists(), 'unchanged inputs discarded the configured build')
        self.patch('second')
        self.assertEqual(self.run_builder(), 'second\n')
        self.assertFalse(marker.exists(), 'changed patches reused configured objects')
        (self.root / 'patches/0001-value.patch').unlink()
        self.assertEqual(self.run_builder(), 'original\n')

    def test_headers_source_and_recipe_changes_invalidate(self):
        self.assertEqual(self.run_builder(), 'original\n')
        self.write('headers.rpm', 'headers-v2')
        self.run_builder()
        self.assertEqual((self.root / 'work/mingw64-headers/usr/header-input').read_text(), 'headers-v2')
        self.write('upstream/wine-11.16/value', 'new-source\n')
        self.archive()
        self.assertEqual(self.run_builder(), 'new-source\n')
        marker = self.write('work/build-11.16/keep', 'stale')
        script = self.root / 'tools/build-wine-runtime.sh'
        script.write_text(script.read_text() + '\n# changed build recipe\n')
        self.assertEqual(self.run_builder(), 'new-source\n')
        self.assertFalse(marker.exists())

    def test_failed_patch_is_not_cached(self):
        self.write('patches/0001-value.patch', '--- a/value\n+++ b/value\n@@ -1 +1 @@\n-absent\n+bad\n')
        self.run_builder(expected=1)
        self.assertFalse((self.root / 'work/wine-11.16/.oxide-prepared').exists())
        self.patch('repaired')
        self.assertEqual(self.run_builder(), 'repaired\n')


if __name__ == '__main__':
    unittest.main()
