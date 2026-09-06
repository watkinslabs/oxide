import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_rootfs_payload_check", ROOT / "windows-rootfs-payload-check.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RootfsPayloadContractTests(unittest.TestCase):
    def test_complete_manifest_is_accepted(self):
        self.assertEqual(MODULE.validate_manifest(MODULE.required_paths()), ())

    def test_missing_compositor_is_an_explicit_negative_control(self):
        paths = [path for path in MODULE.required_paths()
                 if path != "/usr/local/bin/windows-compositor"]
        self.assertIn("/usr/local/bin/windows-compositor",
                      MODULE.validate_manifest(paths))

    def test_normal_qemu_x86_selects_the_staging_route(self):
        makefile = (ROOT.parent / "Makefile").read_text()
        self.assertIn("WINDOWS_NOTEPAD ?= 1", makefile)
        section = makefile.split("qemu-x86:\n", 1)[1].split("\n# One file", 1)[0]
        self.assertIn("$(WINDOWS_NOTEPAD_ENV)", section)
        self.assertIn("$(XTASK) grub --arch x86_64", section)


class Ext4ValidatorTests(unittest.TestCase):
    NTDLL = Path("target/lanes/wine-10.20-build/dlls/ntdll/ntdll.so")
    WIN32U = Path("target/lanes/wine-10.20-build/dlls/win32u/win32u.so")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="oxide-rootfs-fixture-")
        self.root = Path(self.tmp.name)
        self.image = self.root / "root.img"
        with self.image.open("wb") as image:
            image.truncate(64 * 1024 * 1024)
        subprocess.run(["mkfs.ext4", "-q", "-F", str(self.image)], check=True,
                       capture_output=True, text=True)
        for directory in (
                "/usr", "/usr/local", "/usr/local/bin", "/usr/local/lib",
                "/usr/local/lib/oxide", "/usr/local/lib/oxide/windows",
                "/usr/local/lib/oxide/windows/x86_64-windows",
                "/usr/local/lib/oxide/windows/x86_64-unix", "/usr/local/share",
                "/usr/local/share/oxide", "/usr/local/share/oxide/windows",
                "/usr/local/share/oxide/windows/nls", "/usr/share",
                "/usr/share/applications", "/etc", "/etc/oxide", "/etc/xdg",
                "/var", "/var/lib", "/var/lib/oxide", "/usr/lib",
                "/usr/lib/wine", "/usr/lib64", "/usr/lib64/wine"):
            self.debugfs(f"mkdir {directory}")
        self.write("/usr/local/bin/windows-runtime", b"runtime")
        self.write("/usr/local/bin/windows-compositor", b"compositor")
        self.write("/usr/local/bin/registryd", b"registry")
        self.write("/usr/local/bin/windows-notepad-smoke", b"wrapper")
        self.write("/usr/local/lib/oxide/windows/x86_64-windows/notepad.exe",
                   Path("/usr/lib/wine/x86_64-windows/notepad.exe").read_bytes())
        self.write_native("/usr/local/lib/oxide/windows/x86_64-unix/ntdll.so", self.NTDLL)
        self.write_native("/usr/local/lib/oxide/windows/x86_64-unix/win32u.so", self.WIN32U)
        self.write("/usr/local/lib/oxide/windows/x86_64-windows/kernel32.dll", b"dll")
        self.write("/usr/local/lib/oxide/windows/x86_64-unix/kernel32.so", b"so")
        self.write("/usr/local/share/oxide/windows/nls/locale.nls", b"nls")
        self.write("/etc/oxide/windows-runtime.conf", b"OXIDE_WINDOWS_RUNTIME=/usr/local/lib/oxide/windows\n")
        self.write("/usr/share/applications/oxide-notepad.desktop",
                   b"Exec=/usr/local/bin/windows-notepad-smoke\n")
        self.write("/etc/xdg/mimeapps.list",
                   b"application/x-ms-dos-executable=oxide-notepad.desktop\n")
        self.write("/var/lib/oxide/registry.db", b"OXREG\0\1")
        self.debugfs("symlink /usr/lib/wine/x86_64-windows /usr/local/lib/oxide/windows/x86_64-windows")
        self.debugfs("symlink /usr/lib64/wine/x86_64-windows /usr/local/lib/oxide/windows/x86_64-windows")

    def tearDown(self):
        self.tmp.cleanup()

    def debugfs(self, command):
        result = subprocess.run(["debugfs", "-w", "-R", command, str(self.image)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def write(self, guest, data):
        host = self.root / ("source-" + str(len(list(self.root.iterdir()))))
        host.write_bytes(data)
        self.debugfs(f"write {host} {guest}")

    def write_native(self, guest, source):
        self.assertTrue(source.is_file(), source)
        self.debugfs(f"write {source} {guest}")

    def run_validator(self, expected=True, expected_ntdll=None, expected_win32u=None):
        if expected:
            expected_ntdll = self.NTDLL if expected_ntdll is None else expected_ntdll
            expected_win32u = self.WIN32U if expected_win32u is None else expected_win32u
        return MODULE.check_image(self.image, expected_ntdll, expected_win32u)

    def test_real_ext4_fixture_passes_complete_validator(self):
        self.assertEqual(self.run_validator(), "payload: PASS")

    def test_real_ext4_fixture_rejects_wrong_native_pair_bytes(self):
        with self.assertRaisesRegex(MODULE.Failure, "differs from expected"):
            self.run_validator(expected_win32u=self.NTDLL)

    def test_native_provenance_requires_both_expected_artifacts(self):
        with self.assertRaisesRegex(MODULE.Failure, "both ntdll and win32u"):
            self.run_validator(expected=False, expected_win32u=self.WIN32U, expected_ntdll=None)

    def test_real_ext4_fixture_rejects_missing_compositor(self):
        self.debugfs("unlink /usr/local/bin/windows-compositor")
        with self.assertRaisesRegex(MODULE.Failure, "windows-compositor"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_wrong_symlink_target(self):
        self.debugfs("unlink /usr/lib64/wine/x86_64-windows")
        self.debugfs("symlink /usr/lib64/wine/x86_64-windows /tmp/not-the-catalog")
        with self.assertRaisesRegex(MODULE.Failure, "target"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_non_elf_native_copy(self):
        self.debugfs("unlink /usr/local/lib/oxide/windows/x86_64-unix/win32u.so")
        self.write("/usr/local/lib/oxide/windows/x86_64-unix/win32u.so", b"not an ELF")
        with self.assertRaisesRegex(MODULE.Failure, "ELF"):
            self.run_validator()


if __name__ == "__main__":
    unittest.main()
