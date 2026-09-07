import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_rootfs_payload_check", ROOT / "windows-rootfs-payload-check.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# The packaged Windows runtime this tree builds; the fixture is made from it,
# never from a Wine the build host happens to have installed.
WINE_TREE = ROOT.parent / "target/artifacts/wine/x86_64"
WINE_VERSION = (ROOT / "wine-version").read_text().strip()


class RootfsPayloadContractTests(unittest.TestCase):
    def test_complete_manifest_is_accepted(self):
        self.assertEqual(MODULE.validate_manifest(MODULE.required_paths()), ())

    def test_missing_compositor_is_an_explicit_negative_control(self):
        paths = [path for path in MODULE.required_paths()
                 if path != "/usr/local/bin/windows-compositor"]
        self.assertIn("/usr/local/bin/windows-compositor",
                      MODULE.validate_manifest(paths))

    def test_runtime_module_manifest_is_a_negative_control(self):
        self.assertEqual(MODULE.missing_runtime_modules(MODULE.RUNTIME_LOADED_MODULES), ())
        self.assertEqual(MODULE.missing_runtime_modules(["kernel32.dll"]),
                         MODULE.RUNTIME_LOADED_MODULES)

    def test_normal_qemu_x86_selects_the_staging_route(self):
        makefile = (ROOT.parent / "Makefile").read_text()
        self.assertIn("WINDOWS_NOTEPAD ?= 1", makefile)
        section = makefile.split("qemu-x86:\n", 1)[1].split("\n# One file", 1)[0]
        self.assertIn("$(WINDOWS_NOTEPAD_ENV)", section)
        self.assertIn("$(XTASK) grub --arch x86_64", section)


@unittest.skipUnless((WINE_TREE / "wine-version").is_file(),
                     "packaged Wine tree absent; run tools/build-wine-runtime.sh")
class Ext4ValidatorTests(unittest.TestCase):
    NTDLL = WINE_TREE / "x86_64-unix/ntdll.so"
    WIN32U = WINE_TREE / "x86_64-unix/win32u.so"

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
                "/usr/lib/wine", "/usr/lib64", "/usr/lib64/wine",
                "/windows", "/windows/c", "/windows/c/windows"):
            self.debugfs(f"mkdir {directory}")
        self.write("/usr/local/bin/windows-runtime", b"runtime")
        self.write("/usr/local/bin/windows-compositor", b"compositor")
        self.write("/usr/local/bin/registryd", b"registry")
        self.write("/usr/local/bin/windows-notepad-smoke", b"wrapper")
        self.write("/usr/local/lib/oxide/windows/x86_64-windows/notepad.exe",
                   (WINE_TREE / "x86_64-windows/notepad.exe").read_bytes())
        self.write_native("/usr/local/lib/oxide/windows/x86_64-unix/ntdll.so", self.NTDLL)
        self.write_native("/usr/local/lib/oxide/windows/x86_64-unix/win32u.so", self.WIN32U)
        for name in MODULE.VERSIONED_MODULES:
            self.write(f"/usr/local/lib/oxide/windows/x86_64-windows/{name}",
                       (WINE_TREE / "x86_64-windows" / name).read_bytes())
        self.write("/usr/local/lib/oxide/windows/wine-version", f"{WINE_VERSION}\n".encode())
        self.write("/usr/local/lib/oxide/windows/x86_64-windows/imm32.dll", b"dll")
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
        self.debugfs("symlink /windows/c/windows/system32 /usr/local/lib/oxide/windows/x86_64-windows")
        self.debugfs("symlink /windows/z /")

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

    def run_validator(self, expected_version=WINE_VERSION):
        return MODULE.check_image(self.image, expected_version)

    def test_real_ext4_fixture_passes_complete_validator(self):
        self.assertEqual(self.run_validator(), "payload: PASS")

    def test_real_ext4_fixture_rejects_a_wine_the_tree_does_not_build(self):
        with self.assertRaisesRegex(MODULE.Failure, "expected"):
            self.run_validator(expected_version="10.20")

    def test_real_ext4_fixture_rejects_a_catalog_blended_from_two_builds(self):
        name = MODULE.VERSIONED_MODULES[0]
        blob = (WINE_TREE / "x86_64-windows" / name).read_bytes()
        older = blob.replace(f"Wine {WINE_VERSION}".encode("utf-16-le"),
                             "Wine 10.20".encode("utf-16-le").ljust(len(f"Wine {WINE_VERSION}".encode("utf-16-le")), b"\0"))
        self.assertNotEqual(older, blob)
        self.debugfs(f"rm /usr/local/lib/oxide/windows/x86_64-windows/{name}")
        self.write(f"/usr/local/lib/oxide/windows/x86_64-windows/{name}", older)
        with self.assertRaisesRegex(MODULE.Failure, "blended"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_a_stamp_no_module_backs(self):
        for name in MODULE.VERSIONED_MODULES:
            self.debugfs(f"rm /usr/local/lib/oxide/windows/x86_64-windows/{name}")
        with self.assertRaisesRegex(MODULE.Failure, "unbacked"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_missing_compositor(self):
        self.debugfs("unlink /usr/local/bin/windows-compositor")
        with self.assertRaisesRegex(MODULE.Failure, "windows-compositor"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_wrong_symlink_target(self):
        self.debugfs("unlink /usr/lib64/wine/x86_64-windows")
        self.debugfs("symlink /usr/lib64/wine/x86_64-windows /tmp/not-the-catalog")
        with self.assertRaisesRegex(MODULE.Failure, "target"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_a_missing_dos_system_directory(self):
        self.debugfs("unlink /windows/c/windows/system32")
        with self.assertRaisesRegex(MODULE.Failure, "/windows/c/windows/system32"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_a_dos_drive_z_that_is_not_the_unix_root(self):
        self.debugfs("unlink /windows/z")
        self.debugfs("symlink /windows/z /usr")
        with self.assertRaisesRegex(MODULE.Failure, "/windows/z"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_a_system_directory_without_runtime_modules(self):
        self.debugfs("unlink /usr/local/lib/oxide/windows/x86_64-windows/imm32.dll")
        with self.assertRaisesRegex(MODULE.Failure, "imm32.dll"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_a_guest_catalog_carrying_the_held_back_runtime(self):
        # The kernel publishes the NT runtime module's exports itself, so a
        # real image of the same name in the guest catalog is a second source
        # for them. The image holds it back; this is what notices if it stops.
        self.write("/usr/local/lib/oxide/windows/x86_64-windows/ntdll.dll", b"MZ")
        with self.assertRaisesRegex(MODULE.Failure, "ntdll.dll"):
            self.run_validator()

    def test_real_ext4_fixture_rejects_non_elf_native_copy(self):
        self.debugfs("unlink /usr/local/lib/oxide/windows/x86_64-unix/win32u.so")
        self.write("/usr/local/lib/oxide/windows/x86_64-unix/win32u.so", b"not an ELF")
        with self.assertRaisesRegex(MODULE.Failure, "ELF"):
            self.run_validator()


if __name__ == "__main__":
    unittest.main()
