#!/usr/bin/env python3
"""Read-only manifest gate for the default x86 Notepad rootfs boundary.

The check never mounts or writes the guest image. It verifies the files that
the normal qemu-x86 assembly must publish, including the selected
native bridge pair and the desktop/MIME launch path. The packaged Wine version
stamp and the modules themselves establish which Wine the image carries.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


WINDOWS_ROOT = "/usr/local/lib/oxide/windows"
WINDOWS_CATALOG = f"{WINDOWS_ROOT}/x86_64-windows"
UNIX_CATALOG = f"{WINDOWS_ROOT}/x86_64-unix"
NLS_ROOT = "/usr/local/share/oxide/windows/nls"
VERSION_STAMP = f"{WINDOWS_ROOT}/wine-version"
# Modules of the Notepad closure whose version resource names the Wine release.
# A catalog blended from two builds answers this question twice.
VERSIONED_MODULES = ("user32.dll", "gdi32.dll", "kernel32.dll", "comctl32.dll",
                     "shell32.dll", "advapi32.dll")
MIN_AGREEING_MODULES = 4
# The native DOS drive namespace. A drive letter directory under the DOS root
# is the drive; the system drive's windows/system32 is where the loader and
# every native file open resolve a module named by a DOS path.
DOS_SYSTEM32 = "/windows/c/windows/system32"
DOS_DRIVE_Z = "/windows/z"
UNIX_ROOT = "/"
# Modules no launch-time catalog supplies: user32 loads imm32 from its DllMain
# and the ImmGetContext delay thunk resolves it, both at runtime through the
# system directory.
RUNTIME_LOADED_MODULES = ("imm32.dll",)
# The kernel publishes the NT runtime module's exports itself and is the loader
# that binds every other module against them. A real image of the same name in
# the guest catalog would be a second source for those exports, so the image
# holds it back even though the package carries the complete upstream build.
HELD_BACK_MODULES = ("ntdll.dll",)

REQUIRED_FILES = (
    "/usr/local/bin/windows-runtime",
    "/usr/local/bin/windows-compositor",
    "/usr/local/bin/registryd",
    "/usr/local/bin/windows-notepad-smoke",
    f"{WINDOWS_CATALOG}/notepad.exe",
    f"{UNIX_CATALOG}/ntdll.so",
    f"{UNIX_CATALOG}/win32u.so",
    f"{NLS_ROOT}/locale.nls",
    VERSION_STAMP,
    "/etc/oxide/windows-runtime.conf",
    "/usr/share/applications/oxide-notepad.desktop",
    "/etc/xdg/mimeapps.list",
    "/var/lib/oxide/registry.db",
)
REQUIRED_LINKS = {
    "/usr/lib/wine/x86_64-windows": WINDOWS_CATALOG,
    "/usr/lib64/wine/x86_64-windows": WINDOWS_CATALOG,
    DOS_SYSTEM32: WINDOWS_CATALOG,
    DOS_DRIVE_Z: UNIX_ROOT,
}


class Failure(Exception):
    pass


def required_paths():
    return REQUIRED_FILES + tuple(REQUIRED_LINKS)


def validate_manifest(paths):
    """Return missing paths from a materialized guest manifest."""
    present = set(paths)
    return tuple(path for path in required_paths() if path not in present)


def missing_runtime_modules(catalog):
    """Return runtime-loaded modules the DOS system directory cannot resolve."""
    present = {name.lower() for name in catalog}
    return tuple(name for name in RUNTIME_LOADED_MODULES if name not in present)


class Image:
    def __init__(self, path):
        self.path = Path(path).resolve(strict=True)
        if not self.path.is_file():
            raise Failure(f"not a regular image: {self.path}")
        stat = self.path.stat()
        self.fingerprint = (stat.st_dev, stat.st_ino, stat.st_size,
                            stat.st_mtime_ns, stat.st_ctime_ns)
        self.dump_number = 0

    def command(self, expression):
        result = subprocess.run(["debugfs", "-R", expression, str(self.path)],
                                capture_output=True, text=True, timeout=30,
                                env={**os.environ, "LC_ALL": "C"})
        diagnostics = "\n".join(line for line in result.stderr.splitlines()
                                  if line and not line.startswith("debugfs "))
        if diagnostics or result.returncode:
            raise Failure(f"debugfs {expression}: {diagnostics or result.stderr.strip()}")
        return result.stdout

    def stat(self, path):
        return self.command(f"stat {path}")

    def link_target(self, path):
        out = self.stat(path)
        match = re.search(r'^Fast link dest: "([^"]+)"$', out, re.MULTILINE)
        if "Type: symlink" not in out or not match:
            raise Failure(f"guest path is not a fast symlink: {path}")
        return match[1]

    def entries(self, path):
        out = self.command(f"ls -p {path}")
        names = []
        for line in out.splitlines():
            fields = line.split("/")
            if len(fields) >= 6 and fields[5] not in (".", ".."):
                names.append(fields[5])
        return tuple(names)

    def dump(self, path, directory):
        self.dump_number += 1
        target = directory / f"dump-{self.dump_number}"
        result = subprocess.run(["debugfs", "-R", f'dump {path} "{target}"', str(self.path)],
                                capture_output=True, text=True, timeout=30,
                                env={**os.environ, "LC_ALL": "C"})
        diagnostics = "\n".join(line for line in result.stderr.splitlines()
                                  if line and not line.startswith("debugfs "))
        if result.returncode or diagnostics or not target.is_file():
            raise Failure(f"cannot read guest file {path}: {diagnostics or result.stderr.strip()}")
        return target

    def unchanged(self):
        stat = self.path.stat()
        if (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns,
                stat.st_ctime_ns) != self.fingerprint:
            raise Failure("image changed during validation")


def module_wine_version(blob):
    """The Wine release a PE module's version resource names, if any."""
    needle = "Wine ".encode("utf-16-le")
    at = 0
    while True:
        found = blob.find(needle, at)
        if found < 0:
            return None
        cursor = found + len(needle)
        version = ""
        while cursor + 1 < len(blob) and blob[cursor + 1] == 0 and chr(blob[cursor]) in "0123456789.":
            version += chr(blob[cursor])
            cursor += 2
        if "." in version and version[0].isdigit():
            return version
        at = found + len(needle)


def check_wine_provenance(image, expected):
    """One Wine, stated by the image and backed by the modules themselves."""
    with tempfile.TemporaryDirectory(prefix="oxide-wine-version-") as tmp:
        tmpdir = Path(tmp)
        stamp = image.dump(VERSION_STAMP, tmpdir).read_text().strip()
        if stamp != expected:
            raise Failure(f"image carries Wine {stamp!r}, expected {expected!r}")
        agreeing = 0
        for name in VERSIONED_MODULES:
            try:
                blob = image.dump(f"{WINDOWS_CATALOG}/{name}", tmpdir).read_bytes()
            except Failure:
                continue
            found = module_wine_version(blob)
            if found is None:
                continue
            if found != expected:
                raise Failure(f"{name} is Wine {found}, not {expected}: the staged catalog is blended")
            agreeing += 1
        if agreeing < MIN_AGREEING_MODULES:
            raise Failure(f"only {agreeing} staged modules name a Wine version; the stamp is unbacked")


def check_image(path, expected_wine_version):
    image = Image(path)
    missing = []
    for guest_path in REQUIRED_FILES:
        try:
            image.stat(guest_path)
        except Failure:
            missing.append(guest_path)
    for guest_path, expected in REQUIRED_LINKS.items():
        try:
            target = image.link_target(guest_path)
            if target != expected:
                missing.append(f"{guest_path} (target {target!r}, expected {expected!r})")
        except Failure:
            missing.append(guest_path)
    if missing:
        raise Failure("missing required payload:\n  " + "\n  ".join(missing))
    present = [name for name in image.entries(WINDOWS_CATALOG) if name.lower() in HELD_BACK_MODULES]
    if present:
        raise Failure("guest catalog carries a module the kernel publishes itself: " + ", ".join(present))
    pe_catalog = image.entries(WINDOWS_CATALOG)
    unix_catalog = image.entries(UNIX_CATALOG)
    if not any(name.lower().endswith(".dll") for name in pe_catalog):
        raise Failure("PE catalog has no structural DLL payload")
    if not any(name.lower().endswith(".so") for name in unix_catalog):
        raise Failure("Unixlib catalog has no structural Unixlib payload")
    absent = missing_runtime_modules(pe_catalog)
    if absent:
        raise Failure(f"{DOS_SYSTEM32} resolves no " + ", ".join(absent))

    check_native_elf(image, f"{UNIX_CATALOG}/ntdll.so", require_attach=True)
    check_native_elf(image, f"{UNIX_CATALOG}/win32u.so", require_attach=False)
    check_wine_provenance(image, expected_wine_version)

    with tempfile.TemporaryDirectory(prefix="oxide-rootfs-payload-") as tmp:
        tmpdir = Path(tmp)
        notepad = image.dump(f"{WINDOWS_CATALOG}/notepad.exe", tmpdir).read_bytes()
        if len(notepad) < 0x40 or notepad[:2] != b"MZ":
            raise Failure("staged Notepad is not an MZ image")
        pe = int.from_bytes(notepad[0x3C:0x40], "little")
        if (pe + 26 > len(notepad) or notepad[pe:pe + 4] != b"PE\0\0" or
                int.from_bytes(notepad[pe + 4:pe + 6], "little") != 0x8664 or
                int.from_bytes(notepad[pe + 24:pe + 26], "little") != 0x20B):
            raise Failure("staged Notepad is not PE32+ AMD64")
        desktop = image.dump("/usr/share/applications/oxide-notepad.desktop", tmpdir).read_text()
        mimeapps = image.dump("/etc/xdg/mimeapps.list", tmpdir).read_text()
        if "Exec=/usr/local/bin/windows-notepad-smoke" not in desktop:
            raise Failure("desktop entry does not launch the image-owned wrapper")
        if "application/x-ms-dos-executable=oxide-notepad.desktop" not in mimeapps:
            raise Failure("MIME association does not select the Notepad desktop entry")
    image.unchanged()
    return "payload: PASS"


def check_native_elf(image, path, require_attach):
    with tempfile.TemporaryDirectory(prefix="oxide-native-elf-") as tmp:
        elf = image.dump(path, Path(tmp))
        result = subprocess.run(["readelf", "--wide", "--file-header", "--dyn-syms", str(elf)],
                                capture_output=True, text=True, timeout=30,
                                env={**os.environ, "LC_ALL": "C"})
        if result.returncode or result.stderr.strip():
            raise Failure(f"native bridge is not readable ELF: {path}")
        if (not re.search(r"^\s*Class:\s+ELF64$", result.stdout, re.MULTILINE) or
                not re.search(r"^\s*Machine:\s+Advanced Micro Devices X86-64$", result.stdout, re.MULTILINE) or
                not re.search(r"^\s*Type:\s+DYN ", result.stdout, re.MULTILINE)):
            raise Failure(f"native bridge has wrong ELF identity: {path}")
        if require_attach:
            symbols = subprocess.run(["nm", "-D", "--defined-only", str(elf)],
                                     capture_output=True, text=True, timeout=30,
                                     env={**os.environ, "LC_ALL": "C"})
            if (symbols.returncode or symbols.stderr.strip() or
                    not re.search(r"\bwine_oxide_attach_thread$", symbols.stdout, re.MULTILINE)):
                raise Failure(f"native ntdll lacks wine_oxide_attach_thread export: {path}")


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-wine-version", required=True)
    args = parser.parse_args(argv)
    try:
        print(check_image(args.image, args.expected_wine_version))
    except Failure as error:
        print(f"payload: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
