#!/usr/bin/env python3
"""Offline Fedora ext4 DT_NEEDED closure gate; never executes inspected ELFs.

Checks dependency presence/ELF identity, not symbol versions or dlopen plugins.
No host-library fallback, LD_LIBRARY_PATH, ld.so.cache-only directories or hwcaps
selection. Unsupported dynamic lookup policy fails closed. Main staging must
hold the image stable throughout this check and the subsequent copy.
"""
import argparse
from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

MAX_FILE = 256 * 1024 * 1024
MAX_OBJECTS = 4096
MAX_LINKS = 40
SAFE_PATH = re.compile(r"[A-Za-z0-9_./+@,=:-]+\Z")
DEFAULT_DIRS = ("/lib64", "/usr/lib64")


class Failure(Exception):
    pass


class Missing(Failure):
    pass


def run(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                            env={**os.environ, "LC_ALL": "C"}, **kwargs)
    if result.returncode:
        raise Failure(f"{argv[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result


def safe_path(path):
    if not path or len(path) > 4096 or not SAFE_PATH.fullmatch(path):
        raise Failure(f"unsupported/unsafe guest path: {path!r}")
    return path


@dataclass(frozen=True)
class Inode:
    number: int
    kind: str
    size: int
    link: str | None


class Image:
    def __init__(self, path, temporary):
        self.path = Path(path).resolve(strict=True)
        if not self.path.is_file():
            raise Failure(f"not a regular image: {self.path}")
        self.temporary = Path(temporary)
        self.stats = {}
        self.dumps = {}
        self.before = self.fingerprint()

    def fingerprint(self):
        st = self.path.stat()
        return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns

    def unchanged(self):
        if self.fingerprint() != self.before:
            raise Failure("image changed during dependency check; serialize staging")

    def request(self, command):
        # No -w, scripts, recursive extraction, or shell command evaluation.
        result = run(["debugfs", "-R", command, str(self.path)])
        diagnostics = "\n".join(line for line in result.stderr.splitlines()
                                if line and not line.startswith("debugfs "))
        if diagnostics:
            if re.fullmatch(r"[^\n]*: File not found by ext2_lookup\s*", diagnostics):
                raise Missing(diagnostics.strip())
            raise Failure(f"debugfs {command}: {diagnostics}")
        return result.stdout

    def stat(self, path):
        safe_path(path)
        if path not in self.stats:
            out = self.request(f"stat {path}")
            header = re.search(r"^Inode: (\d+)\s+Type: (\w+)", out, re.M)
            size = re.search(r"^User:.*\bSize:\s+(\d+)", out, re.M)
            link = re.search(r'^Fast link dest: "(.*)"$', out, re.M)
            if not header or not size:
                raise Failure(f"unrecognized inode metadata: {path}")
            self.stats[path] = Inode(int(header[1]), header[2], int(size[1]),
                                     link[1] if link else None)
        return self.stats[path]

    def dump(self, inode):
        if inode.size > MAX_FILE:
            raise Failure(f"inode {inode.number} exceeds extraction limit")
        if inode.number not in self.dumps:
            if len(self.dumps) >= MAX_OBJECTS:
                raise Failure("extraction object limit exceeded")
            # Host names derive only from numeric inodes, never guest paths.
            target = self.temporary / f"inode-{inode.number}"
            if any(c in str(target) for c in ('"', '\\', '\n', '\r')):
                raise Failure("unsupported temporary directory name")
            self.request(f'dump <{inode.number}> "{target}"')
            if not target.is_file() or target.stat().st_size != inode.size:
                raise Failure(f"short/failed inode extraction: {inode.number}")
            self.dumps[inode.number] = target
        return self.dumps[inode.number]

    def resolve(self, path):
        safe_path(path)
        if not path.startswith("/"):
            raise Failure(f"guest path must be absolute: {path}")
        pending, parts, links = deque(path.split("/")), [], 0
        inode = self.stat("/")
        while pending:
            component = pending.popleft()
            if component in ("", "."):
                continue
            if component == "..":
                if not parts:
                    raise Failure(f"guest path escapes root: {path}")
                parts.pop()
                inode = self.stat("/" + "/".join(parts))
                continue
            candidate = "/" + "/".join(parts + [component])
            inode = self.stat(candidate)
            if inode.kind == "symlink":
                links += 1
                if links > MAX_LINKS:
                    raise Failure(f"symlink loop/limit: {path}")
                dest = inode.link
                if dest is None:
                    dest = self.dump(inode).read_bytes().decode("utf-8", errors="strict")
                safe_path(dest)
                if dest.startswith("/"):
                    parts = []
                pending.extendleft(reversed(dest.split("/")))
            else:
                parts.append(component)
                if pending and inode.kind != "directory":
                    raise Failure(f"non-directory guest component: {candidate}")
        return "/" + "/".join(parts), inode

    def file(self, path):
        canonical, inode = self.resolve(path)
        if inode.kind != "regular":
            raise Failure(f"not a regular guest ELF: {path} ({inode.kind})")
        return canonical, self.dump(inode)


@dataclass(frozen=True)
class Elf:
    identity: tuple
    needed: tuple
    interpreter: str | None
    rpath: str | None
    runpath: str | None


def inspect(path):
    result = run(["readelf", "--wide", "--file-header", "--program-headers", "--dynamic", str(path)])
    if result.stderr.strip():
        raise Failure(f"readelf diagnostics for {path}: {result.stderr.strip()}")
    out = result.stdout
    fields = {}
    for key in ("Class", "Data", "Machine", "Type"):
        match = re.search(rf"^\s*{key}:\s+(.+)$", out, re.M)
        if not match:
            raise Failure(f"missing ELF {key}: {path}")
        fields[key] = match[1]
    if not fields["Type"].startswith(("DYN ", "EXEC ")):
        raise Failure(f"not an executable/shared ELF: {path}")
    if fields["Class"] != "ELF64" or fields["Machine"] not in ("Advanced Micro Devices X86-64", "AArch64"):
        raise Failure(f"unsupported Fedora ELF ABI: {path}")
    tags = {}
    for line in out.splitlines():
        match = re.search(r"\((NEEDED|RPATH|RUNPATH)\).*\[(.*)\]$", line)
        if match:
            tags.setdefault(match[1], []).append(match[2])
        elif re.search(r"\((NEEDED|RPATH|RUNPATH)\)", line):
            raise Failure(f"malformed dynamic string: {path}")
        if re.search(r"\((AUDIT|DEPAUDIT|FILTER|AUXILIARY)\)", line) or "NODEFLIB" in line:
            raise Failure(f"unsupported dynamic lookup policy: {path}: {line.strip()}")
    interp = re.findall(r"\[Requesting program interpreter: (.*)\]", out)
    if len(interp) > 1 or (re.search(r"^\s*INTERP\s", out, re.M) and not interp):
        raise Failure(f"malformed PT_INTERP: {path}")
    for tag in ("RPATH", "RUNPATH"):
        if len(tags.get(tag, [])) > 1:
            raise Failure(f"duplicate {tag}: {path}")
    return Elf(tuple(fields[k] for k in ("Class", "Data", "Machine")),
               tuple(tags.get("NEEDED", [])), interp[0] if interp else None,
               next(iter(tags.get("RPATH", [])), None), next(iter(tags.get("RUNPATH", [])), None))


def directories(value, guest):
    if value is None:
        return ()
    if "$ORIGIN" in value or "${ORIGIN}" in value:
        if guest is None:
            raise Failure("host ELF uses $ORIGIN; guest staging destination is unknown")
        origin = guest.rsplit("/", 1)[0]
        value = value.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
    paths = value.split(":")
    for path in paths:
        safe_path(path)
        if not path.startswith("/"):
            raise Failure(f"relative/empty dynamic search directory: {path!r}")
    return tuple(paths)


def check(image, roots):
    reports = []
    for root in roots:
        root = Path(root).resolve(strict=True)
        expected = inspect(root).identity
        pending = deque([(str(root), root, None, ())])
        visited = set()
        while pending:
            label, host, guest, inherited = pending.popleft()
            key = (label, inherited)
            if key in visited:
                continue
            if len(visited) >= MAX_OBJECTS:
                raise Failure("dependency graph limit exceeded")
            visited.add(key)
            elf = inspect(host)
            if elf.identity != expected:
                raise Failure(f"ELF ABI mismatch: {label}: {elf.identity} != {expected}")
            own = directories(elf.rpath, guest) if elf.runpath is None else ()
            inherited = tuple(dict.fromkeys(own + inherited))
            search = (inherited if elf.runpath is None else directories(elf.runpath, guest)) + DEFAULT_DIRS
            edges = list(elf.needed)
            if elf.interpreter:
                if not elf.interpreter.startswith("/"):
                    raise Failure(f"relative PT_INTERP: {label}")
                edges.insert(0, elf.interpreter)
            for name in edges:
                safe_path(name)
                if "/" in name:
                    if not name.startswith("/"):
                        raise Failure(f"relative DT_NEEDED unsupported: {label} -> {name}")
                    candidates = (name,)
                else:
                    candidates = tuple(directory + "/" + name for directory in search)
                for candidate in candidates:
                    try:
                        canonical, extracted = image.file(candidate)
                        break
                    except Missing:
                        continue
                else:
                    raise Failure(f"missing dependency: {label} -> {name}; searched {', '.join(candidates)}")
                reports.append(f"{label} -> {name} => {canonical}")
                pending.append((canonical, extracted, canonical, inherited))
        image.unchanged()
    return reports


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--elf", required=True, action="append", type=Path)
    parser.add_argument("--temp-dir", type=Path, help="owned extraction parent (also honors TMPDIR)")
    args = parser.parse_args(argv)
    try:
        with tempfile.TemporaryDirectory(prefix="windows-rootfs-elf-", dir=args.temp_dir) as tmp:
            reports = check(Image(args.image, tmp), args.elf)
        for report in reports:
            print(report)
        print(f"PASS: {len(args.elf)} ELF roots, {len(reports)} dependency edges (presence/ABI only)")
        return 0
    except (Failure, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
