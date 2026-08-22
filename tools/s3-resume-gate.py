#!/usr/bin/env python3
"""Execute the linked x86 S3 wakeup blob from its firmware entry state."""

import argparse
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

LOAD = 1
SYMTAB = 2
BLOB_START = "oxide_wakeup_tramp"
BLOB_END = "oxide_wakeup_tramp_end"
BLOB_BYTES = 4096
CR3_PA = 0x1000
PDPT_PA = 0x2000
PD_PA = 0x3000
PAYLOAD_PA = 0x8000
TRAMP_PA = 0x9000
PATCH_CR3 = 0xF00
PATCH_ENTRY = 0xF08
PASS_STATUS = (0x10 << 1) | 1
PASS_MARKER = b"S3-TRAMPOLINE-PASS"


def sections(data: bytes):
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsz, count = struct.unpack_from("<HH", data, 58)
    return [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsz)
            for i in range(count)]


def symbols(data: bytes) -> dict[str, int]:
    out = {}
    sh = sections(data)
    for entry in sh:
        if entry[1] != SYMTAB:
            continue
        _, _, _, _, off, size, link, _, _, entsz = entry
        strings = sh[link]
        names = data[strings[4]:strings[4] + strings[5]]
        for at in range(off, off + size, entsz):
            name_at, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", data, at)
            end = names.find(b"\0", name_at)
            name = names[name_at:end].decode(errors="replace")
            if name:
                out[name] = value
    return out


def virtual_bytes(data: bytes, start: int, end: int) -> bytes:
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsz, count = struct.unpack_from("<HH", data, 54)
    for i in range(count):
        p = struct.unpack_from("<IIQQQQQQ", data, phoff + i * entsz)
        kind, _, off, va, _, file_bytes, _, _ = p
        if kind == LOAD and va <= start and end <= va + file_bytes:
            at = off + start - va
            return data[at:at + end - start]
    raise ValueError("linked wakeup blob does not lie in one file-backed LOAD segment")


def linked_blob(elf: Path) -> bytearray:
    data = elf.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("kernel is not a little-endian ELF64 image")
    syms = symbols(data)
    missing = [name for name in (BLOB_START, BLOB_END) if name not in syms]
    if missing:
        raise ValueError("kernel has no " + ", ".join(missing))
    blob = bytearray(virtual_bytes(data, syms[BLOB_START], syms[BLOB_END]))
    if len(blob) != BLOB_BYTES:
        raise ValueError(f"linked wakeup blob is {len(blob)} bytes, expected {BLOB_BYTES}")
    return blob


def assemble(repo: Path, source: str, out: Path):
    subprocess.run(["nasm", "-f", "bin", "-o", str(out),
                    str(repo / source)], check=True)


def disk_image(boot: bytes, blob: bytearray, payload: bytes, corrupt: bool) -> bytes:
    struct.pack_into("<Q", blob, PATCH_CR3, CR3_PA)
    struct.pack_into("<Q", blob, PATCH_ENTRY, PAYLOAD_PA)
    if corrupt:
        blob[0] = 0xF4
    loaded = bytearray(16 * 512)
    loaded[:len(payload)] = payload
    loaded[TRAMP_PA - PAYLOAD_PA:TRAMP_PA - PAYLOAD_PA + len(blob)] = blob
    disk = bytearray(1440 * 1024)
    disk[:len(boot)] = boot
    disk[512:512 + len(loaded)] = loaded
    return bytes(disk)


def run_once(repo: Path, blob: bytearray, corrupt: bool) -> tuple[bool, bytes, int]:
    with tempfile.TemporaryDirectory(prefix="oxide-s3-resume-") as tmp_name:
        tmp = Path(tmp_name)
        payload_path = tmp / "payload.bin"
        assemble(repo, "tools/s3-resume-x86.asm", payload_path)
        boot_path = tmp / "boot.img"
        sector_path = tmp / "boot-sector.bin"
        assemble(repo, "tools/s3-resume-boot.asm", sector_path)
        boot_path.write_bytes(disk_image(sector_path.read_bytes(), blob,
                                         payload_path.read_bytes(), corrupt))
        cmd = [
            "qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", "Haswell-v4",
            "-m", "32M", "-display", "none", "-serial", "none", "-monitor", "none",
            "-no-reboot", "-debugcon", "stdio",
            "-global", "isa-debugcon.iobase=0xe9",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-drive", f"format=raw,file={boot_path},if=floppy", "-boot", "a",
        ]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=3, check=False)
            output, status = proc.stdout, proc.returncode
        except subprocess.TimeoutExpired as exc:
            output, status = exc.stdout or b"", 124
        return status == PASS_STATUS and PASS_MARKER in output, output, status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    for tool in ("qemu-system-x86_64", "nasm"):
        if shutil.which(tool) is None:
            print(f"s3-resume-gate: missing {tool}", file=sys.stderr)
            return 2
    try:
        blob = linked_blob(args.kernel)
        if args.self_test:
            passed, _, status = run_once(repo, bytearray(blob), True)
            if passed:
                print("s3-resume-gate: RED control failed (halted entry passed)", file=sys.stderr)
                return 1
            print(f"s3-resume-gate: RED control PASS (halted entry rejected, status={status})")
        passed, output, status = run_once(repo, bytearray(blob), False)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"s3-resume-gate: setup failure: {exc}", file=sys.stderr)
        return 2
    if not passed:
        sys.stderr.buffer.write(output)
        print(f"s3-resume-gate: FAIL (status={status})", file=sys.stderr)
        return 1
    print("s3-resume-gate: GREEN PASS — linked 16→32→64 blob reached its patched entry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
