#!/usr/bin/env python3
"""Acceptance harness for tests/acceptance/<name>/scenario.sh per
docs/43§5. Spawns QEMU with the disk image produced by `xtask
qemu`, parses the scenario file (`>` = send, `<` = expect, others
= comment), and reports pass / fail.

Usage:
  tools/accept.py <name> [--arch x86_64|aarch64] [--timeout SECS]

Exit code 0 = pass, 1 = fail, 2 = setup error.

Per CLAUDE.md: drives QEMU directly, no human-in-the-loop. Builds
the image via `make x86` or `make arm` first; assumes the
toolchain is already present.
"""

import argparse
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

OVMF_X86 = REPO / "vendor/firmware/ovmf-x64.fd"
OVMF_ARM = REPO / "vendor/firmware/ovmf-aarch64.fd"

FAULT_PATTERNS = (
    b"[FAULT]",
    b"panic:",
    b"PANIC:",
    b"BUG:",
    b"Unable to handle kernel",
)

ANSI_ESC = re.compile(rb"\x1b\[[0-9;]*[a-zA-Z]|\x1b[=>][0-9]?")

def strip_ansi(b: bytes) -> bytes:
    return ANSI_ESC.sub(b"", b)

def parse_scenario(path: Path):
    """Yields (kind, payload). kind in {'send','expect','comment'}."""
    for line in path.read_text().splitlines():
        if line.startswith(">"):
            yield ("send", line[1:].lstrip())
        elif line.startswith("<"):
            yield ("expect", line[1:].strip())
        else:
            yield ("comment", line)

def qemu_cmd(arch: str, image: Path) -> list[str]:
    if arch == "x86_64":
        return [
            "qemu-system-x86_64",
            "-machine", "q35,accel=tcg",
            "-cpu", "Haswell-v4",
            "-m", "256",
            "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_X86}",
            "-drive", f"format=raw,file={image}",
            "-display", "none",
            "-serial", "stdio",
            "-no-reboot",
        ]
    elif arch == "aarch64":
        return [
            "qemu-system-aarch64",
            "-machine", "virt",
            "-cpu", "cortex-a72",
            "-m", "256",
            "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_ARM}",
            "-drive", f"format=raw,file={image}",
            "-display", "none",
            "-serial", "stdio",
            "-no-reboot",
        ]
    else:
        raise SystemExit(f"unknown arch: {arch}")

def run(name: str, arch: str, timeout: int) -> int:
    scenario_dir = REPO / "tests/acceptance" / name
    scenario = scenario_dir / "scenario.sh"
    if not scenario.exists():
        print(f"accept: no scenario at {scenario}", file=sys.stderr)
        return 2
    image = REPO / f"target/oxide-{arch}.img"
    if not image.exists():
        print(f"accept: build the image first (make {('x86' if arch=='x86_64' else 'arm')})",
              file=sys.stderr)
        return 2
    if not OVMF_X86.exists() or not OVMF_ARM.exists():
        print("accept: vendor/firmware/ovmf-*.fd missing; run tools/fetch-vendor.sh",
              file=sys.stderr)
        return 2

    steps = list(parse_scenario(scenario))
    print(f"accept: {name} arch={arch} steps={len([s for s in steps if s[0]!='comment'])}")

    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        qemu_cmd(arch, image),
        stdin=slave_fd, stdout=slave_fd, stderr=subprocess.PIPE,
        close_fds=True,
    )
    os.close(slave_fd)

    buf = bytearray()
    deadline = time.time() + timeout
    sent_login_settle = False
    step_idx = 0

    try:
        while step_idx < len(steps):
            kind, payload = steps[step_idx]
            if kind == "comment":
                step_idx += 1
                continue
            if kind == "send":
                # Drain whatever's pending so the prompt is visible
                # before we type; wait briefly for login banner first
                # send.
                if not sent_login_settle:
                    end = time.time() + 5
                    while time.time() < end:
                        r, _, _ = select.select([master_fd], [], [], 0.2)
                        if r:
                            chunk = os.read(master_fd, 4096)
                            buf += chunk
                        if b"login:" in buf:
                            break
                    sent_login_settle = True
                line = (payload + "\n").encode()
                os.write(master_fd, line)
                print(f"  > {payload!r}")
                step_idx += 1
                continue
            if kind == "expect":
                while time.time() < deadline:
                    r, _, _ = select.select([master_fd], [], [], 0.5)
                    if r:
                        chunk = os.read(master_fd, 4096)
                        buf += chunk
                    clean = strip_ansi(bytes(buf))
                    for pat in FAULT_PATTERNS:
                        if pat in clean:
                            print(f"  ! FAULT: {pat.decode()} seen", file=sys.stderr)
                            return 1
                    if payload.encode() in clean:
                        print(f"  < {payload!r} OK")
                        step_idx += 1
                        break
                else:
                    print(f"  ! TIMEOUT waiting for {payload!r}", file=sys.stderr)
                    return 1
                continue
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        try: os.close(master_fd)
        except OSError: pass

    print(f"accept: {name} PASS")
    return 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name", help="acceptance scenario name (subdir of tests/acceptance/)")
    ap.add_argument("--arch", default="x86_64", choices=["x86_64", "aarch64"])
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()
    sys.exit(run(args.name, args.arch, args.timeout))

if __name__ == "__main__":
    main()
