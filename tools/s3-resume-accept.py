#!/usr/bin/env python3
"""One-shot x86 ACPI S3 suspend/resume acceptance under Q35 firmware."""

import argparse
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

FAULTS = (b"[FAULT]", b"[BADSTACK]", b"panic:", b"PANIC:", b"BUG:")


class Qmp:
    def __init__(self, path: Path, deadline: float):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        while True:
            try:
                self.sock.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise TimeoutError("QMP socket never became ready")
                time.sleep(0.1)
        self.file = self.sock.makefile("rwb", buffering=0)
        greeting = self.read(deadline)
        if "QMP" not in greeting:
            raise RuntimeError("QMP greeting missing")
        self.call("qmp_capabilities", deadline)

    def read(self, deadline: float):
        self.sock.settimeout(max(0.1, deadline - time.monotonic()))
        line = self.file.readline()
        if not line:
            raise RuntimeError("QMP closed")
        return json.loads(line)

    def call(self, name: str, deadline: float):
        self.file.write(json.dumps({"execute": name}).encode() + b"\r\n")
        while True:
            message = self.read(deadline)
            if "error" in message:
                raise RuntimeError(f"QMP {name}: {message['error']}")
            if "return" in message:
                return message["return"]

    def status(self, deadline: float) -> str:
        return self.call("query-status", deadline)["status"]

    def close(self):
        self.file.close()
        self.sock.close()


def drain(proc: subprocess.Popen, log, captured: bytearray):
    if proc.stdout is None:
        return
    ready, _, _ = select.select([proc.stdout], [], [], 0.1)
    if not ready:
        return
    chunk = os.read(proc.stdout.fileno(), 65536)
    if chunk:
        captured.extend(chunk)
        log.write(chunk)
        log.flush()


def wait_for(proc, log, captured, marker: bytes, deadline: float):
    while marker not in captured:
        if any(fault in captured for fault in FAULTS):
            raise RuntimeError("kernel fault before " + marker.decode(errors="replace"))
        if proc.poll() is not None:
            raise RuntimeError(f"QEMU exited with {proc.returncode} before {marker!r}")
        if time.monotonic() >= deadline:
            raise TimeoutError("timeout waiting for " + marker.decode(errors="replace"))
        drain(proc, log, captured)


def send_slow(proc: subprocess.Popen, command: str):
    if proc.stdin is None:
        raise RuntimeError("QEMU stdin unavailable")
    proc.stdin.write(b"\n")
    proc.stdin.flush()
    time.sleep(0.5)
    data = command.encode() + b"\n"
    for at in range(0, len(data), 8):
        proc.stdin.write(data[at:at + 8])
        proc.stdin.flush()
        time.sleep(0.12)


def prepare(repo: Path):
    env = os.environ.copy()
    env["OXIDE_SERIAL_SHELL"] = "1"
    subprocess.run(["make", "qemu-x86-image"], cwd=repo, env=env, check=True)


def accept(repo: Path, timeout: int, keep_log: Path | None) -> int:
    deadline = time.monotonic() + timeout
    tmp = tempfile.TemporaryDirectory(prefix="oxide-s3-accept-")
    qmp_path = Path(tmp.name) / "qmp.sock"
    if keep_log is None:
        fd, name = tempfile.mkstemp(prefix="oxide-s3-resume-", suffix=".log")
        os.close(fd)
        log_path = Path(name)
    else:
        log_path = keep_log
    env = os.environ.copy()
    env.update({"OXIDE_SERIAL_SHELL": "1", "OXIDE_QEMU_HEADLESS": "1",
                "OXIDE_QEMU_QMP_SOCK": str(qmp_path), "OXIDE_SERIAL_LOG": "0"})
    log = log_path.open("wb")
    proc = subprocess.Popen(["make", "qemu-x86-existing", "SMP=2"], cwd=repo,
                            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, start_new_session=True)
    captured = bytearray()
    qmp = None
    try:
        qmp = Qmp(qmp_path, deadline)
        wait_for(proc, log, captured, b"Reached target basic.target", deadline)
        wait_for(proc, log, captured, b"Started debug-shell.service", deadline)
        send_slow(proc, "printf 'S3-BEFORE\\n'; cat /sys/power/mem_sleep")
        wait_for(proc, log, captured, b"S3-BEFORE", deadline)
        wait_for(proc, log, captured, b"deep", deadline)
        command = ("echo deep > /sys/power/mem_sleep; printf 'S3-ARMED\\n'; "
                   "echo mem > /sys/power/state; printf 'S3-RESUMED\\n'; "
                   "printf 'S3-SUCCESS='; cat /sys/power/suspend_stats/success")
        send_slow(proc, command)
        wait_for(proc, log, captured, b"S3-ARMED", deadline)
        while qmp.status(deadline) != "suspended":
            if time.monotonic() >= deadline:
                raise TimeoutError("QEMU never entered ACPI S3")
            drain(proc, log, captured)
            time.sleep(0.2)
        qmp.call("system_wakeup", deadline)
        wait_for(proc, log, captured, b"S3-RESUMED", deadline)
        wait_for(proc, log, captured, b"S3-SUCCESS=1", deadline)
        if any(fault in captured for fault in FAULTS):
            raise RuntimeError("kernel fault after S3 resume")
        print(f"s3-resume-accept: PASS — firmware S3 resumed through processor-state restore; log={log_path}")
        return 0
    except (OSError, RuntimeError, TimeoutError) as exc:
        print(f"s3-resume-accept: FAIL — {exc}; log={log_path}", file=sys.stderr)
        return 1
    finally:
        if qmp is not None:
            qmp.close()
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        drain(proc, log, captured)
        log.close()
        tmp.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--keep-log", type=Path)
    parser.add_argument("--run-existing", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    try:
        if not args.run_existing:
            prepare(repo)
        return accept(repo, args.timeout, args.keep_log)
    except subprocess.CalledProcessError as exc:
        print(f"s3-resume-accept: image build failed ({exc.returncode})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
