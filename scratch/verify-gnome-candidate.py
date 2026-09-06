"""Final GNOME-only verification of a separately built, hash-pinned image."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def wait_changed_frame(runner, qmp, uart, data, log, before, deadline, label):
    while time.monotonic() < deadline:
        path, digest = runner.screenshot(qmp, label)
        if digest != before:
            return path, digest
        runner.uart_pump(uart, data, log, min(1, max(0, deadline - time.monotonic())))
    runner.die("frame unchanged before verification deadline; inspect retained evidence")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_id")
    parser.add_argument("iso_sha256")
    args = parser.parse_args()
    if not args.build_id.replace("-", "").isalnum():
        parser.error("invalid build identifier")
    iso = ROOT / "target/builds" / args.build_id / "oxide-x86_64-grub.iso"
    if hashlib.sha256(iso.read_bytes()).hexdigest() != args.iso_sha256:
        parser.error("candidate ISO digest mismatch")
    os.environ["OXIDE_NOTEPAD_BUILD_ID"] = args.build_id
    os.environ["OXIDE_NOTEPAD_ACCEPTANCE_DIR"] = str(ROOT / "target" / (args.build_id + "-verification"))
    sys.path.insert(0, str(ROOT / "tools"))
    spec = importlib.util.spec_from_file_location("acceptance", ROOT / "tools/windows-notepad-acceptance.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    env = dict(os.environ, OXIDE_SERIAL_SHELL="1", OXIDE_QEMU_UART_SOCK=str(runner.UART),
               OXIDE_QEMU_QMP_SOCK=str(runner.QMP))
    env.pop("OXIDE_QEMU_HEADLESS", None)
    with runner.QEMU_LOG.open("wb") as output:
        runner.qemu = subprocess.Popen(
            ["cargo", "run", "--quiet", "-p", "xtask", "--", "grub", "--arch", "x86_64",
             "--smp", "1", "--id", args.build_id, "--run-existing"],
            cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=output,
            stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + runner.TIMEOUT
    qmp = runner.QmpTransactions(lambda: runner.wait_socket(runner.QMP, deadline, "QMP"))
    try:
        with runner.wait_socket(runner.UART, deadline, "UART") as uart, runner.UART_LOG.open("wb") as log:
            data = bytearray()
            runner.wait_marker(uart, data, log, "Entering running state", deadline)
            runner.uart_pump(uart, data, log, 2)
            _, before = runner.screenshot(qmp, "gnome")
            runner.keys(qmp, "meta_l")
            _, after = wait_changed_frame(runner, qmp, uart, data, log,
                                          before, deadline, "overview")
            runner.keys(qmp, "meta_l")
            wait_changed_frame(runner, qmp, uart, data, log, after, deadline, "response")
            uart.sendall(b"uname -a\n")
            runner.uart_pump(uart, data, log, 1)
            print("gnome-verification: session and changed frame captured; visual review required", flush=True)
        runner.qmp(qmp, "quit")
        runner.qemu.wait(timeout=20)
    except BaseException:
        try:
            captured = runner.qmp(qmp, "human-monitor-command", {"command-line": "info registers"})
            (runner.OUT / "failure-registers.json").write_text(json.dumps(captured, indent=2))
            runner.screenshot(qmp, "failure")
        except (OSError, ValueError, SystemExit, RuntimeError):
            pass
        raise


if __name__ == "__main__":
    main()
