#!/usr/bin/env python3
"""Ask a running guest to power itself off, the way a power-button press does.

QMP `system_powerdown` raises the machine's power-button event; systemd turns
that into an orderly shutdown that unmounts the root filesystem. Killing QEMU
instead leaves whatever was in flight on the disk, which is how a boot harness
accumulates permanent filesystem damage across runs.

This module only *requests* the shutdown. Waiting for the guest to go away and
deciding when to give up belong to the caller that owns the QEMU process, so a
timeout is a caller policy rather than a hidden one here.
"""
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from notepad_qmp import QmpError, QmpTransactions   # noqa: E402

POWERDOWN = "system_powerdown"


def connector(sock_path, deadline):
    """Return a connect() for QmpTransactions that retries until `deadline`."""
    def connect():
        last = None
        while True:
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                conn.settimeout(max(0.001, min(10.0, deadline - time.monotonic())))
                conn.connect(str(sock_path))
                return conn
            except OSError as exc:
                last = exc
                conn.close()
                if time.monotonic() >= deadline:
                    raise QmpError(f"QMP socket {sock_path} unreachable: {last}")
                time.sleep(0.1)
    return connect


def request_powerdown(sock_path, timeout=5.0):
    """Raise the guest's power button. True if QEMU accepted the request.

    Acceptance is not proof of shutdown: an unattended guest, or one whose
    userspace is already wedged, ignores the button. The caller still has to
    watch the process exit.
    """
    deadline = time.monotonic() + timeout
    QmpTransactions(connector(sock_path, deadline)).execute(POWERDOWN)
    return True


def main(argv):
    if not 2 <= len(argv) <= 3:
        print("usage: guest_powerdown.py <qmp-socket> [timeout-seconds]", file=sys.stderr)
        return 2
    timeout = float(argv[2]) if len(argv) == 3 else 5.0
    try:
        request_powerdown(argv[1], timeout)
    except (QmpError, OSError, ValueError) as exc:
        print(f"guest_powerdown: request failed: {exc}", file=sys.stderr)
        return 1
    print(f"guest_powerdown: {POWERDOWN} accepted by QEMU")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
