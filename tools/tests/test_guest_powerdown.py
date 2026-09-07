"""The orderly-stop request, and the shell fallback that must never impersonate it."""
import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import guest_powerdown
from notepad_qmp import QmpError


class RecordingQmp:
    """Accepts one connection, speaks QMP, records the commands it was sent."""

    def __init__(self, path, fail=False):
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.stopped = threading.Event()
        self.commands = []
        self.fail = fail
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with conn, conn.makefile("rb") as stream:
                    conn.settimeout(3)
                    conn.sendall(b'{"QMP":{"version":{},"capabilities":[]}}\r\n')
                    for line in stream:
                        command = json.loads(line)["execute"]
                        self.commands.append(command)
                        if self.fail and command != "qmp_capabilities":
                            conn.sendall(b'{"error":{"class":"GenericError","desc":"no"}}\r\n')
                        else:
                            conn.sendall(b'{"return":{}}\r\n')
            except (BrokenPipeError, ConnectionResetError, ValueError):
                pass

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(4)


class GuestPowerdownTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="guest-powerdown-")
        self.addCleanup(self.tmp.cleanup)
        self.sock = Path(self.tmp.name) / "q.sock"

    def test_request_sends_system_powerdown(self):
        server = RecordingQmp(self.sock)
        self.addCleanup(server.close)
        self.assertTrue(guest_powerdown.request_powerdown(self.sock, timeout=5))
        self.assertIn("system_powerdown", server.commands)

    def test_refused_request_is_an_error_not_a_silent_success(self):
        server = RecordingQmp(self.sock, fail=True)
        self.addCleanup(server.close)
        with self.assertRaises(QmpError):
            guest_powerdown.request_powerdown(self.sock, timeout=5)

    def test_absent_socket_gives_up_within_the_caller_timeout(self):
        with self.assertRaises(QmpError):
            guest_powerdown.request_powerdown(self.sock, timeout=0.3)

    def test_cli_reports_failure_when_there_is_nothing_to_ask(self):
        out = subprocess.run(
            [sys.executable, str(TOOLS / "guest_powerdown.py"), str(self.sock), "0.3"],
            capture_output=True, text=True)
        self.assertEqual(out.returncode, 1)
        self.assertIn("request failed", out.stderr)


class StopBootFallbackTests(unittest.TestCase):
    """boot-smoke's fallback must be visible as a kill.

    A run that killed the guest and a run whose guest powered itself off leave
    the root image in completely different states; if the harness reported them
    the same way, the damage this whole change exists to stop would be invisible
    again.
    """

    SCRIPT = TOOLS / "boot-smoke.sh"

    def source_stop_boot(self, script):
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              cwd=str(TOOLS.parent))

    def test_no_qmp_endpoint_reports_a_kill(self):
        harness = f'''
            set -u
            SMOKE_ROOT="{TOOLS.parent}"
            QEMU_PIDFILE=$(mktemp); echo $$ > "$QEMU_PIDFILE"
            PIDFILE=$(mktemp)
            QMP_SOCK=""
            SHUTDOWN_TIMEOUT=1
            kill_boot() {{ :; }}
            {self.stop_boot_body()}
            stop_boot 1
            echo "outcome=$SHUTDOWN_OUTCOME"
        '''
        out = self.source_stop_boot(harness)
        self.assertIn("outcome=killed", out.stdout, out.stderr)
        self.assertIn("shutdown=killed", out.stderr)

    def test_an_already_exited_guest_is_not_reported_as_a_shutdown(self):
        harness = f'''
            set -u
            SMOKE_ROOT="{TOOLS.parent}"
            QEMU_PIDFILE=$(mktemp)
            PIDFILE=$(mktemp)
            QMP_SOCK=""
            SHUTDOWN_TIMEOUT=1
            kill_boot() {{ :; }}
            {self.stop_boot_body()}
            stop_boot 1
            echo "outcome=$SHUTDOWN_OUTCOME"
        '''
        out = self.source_stop_boot(harness)
        self.assertIn("outcome=already-exited", out.stdout, out.stderr)

    def stop_boot_body(self):
        """Extract stop_boot from the harness so the test runs the real function."""
        text = self.SCRIPT.read_text()
        start = text.index("stop_boot() {")
        end = text.index("\n}\n", start) + len("\n}\n")
        return text[start:end]


if __name__ == "__main__":
    unittest.main()
