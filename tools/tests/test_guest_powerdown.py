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

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="stop-boot-qmp-")
        self.addCleanup(self.tmp.cleanup)
        self.sock = Path(self.tmp.name) / "q.sock"

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

    def run_stop_boot(self, *, qmp_sock, log_text, grace=1, budget=4, guest_alive=True):
        """Drive the real stop_boot against a live sleeper as the guest."""
        with tempfile.TemporaryDirectory(prefix="stop-boot-") as tmp:
            log = Path(tmp) / "serial.log"
            log.write_text(log_text)
            harness = f'''
                set -u
                SMOKE_ROOT="{TOOLS.parent}"
                LOG="{log}"
                PIDFILE=$(mktemp)
                QEMU_PIDFILE=$(mktemp)
                QMP_SOCK="{qmp_sock}"
                SHUTDOWN_TIMEOUT={budget}
                SHUTDOWN_GRACE={grace}
                SHUTDOWN_MARKER="Powering off|systemd-shutdown"
                killed=0
                kill_boot() {{ killed=1; }}
                if [ {int(guest_alive)} -eq 1 ]; then
                    sleep 30 & guest=$!; echo $guest > "$QEMU_PIDFILE"
                fi
                {self.stop_boot_body()}
                stop_boot {budget}
                [ -n "${{guest:-}}" ] && kill "$guest" 2>/dev/null
                echo "outcome=$SHUTDOWN_OUTCOME killed=$killed"
            '''
            return self.source_stop_boot(harness)

    def test_a_guest_that_ignores_the_button_is_killed_at_the_grace_not_the_budget(self):
        server = RecordingQmp(self.sock)
        self.addCleanup(server.close)
        out = self.run_stop_boot(qmp_sock=self.sock, log_text="Reached target basic.target\n")
        self.assertIn("outcome=killed killed=1", out.stdout, out.stderr)
        self.assertIn("IGNORED the power button", out.stderr)
        self.assertIn("system_powerdown", server.commands)

    def test_a_guest_that_started_shutting_down_gets_the_whole_budget(self):
        server = RecordingQmp(self.sock)
        self.addCleanup(server.close)
        out = self.run_stop_boot(qmp_sock=self.sock,
                                 log_text="systemd-shutdown[1]: Powering off.\n")
        self.assertIn("outcome=killed killed=1", out.stdout, out.stderr)
        self.assertIn("began shutting down but did not finish", out.stderr)
        self.assertNotIn("IGNORED", out.stderr)

    def stop_boot_body(self):
        """Extract stop_boot from the harness so the test runs the real function."""
        text = self.SCRIPT.read_text()
        start = text.index("stop_boot() {")
        end = text.index("\n}\n", start) + len("\n}\n")
        return text[start:end]


if __name__ == "__main__":
    unittest.main()
