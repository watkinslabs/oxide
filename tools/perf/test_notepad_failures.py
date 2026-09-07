"""Offline failure-path checks against the acceptance runner and emitted wrapper."""
import importlib.util
import io
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))


class _reader:
    """Stand-in for the run's console reader holding already-arrived text."""
    def __init__(self, data): self._data = data
    def text(self): return self._data.decode("utf-8", "replace")


class FailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="notepad-failures-")
        self.addCleanup(self.tmp.cleanup)
        spec = importlib.util.spec_from_file_location(
            "acceptance_failures", TOOLS / "windows-notepad-acceptance.py")
        self.runner = importlib.util.module_from_spec(spec)
        with patch("atexit.register"), patch.dict(
                "os.environ", {"OXIDE_NOTEPAD_ACCEPTANCE_DIR": self.tmp.name}):
            spec.loader.exec_module(self.runner)

    def test_fault_rejects_even_with_expected_marker_buffered(self):
        for text in (b"[BUG] broken\nready\n", b"ready\n[FAULT] broken\n"):
            with self.subTest(text=text), self.assertRaises(SystemExit), \
                 patch("sys.stderr", new=io.StringIO()):
                self.runner.wait_marker(_reader(text), "ready", time.monotonic() + 1)

    def test_clean_buffered_marker_succeeds(self):
        self.runner.wait_marker(_reader(b"ready\n"), "ready", time.monotonic() + 1)

    def test_connected_qmp_without_greeting_times_out_and_closes(self):
        path = Path(self.tmp.name) / "q.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen(1)
            conn = self.runner.wait_socket(path, time.monotonic() + 0.1, "QMP")
            with conn, server.accept()[0] as peer:
                # The production connection must retain a finite IO timeout,
                # not just bound polling for the socket pathname.
                self.assertIsNotNone(conn.gettimeout())
                self.assertLessEqual(conn.gettimeout(), 0.1)
                with self.assertRaises(TimeoutError):
                    self.runner.QmpTransactions(lambda: conn).execute("query-status")
                self.assertEqual(conn.fileno(), -1)
                peer.settimeout(1)
                self.assertEqual(peer.recv(1), b"")

    def test_expired_socket_deadline_does_not_connect(self):
        with patch.object(self.runner.socket, "socket") as connect, \
             patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            self.runner.wait_socket(Path(self.tmp.name), time.monotonic() - 1, "QMP")
        connect.assert_not_called()

    def image_environment(self, overrides):
        source = self.runner.IMAGES / "output/gnome-x86_64-root.img"
        result = subprocess.CompletedProcess([], 0, stdout="ID=oxide\n")
        with patch.dict("os.environ", overrides, clear=True), \
             patch.object(Path, "is_file", lambda path: path == source), \
             patch.object(self.runner.subprocess, "run", return_value=result) as run, \
             patch("sys.stdout", new=io.StringIO()):
            self.runner.prepare_image()
        image = next(call for call in run.call_args_list if call.args[0][0] == "cargo")
        self.assertIn("image", image.args[0])
        return image.kwargs["env"]

    def test_plain_acceptance_passes_no_host_wine_path_to_the_image(self):
        environment = self.image_environment({})
        self.assertEqual(environment["OXIDE_WINDOWS_NOTEPAD_SMOKE"], "1")
        makefile = (TOOLS.parent / "Makefile").read_text()
        # The Wine tree is packaged, not pointed at: no adapter path may reach
        # staging through the environment or the make invocation.
        for name in ("OXIDE_WINE_NTDLL", "OXIDE_WINE_WIN32U", "OXIDE_WINE_NLS", "OXIDE_WINE_RUNTIME_ROOT"):
            self.assertNotIn(name, environment)
            self.assertNotIn(name, makefile)

    def test_emitted_wrapper_reports_success_and_failure_under_errexit(self):
        source = (TOOLS / "xtask/src/rootfs_disks/windows_notepad.rs").read_text()
        script = source.split('br#"#!/bin/sh\n', 1)[1].split('"#', 1)[0]
        lines = script.splitlines()
        start = next(i for i, line in enumerate(lines)
                     if line.startswith("/usr/local/bin/windows-runtime --launch"))
        # Run the actual emitted invocation/status/exit tail. Only the executable
        # is replaced; no image, registry service or guest is started.
        tail = "\n".join(lines[start - 1:]).replace(
            "/usr/local/bin/windows-runtime --launch", "mock_runtime --launch")
        for status in (0, 7, 127):
            with self.subTest(status=status):
                result = subprocess.run(
                    ["sh", "-c", f"set -e\nmock_runtime() {{ return {status}; }}\n" + tail],
                    capture_output=True, text=True, timeout=2)
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stdout,
                                 f"[WINDOWS-NOTEPAD] runtime-exit status={status}\n")


if __name__ == "__main__":
    unittest.main()
