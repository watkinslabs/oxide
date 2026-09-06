"""Single-client QMP listener and real acceptance UART wait, without a guest."""
import importlib.util
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
from notepad_qmp import QmpError, QmpTransactions


class SingleClientServer:
    def __init__(self, path):
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.path = path
        self.stopped = threading.Event()
        self.commands = []
        self.errors = []
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def connect(self):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(1)
        try:
            conn.connect(str(self.path))
        except BaseException:
            conn.close()
            raise
        return conn

    def run(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with conn, conn.makefile("rb") as stream:
                    conn.settimeout(3)
                    # Fragment greeting; event + reply share one transport write below.
                    conn.sendall(b'{"QMP":')
                    conn.sendall(b'{"version":{},"capabilities":[]}}\r\n')
                    negotiated = False
                    for line in stream:
                        request = json.loads(line)
                        cmd = request["execute"]
                        self.commands.append(request)
                        if not negotiated and cmd != "qmp_capabilities":
                            raise AssertionError("missing per-connection capability negotiation")
                        negotiated = True
                        if cmd == "disconnect":
                            break
                        result = ({"error": {"class": "GenericError", "desc": "injected"}}
                                  if cmd == "fail" else {"return": {}})
                        if cmd == "malformed":
                            conn.sendall(b'not-json\n')
                        else:
                            conn.sendall(b'{"event":"TEST"}\r\n' +
                                         json.dumps(result).encode() + b'\r\n')
            except (BrokenPipeError, ConnectionResetError):
                pass
            except BaseException as error:
                self.errors.append(error)

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(4)
        if self.thread.is_alive():
            raise AssertionError("QMP connection leaked")
        if self.errors:
            raise self.errors[0]


class QmpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="notepad-qmp-")
        self.addCleanup(self.tmp.cleanup)
        self.server = SingleClientServer(Path(self.tmp.name) / "q.sock")
        self.addCleanup(self.server.close)
        self.client = QmpTransactions(self.server.connect)

    def test_each_command_releases_listener_and_negotiates(self):
        args = {"keys": [{"type": "qcode", "data": "a"}]}
        self.assertEqual(self.client.execute("send-key", args), {"return": {}})
        QmpTransactions(self.server.connect).execute("query-status")
        self.assertEqual([r["execute"] for r in self.server.commands],
                         ["qmp_capabilities", "send-key", "qmp_capabilities", "query-status"])
        self.assertEqual(self.server.commands[1]["arguments"], args)

    def test_errors_close_connection_without_replaying(self):
        for command, error in [("fail", QmpError), ("disconnect", QmpError),
                               ("malformed", ValueError)]:
            with self.subTest(command=command):
                with self.assertRaises(error):
                    self.client.execute(command)
                QmpTransactions(self.server.connect).execute("query-status")
                self.assertEqual(sum(r["execute"] == command for r in self.server.commands), 1)

    def test_other_client_completes_during_real_serial_wait(self):
        # Import without running main or registering guest cleanup in this test process.
        spec = importlib.util.spec_from_file_location("acceptance_qmp_test", TOOLS / "windows-notepad-acceptance.py")
        runner = importlib.util.module_from_spec(spec)
        with patch("atexit.register"), patch.dict("os.environ", {"OXIDE_NOTEPAD_ACCEPTANCE_DIR": self.tmp.name}):
            spec.loader.exec_module(runner)
        uart, guest = socket.socketpair()
        self.addCleanup(uart.close)
        self.addCleanup(guest.close)
        waiting = threading.Event()
        finished = threading.Event()
        errors = []
        pump = runner.uart_pump
        wait_socket = runner.wait_socket

        class SerialWaitComplete(Exception):
            pass

        def connect(path, deadline, label):
            if path == runner.UART:
                return uart
            if path == runner.QMP:
                return self.server.connect()
            return wait_socket(path, deadline, label)

        def launch(serial, buffer, log, transport, deadline):
            # main constructs the production transport; no QMP session is opened
            # until this command. Keep the actual parent qmp and UART wait paths.
            self.assertEqual(self.server.commands, [])
            runner.qmp(transport, "query-status")
            runner.wait_marker(serial, buffer, log, "desktop-ready", time.monotonic() + 5)
            raise SerialWaitComplete()

        def announce_wait(*args):
            waiting.set()
            return pump(*args)

        def wait_serial():
            try:
                runner.main()
            except SerialWaitComplete:
                pass
            except BaseException as error:
                errors.append(error)
            finally:
                finished.set()

        with patch.object(runner, "uart_pump", side_effect=announce_wait), \
             patch.object(runner, "QMP", Path(self.tmp.name) / "runner-qmp.sock"), \
             patch.object(runner, "wait_socket", side_effect=connect), \
             patch.object(runner, "prepare_image"), \
             patch.object(runner.subprocess, "Popen"), \
             patch.object(runner, "launch_on_desktop", side_effect=launch):
            waiter = threading.Thread(target=wait_serial)
            waiter.start()
            try:
                self.assertTrue(waiting.wait(1))
                # A connected backlog socket is insufficient: greeting, negotiation,
                # and response must finish while the acceptance wait is still pending.
                other = QmpTransactions(self.server.connect)
                self.assertEqual(other.execute("query-status"), {"return": {}})
                self.assertFalse(finished.is_set())
            finally:
                guest.sendall(b"desktop-ready\n")
                waiter.join(6)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(errors, [])

    def test_acceptance_image_env_supplies_source_owned_wine_adapters(self):
        spec = importlib.util.spec_from_file_location("acceptance_env_test", TOOLS / "windows-notepad-acceptance.py")
        runner = importlib.util.module_from_spec(spec)
        with patch("atexit.register"), patch.dict("os.environ", {}, clear=True):
            spec.loader.exec_module(runner)
        env = runner.image_build_env({})
        self.assertEqual(env["OXIDE_WINE_NTDLL"], str(runner.DEFAULT_WINE_NTDLL))
        self.assertEqual(env["OXIDE_WINE_WIN32U"], str(runner.DEFAULT_WINE_WIN32U))
        custom = {"OXIDE_WINE_NTDLL": "/tmp/custom-ntdll.so", "OXIDE_WINE_WIN32U": "/tmp/custom-win32u.so"}
        self.assertEqual(runner.image_build_env(custom)["OXIDE_WINE_NTDLL"], custom["OXIDE_WINE_NTDLL"])
        self.assertEqual(runner.image_build_env(custom)["OXIDE_WINE_WIN32U"], custom["OXIDE_WINE_WIN32U"])


if __name__ == "__main__":
    unittest.main()
