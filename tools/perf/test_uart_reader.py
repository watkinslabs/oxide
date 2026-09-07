"""The guest console must be captured for the whole run, not only while a
marker wait is outstanding.

Three acceptance runs concluded "no input messages reached the kernel" from a
log that stopped ~1s of guest time after the last awaited marker and ~20s
before the click was injected: the console was read only inside the marker
wait, so the window the run exists to evidence was never captured.
"""
import io
import socket
import sys
import time
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

from uart_reader import UartReader


class _Log(io.BytesIO):
    def flush(self): pass


def _drain(reader, needle, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if needle in reader.text():
            return True
        time.sleep(0.02)
    return False


class UartReaderTests(unittest.TestCase):
    def setUp(self):
        self.host, self.guest = socket.socketpair()
        self.addCleanup(self.host.close)
        self.addCleanup(self.guest.close)
        self.log = _Log()
        self.reader = UartReader(self.host, self.log)
        self.addCleanup(self.reader.stop)

    def test_console_written_while_nothing_waits_is_still_captured(self):
        # Nothing in this test asks the reader for anything until after the
        # guest has finished writing: a reader that only runs inside a wait
        # captures none of this.
        self.guest.sendall(b"[WINDOWS-MESSAGE-CALL] msg=0000000000000201\n")
        time.sleep(0.5)
        self.assertTrue(_drain(self.reader, "msg=0000000000000201"))
        self.assertIn(b"msg=0000000000000201", self.log.getvalue())

    def test_capture_spans_a_gap_with_no_reader_call(self):
        self.guest.sendall(b"first\n")
        self.assertTrue(_drain(self.reader, "first"))
        time.sleep(0.4)
        self.guest.sendall(b"second\n")
        time.sleep(0.4)
        self.guest.sendall(b"third\n")
        self.assertTrue(_drain(self.reader, "third"))
        self.assertIn("second", self.reader.text())

    def test_stop_drains_what_the_socket_still_holds(self):
        # The pump exits on the stop flag, so anything written between its
        # last poll and the stop stays in the socket. That is the tail of the
        # acceptance run -- the click and the typing -- and it must reach the
        # log rather than be dropped with the connection.
        self.reader._stop.set()
        self.reader._thread.join(timeout=2)
        self.guest.sendall(b"[WINDOWS-GETMESSAGE] msg=0000000000000201\n")
        self.reader.stop()
        self.assertIn(b"msg=0000000000000201", self.log.getvalue())

    def test_stop_is_idempotent_and_leaves_the_log_flushed(self):
        self.guest.sendall(b"done\n")
        self.assertTrue(_drain(self.reader, "done"))
        self.reader.stop()
        self.reader.stop()
        self.assertIn(b"done", self.log.getvalue())


if __name__ == "__main__":
    unittest.main()
