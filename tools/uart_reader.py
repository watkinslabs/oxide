"""Continuous guest-console reader for the acceptance run.

Reading the console only while a marker wait is outstanding leaves it unread
across activation, the click, the typing and the screenshots -- exactly the
window whose evidence the run exists to produce. What the guest prints then
stays in the socket buffer and is lost, so a grep of the retained log reports
an absence the log was never in a position to show.
"""
import select
import threading


class UartReader:
    """Drain a guest console socket into a buffer and its log for the whole run."""

    POLL_SECONDS = 0.25
    CHUNK = 65536

    def __init__(self, conn, log):
        self._conn = conn
        self._log = log
        self._buffer = bytearray()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._pump, name="uart-reader", daemon=True)
        self._thread.start()

    def _pump(self):
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([self._conn], [], [], self.POLL_SECONDS)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                data = self._conn.recv(self.CHUNK)
            except OSError:
                return
            if not data:
                return
            with self._lock:
                self._buffer.extend(data)
                self._log.write(data)
                self._log.flush()

    def text(self):
        """Everything the guest has printed so far, decoded lossily."""
        with self._lock:
            return self._buffer.decode("utf-8", "replace")

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
