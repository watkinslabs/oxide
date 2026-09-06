"""Command-scoped QMP transport; no socket or guest ownership between calls."""
import json


class QmpError(RuntimeError):
    pass


class QmpTransactions:
    """connect() supplies a socket using the caller's existing readiness deadline."""

    def __init__(self, connect):
        self.connect = connect

    @staticmethod
    def _read(stream):
        while True:
            line = stream.readline()
            if not line:
                raise QmpError("QMP disconnected before reply")
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise QmpError("QMP reply is not an object")
            if "event" not in value:
                return value

    @classmethod
    def _command(cls, conn, stream, command, arguments=None):
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        conn.sendall((json.dumps(request) + "\n").encode())
        result = cls._read(stream)
        if "error" in result:
            raise QmpError(f"QMP {command} failed: {result['error']}")
        if "return" not in result:
            raise QmpError(f"QMP {command} missing response")
        return result

    def execute(self, command, arguments=None):
        # Both the buffered reader and socket close on success and every error.
        # Never replay commands: a lost reply can follow a completed mutation.
        with self.connect() as conn, conn.makefile("rb") as stream:
            if "QMP" not in self._read(stream):
                raise QmpError("QMP greeting missing")
            self._command(conn, stream, "qmp_capabilities")
            return self._command(conn, stream, command, arguments)
