"""Per-run screenshot evidence; clocks sampled at successful QMP completion.

Schema v1: event=screenshot, run_id/label/path strings, sha256=64 lowercase
hex digits, command_completed_monotonic_ns and command_completed_unix_ns
integer host-clock readings. The two clocks are sampled sequentially.
Timestamps describe command completion, not guest render onset or readiness.
"""
import json
import os
from pathlib import Path
import re
import time


def screenshot_completed():
    return time.monotonic_ns(), time.time_ns()


def record_screenshot(journal, run_id, label, path, sha256, completed):
    if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise ValueError("screenshot evidence requires full SHA-256")
    monotonic_ns, unix_ns = completed
    if type(monotonic_ns) is not int or type(unix_ns) is not int:
        raise ValueError("screenshot evidence requires integer nanoseconds")
    record = dict(schema_version=1, event="screenshot", run_id=str(run_id),
                  label=str(label), path=str(Path(path).resolve()), sha256=sha256,
                  command_completed_monotonic_ns=monotonic_ns,
                  command_completed_unix_ns=unix_ns)
    journal = Path(journal)
    # A successful return means record data and its directory entry were synced.
    # Fail visibly rather than claim durable evidence when either sync fails.
    with journal.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(journal.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return record
