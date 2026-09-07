"""A marker cannot arrive from a guest that has exited.

Waiting out the whole run deadline to report a missing marker hides which of
the two happened: a slow guest, or one that is no longer there. Each case
below has its opposite in the same file, so a check that always fires (or
never fires) cannot pass.
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "acceptance", Path(__file__).resolve().parents[1] / "windows-notepad-acceptance.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class Reader:
    """A console that never produces the marker."""

    def text(self):
        return "boot lines that do not contain what is awaited"


class Guest:
    def __init__(self, status):
        self.returncode = status
        self._status = status

    def poll(self):
        return self._status


def test_a_dead_guest_ends_the_wait_at_once():
    started = time.monotonic()
    with pytest.raises(SystemExit):
        acceptance.wait_marker(Reader(), "marker", started + 30, Guest(0))
    assert time.monotonic() - started < 5


def test_a_live_guest_waits_for_its_deadline():
    started = time.monotonic()
    with pytest.raises(SystemExit):
        acceptance.wait_marker(Reader(), "marker", started + 0.3, Guest(None))
    assert time.monotonic() - started >= 0.3


def test_a_caller_with_no_guest_still_waits_for_its_deadline():
    started = time.monotonic()
    with pytest.raises(SystemExit):
        acceptance.wait_marker(Reader(), "marker", started + 0.3, None)
    assert time.monotonic() - started >= 0.3
