"""Hosted tests for the post-fault UART drain.

Positive control: `test_stops_when_the_guest_goes_quiet` and
`test_captures_a_report_that_arrives_in_pieces` are inverses -- a drain
that returned immediately fails the second, and a drain that never
returned fails the first and `test_capped_when_the_guest_never_stops`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from notepad_fault_drain import drain  # noqa: E402


class Fake:
    """Scripted pump: one entry per call, each the byte count it captured."""

    def __init__(self, counts, slice_seconds=0.25):
        self.counts = list(counts)
        self.slice = slice_seconds
        self.now = 0.0
        self.calls = 0

    def clock(self):
        return self.now

    def pump(self):
        self.calls += 1
        self.now += self.slice
        return self.counts.pop(0) if self.counts else 0


def test_stops_when_the_guest_goes_quiet():
    fake = Fake([0, 0, 0, 0, 0, 0, 0, 0])
    assert drain(fake.pump, fake.clock) == 0
    # 1.0s of quiet at 0.25s per slice.
    assert fake.calls == 4


def test_captures_a_report_that_arrives_in_pieces():
    # Four oops lines, each landing after a gap shorter than the quiet
    # window, then silence.
    fake = Fake([64, 0, 72, 0, 0, 96, 0, 0, 0, 0, 0])
    assert drain(fake.pump, fake.clock) == 64 + 72 + 96


def test_capped_when_the_guest_never_stops():
    fake = Fake([16] * 1000)
    drain(fake.pump, fake.clock)
    assert fake.calls == 20  # 5.0s cap at 0.25s per slice


def test_a_silent_guest_is_not_waited_on_beyond_the_quiet_window():
    fake = Fake([], slice_seconds=1.0)
    assert drain(fake.pump, fake.clock) == 0
    assert fake.calls == 1
