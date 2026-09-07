"""Cadence read-out over the guest's own trace, with the real evidence.

Positive control: `tgt-B3566` measured a 79-81 ms WM_CHAR interval while the
harness typed with QEMU's default `send-key` hold. The same read-out over a
log whose phases differ must report those phases apart rather than averaging
them into one number, or a change on either side would look like a change on
the other.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from notepad_cadence import char_timestamps, intervals_ms, render, segments, summarise  # noqa: E402


def line(seconds, message=0x102, hwnd=2):
    return f"[{seconds:.3f}] [WINDOWS-GETMESSAGE] hwnd={hwnd:016x} msg={message:016x}"


def log(*groups):
    """Phases separated by the idle pause the harness leaves between them."""
    out, clock = [], 10.0
    for step_ms, count in groups:
        for _ in range(count):
            out.append(line(clock))
            clock += step_ms / 1000
        clock += 2.0
    return "\n".join(out)


def test_only_wm_char_retrievals_are_counted():
    text = "\n".join([line(1.0, message=0x102), line(1.1, message=0x0f), line(1.2, message=0x102),
                      "[1.3] some other guest line"])
    assert char_timestamps(text) == [1.0, 1.2]


def test_phases_split_on_the_idle_pause_not_on_a_count():
    found = segments(char_timestamps(log((80, 4), (5, 4))))
    assert [len(part) for part in found] == [4, 4]


def test_the_first_interval_of_a_phase_is_not_a_cadence_sample():
    assert intervals_ms([1.0, 1.08, 1.16]) == [80.0, 80.0]


def test_each_phase_keeps_its_own_median():
    rows = summarise(log((80, 5), (5, 5), (1, 5)), ["default", "held", "immediate"])
    assert [row["characters"] for row in rows] == [5, 5, 5]
    assert [row["median_ms"] for row in rows] == [80.0, 5.0, 1.0]


def test_a_phase_that_never_typed_is_reported_not_renumbered():
    rows = summarise(log((80, 5)), ["default", "held"])
    assert rows[0]["median_ms"] == 80.0
    assert rows[1] == {"phase": "held", "characters": 0, "intervals": [], "median_ms": None}


def test_the_recorded_run_reports_the_measured_default_hold_cadence():
    """The tgt-B3566 acceptance run, typed entirely at QEMU's default hold."""
    fixture = Path(__file__).parent / "fixtures" / "cadence-b3566-getmessage.log"
    rows = summarise(fixture.read_text(), ["token"])
    assert rows[0]["characters"] == 14
    assert 74.0 <= rows[0]["median_ms"] <= 84.0


def test_render_names_every_phase():
    table = render(summarise(log((80, 3), (5, 3)), ["default", "held"]))
    assert "| default | 3 | 80.0 |" in table
    assert "| held | 3 | 5.0 |" in table


def test_the_measured_run_puts_the_interval_on_the_sender_not_the_guest():
    """One run, one guest, one control, three ways of delivering the same
    eight characters. `send-key` costs the same at a 100 ms hold and at a
    5 ms hold, so the hold is not the pacer; `input-send-event`, which is not
    queued at all, is seven times faster. A guest that took 80 ms per
    character could not have produced the third row."""
    fixture = Path(__file__).parent / "fixtures" / "cadence-b3567-phases.log"
    rows = summarise(fixture.read_text(), ["default hold", "short hold", "immediate", "token"])
    assert [row["characters"] for row in rows] == [9, 9, 9, 14]
    assert 70.0 <= rows[0]["median_ms"] <= 85.0
    assert abs(rows[0]["median_ms"] - rows[1]["median_ms"]) < 10.0
    assert rows[2]["median_ms"] < rows[1]["median_ms"] / 4
