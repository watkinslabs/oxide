"""Per-character typing cadence, read out of the guest's own trace.

The interval between characters can be set on either side of the wire. QEMU's
`send-key` delays the key-up by `hold-time`, which defaults to 100 ms, and the
input queue is serial, so a harness that sends one `send-key` per character
paces the guest rather than measuring it: the QMP command itself returns in
well under a millisecond. The only way to tell the two apart is to type the
same number of characters several ways in one run and compare the timestamps
the guest stamps on its own message retrievals.

Phases are separated by a deliberate idle gap, so segmentation is by gap and
not by a count that a stray retrieval would shift.
"""
import re
import statistics

# WM_CHAR. The trace carries the message number, not the character.
WM_CHAR = 0x102
# Idle the harness leaves between typing phases, and the threshold that
# separates them. The threshold sits well above any plausible per-character
# interval and well below the pause.
PHASE_PAUSE_SECONDS = 1.5
PHASE_GAP_SECONDS = 0.5

LINE = re.compile(r"^\[\s*(\d+\.\d+)\]\s+\[WINDOWS-GETMESSAGE\]\s+hwnd=[0-9a-f]+\s+msg=([0-9a-f]+)\s*$")


def char_timestamps(text):
    """Guest monotonic seconds at which each WM_CHAR was retrieved."""
    out = []
    for line in text.splitlines():
        found = LINE.match(line.strip())
        if found and int(found.group(2), 16) == WM_CHAR:
            out.append(float(found.group(1)))
    return out


def segments(stamps, gap=PHASE_GAP_SECONDS):
    """Split retrievals into typing phases on the idle gap between them."""
    out = []
    for stamp in stamps:
        if out and stamp - out[-1][-1] <= gap:
            out[-1].append(stamp)
        else:
            out.append([stamp])
    return out


def intervals_ms(segment):
    """Per-character intervals inside one phase, in milliseconds.

    The first interval of a phase spans the idle pause plus whatever the
    phase's first keystroke had to wait for, so it is not a cadence sample
    and the caller never sees it.
    """
    return [round((b - a) * 1000, 1) for a, b in zip(segment, segment[1:])]


def summarise(text, labels):
    """One row per typing phase, in the order the phases were typed.

    A phase that produced too few retrievals to have a cadence is reported
    with its count and no median rather than dropped: a missing phase is a
    result about the guest, not a reason to renumber the rest.
    """
    found = segments(char_timestamps(text))
    rows = []
    for index, label in enumerate(labels):
        segment = found[index] if index < len(found) else []
        steps = intervals_ms(segment)
        rows.append({
            "phase": label,
            "characters": len(segment),
            "intervals": steps,
            "median_ms": statistics.median(steps) if steps else None,
        })
    return rows


def render(rows):
    """Fixed-width table of the cadence rows, for the run's evidence."""
    lines = ["| phase | chars | median ms | intervals ms |", "|---|---|---|---|"]
    for row in rows:
        median = "-" if row["median_ms"] is None else f"{row['median_ms']:.1f}"
        lines.append(f"| {row['phase']} | {row['characters']} | {median} | {'/'.join(str(v) for v in row['intervals'])} |")
    return "\n".join(lines)
