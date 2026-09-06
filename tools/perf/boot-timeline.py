#!/usr/bin/env python3
"""Report recorded boot milestones and unit durations without launching a VM.

Unit intervals overlap and must not be summed or called a critical chain.
GNOME's running-state marker is distinct from systemd's graphical target;
neither alone proves that a frame was displayed or input was accepted.
"""
import argparse
import json
import re
from pathlib import Path

STAMP = re.compile(r"\[(\d+\.\d+)\]\s*(.*)")
UNIT = re.compile(r"systemd\[(\d+)\]: (Starting|Started|Finished|Failed to start) (\S+) -")
MARKERS = {
    "root_mounted": "[ROOT] ext4 at /: ok",
    "system_manager": "systemd[1]: systemd ",
    "units_queued": "Queued start job for default target",
    "basic_target": "Reached target basic.target",
    "graphical_target": "Reached target graphical.target",
    "system_startup_finished": "systemd[1]: Startup finished in",
    "shell_starting": "Running GNOME Shell",
    "display_named": "Using Wayland display name",
    "session_running": "Entering running state",
    "shell_started": "GNOME Shell started at",
}


def parse(text):
    milestones, pending, durations, errors = {}, {}, [], []
    block = None
    last_stamp = -1.0
    for line in text.splitlines():
        match = STAMP.search(line)
        if not match:
            continue
        stamp, message = float(match[1]), match[2]
        if stamp < last_stamp - 1:
            raise ValueError("timestamps reset: provide one boot per log")
        last_stamp = max(last_stamp, stamp)
        for name, marker in MARKERS.items():
            if marker in message:
                milestones.setdefault(name, stamp)
        unit = UNIT.search(message)
        if unit:
            manager, event, name = unit.groups()
            key = (manager, name)
            if event == "Starting":
                pending[key] = stamp
            elif key in pending:
                start = pending.pop(key)
                durations.append(dict(manager=manager, unit=name, start=start,
                                      end=stamp, seconds=round(stamp - start, 3), result=event))
        sample = re.search(r"\[BLK-RESUME\] cnt=(\d+) avg_ns=(\d+) last_ns=(\d+)", message)
        if sample:
            block = dict(time=stamp, count=int(sample[1]), average_ms=int(sample[2]) / 1e6)
        if re.search(r"Timeout was reached|timed out|segfault at|bus error|Kernel panic", message):
            errors.append(dict(time=stamp, message=message))
    return dict(milestones=milestones, units=sorted(durations, key=lambda item: -item["seconds"]),
                unfinished=[dict(manager=manager, unit=name, start=start)
                            for (manager, name), start in pending.items()],
                block_completion_to_collection=block, errors=errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    reports = []
    for path in args.logs:
        try:
            reports.append(dict(log=str(path), **parse(path.read_text(errors="replace"))))
        except (OSError, ValueError) as error:
            parser.error(f"{path}: {error}")
    if args.json:
        print(json.dumps(reports, indent=2))
        return
    for report in reports:
        print(report["log"])
        for name in MARKERS:
            stamp = report["milestones"].get(name)
            print(f"  {name:22s} {stamp if stamp is not None else 'not observed'}")
        print("  Longest observed unit intervals (overlap; not a critical chain):")
        for unit in report["units"][:10]:
            print(f"    {unit['seconds']:8.3f}s  {unit['unit']} ({unit['result']})")
        if report["block_completion_to_collection"]:
            block = report["block_completion_to_collection"]
            print(f"  Block completion-to-collection: {block['average_ms']:.3f}ms average, {block['count']} requests")
            print("    Includes time before an async caller waits; does not measure device latency.")
        print(f"  Recorded errors/timeouts: {len(report['errors'])}; unfinished unit starts: {len(report['unfinished'])}")


if __name__ == "__main__":
    main()
