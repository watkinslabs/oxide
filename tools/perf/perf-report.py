#!/usr/bin/env python3
"""Compare this kernel's measured syscall and fault costs against the host Linux.

Both sides are MEASURED, never quoted. The oxide side is parsed from a boot
serial log carrying [SYSCOST] and [FAULTCOST]; the Linux side is the native
benchmark in tools/perf/linux-baseline.c run on the host kernel.

  make perf-report                 # build, boot, measure, compare
  tools/perf/perf-report.py --log <serial.log> [--baseline <tsv>]

The two sides are not identical workloads and the report says so: oxide's
figure is the average over every call a real desktop boot made, the host's is
a tight loop over one shape of the same call. Treat a ratio as an order of
magnitude, not a benchmark score.
"""
import argparse
import re
import subprocess
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from pathlib import Path

import chart

HERE = Path(__file__).resolve().parent

# Syscall slot -> (display name, host baseline row, calls per baseline iteration).
# A baseline row that times a PAIR is divided by the number of calls it makes.
SYSCALLS = {
    0:   ("read",       "read_4k",             1),
    3:   ("close",      "close",               1),
    9:   ("mmap",       "mmap+munmap_64k",     2),
    10:  ("mprotect",   "mprotect_64k",        2),
    11:  ("munmap",     "mmap+munmap_64k",     2),
    18:  ("pwrite64",   "pwrite_4k",           1),
    28:  ("madvise",    "madvise_dontneed_64k",1),
    45:  ("recvfrom",   "sendmsg+recvmsg_256", 2),
    46:  ("sendmsg",    "sendmsg+recvmsg_256", 2),
    47:  ("recvmsg",    "sendmsg+recvmsg_256", 2),
    257: ("openat",     "openat+close",        2),
    262: ("newfstatat", "fstatat",             1),
    307: ("sendmmsg",   "sendmsg+recvmsg_256", 2),
}

# Measured but deliberately NOT compared. `writev` in a desktop boot is
# overwhelmingly console output: the write reaches the VT, and fbcon scrolls by
# copying the whole framebuffer (`copy_within` over ~3 MB at 1024x768x4), which
# is what the reference's unaccelerated fbcon does too. Comparing that against a
# host loop writing to /dev/null said 2600x and meant nothing. Give it a host
# baseline that scrolls a framebuffer, or leave it out of the ratio.
UNCOMPARED = {
    20: ("writev", "console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null"),
}

FAULTS = {
    "wr-absent": ("write fault, page absent", "fault_anon_write", 1),
}


def run_baseline(binary: Path, tsv: Path | None) -> dict[str, int]:
    if tsv and tsv.exists():
        text = tsv.read_text()
    else:
        src = HERE / "linux-baseline.c"
        exe = Path("/tmp/oxide-linux-baseline")
        subprocess.run(["gcc", "-O2", "-o", str(exe), str(src)], check=True)
        text = subprocess.run([str(exe), "/tmp"], check=True,
                              capture_output=True, text=True).stdout
        if tsv:
            tsv.write_text(text)
    out = {}
    for line in text.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) == 4:
            out[parts[0]] = int(parts[3])
    return out


def parse_oxide(log: Path):
    """Last [SYSCOST] block and last [FAULTCOST] block in the log."""
    sysrows, faultrows, totals = {}, {}, {}
    text = log.read_text(errors="replace")
    for m in re.finditer(r"\[SYSCOST\] all-tasks cpu_calls=(\d+) cpu_total_ms=(\d+) cpu_avg_ns=(\d+)", text):
        totals["calls"], totals["total_ms"], totals["avg_ns"] = (int(g) for g in m.groups())
    for m in re.finditer(r"nr=(\d+) cpu_cnt=(\d+) cpu_ms=(\d+) cpu_avg_ns=(\d+)", text):
        nr, cnt, ms, avg = (int(g) for g in m.groups())
        # The kernel emits cumulative checkpoints and only prints the current
        # top rows. Keep the newest cumulative sample seen for each syscall so
        # a row that falls out of the final top-N dump is not lost.
        if nr not in sysrows or cnt >= sysrows[nr][0]:
            sysrows[nr] = (cnt, ms, avg)
    for m in re.finditer(r"  (rd-absent|wr-absent|rd-prot|wr-prot) cnt=(\d+) ms=(\d+) avg_ns=(\d+)", text):
        key = m.group(1)
        row = (int(m.group(2)), int(m.group(3)), int(m.group(4)))
        if key not in faultrows or row[0] >= faultrows[key][0]: faultrows[key] = row
    blk = {}
    for m in re.finditer(r"  blk-(read|write|flush|other) cnt=(\d+) ms=(\d+) avg_ns=(\d+)", text):
        key = m.group(1)
        row = (int(m.group(2)), int(m.group(3)), int(m.group(4)))
        if key not in blk or row[0] >= blk[key][0]: blk[key] = row
    return totals, sysrows, faultrows, blk


# How far a row may drift above its recorded ratio before the gate calls it a
# regression. The report's own footer measures the guest-side spread at tens of
# percent, so anything tighter fails on noise.
RATCHET_TOLERANCE = 1.6


def load_ratios(path: Path) -> dict[str, float]:
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, _, value = line.partition("\t")
        try:
            out[name] = float(value)
        except ValueError:
            continue
    return out


def save_ratios(path: Path, ratios: dict[str, float]) -> None:
    body = ["# Per-operation cost relative to the host kernel, as measured by",
            "# `make perf-report`. The gate holds each row to its value here.",
            "# Lower it with `perf-report.py --accept` after a run that improves one;",
            "# raising a number by hand is how a ratchet stops being a ratchet."]
    body += [f"{name}\t{ratio:.1f}" for name, ratio in sorted(ratios.items())]
    path.write_text("\n".join(body) + "\n")


def bar(ratio: float, width: int = 24) -> str:
    if ratio <= 1:
        return "|"
    filled = min(width, int(round(width * min(ratio, 100) / 100)))
    return "#" * max(1, filled)


def verdict(ratio: float) -> str:
    if ratio < 2:   return "ok"
    if ratio < 5:   return "slow"
    if ratio < 20:  return "BAD"
    return "SEVERE"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True, type=Path, help="boot serial log with [SYSCOST]/[FAULTCOST]")
    ap.add_argument("--baseline", type=Path, default=Path("/tmp/oxide-linux-baseline.tsv"))
    ap.add_argument("--markdown", type=Path, help="also write the report here")
    ap.add_argument("--html", type=Path, help="also write a self-contained chart here")
    ap.add_argument("--baseline-ratios", type=Path,
                    default=Path(__file__).resolve().parent / "ratios.tsv",
                    help="per-operation ratios this tree is held to")
    ap.add_argument("--accept", action="store_true",
                    help="rewrite the ratio baseline from this run (only ever downward)")
    args = ap.parse_args()

    if not args.log.exists():
        print(f"perf-report: no serial log at {args.log}", file=sys.stderr)
        return 2
    host = run_baseline(HERE, args.baseline)
    totals, sysrows, faultrows, blk = parse_oxide(args.log)
    if not sysrows and not faultrows:
        print("perf-report: the log carries no profiler output — boot with "
              "FEATURES=debug-syscost,debug-faultcost", file=sys.stderr)
        return 2

    lines = []
    def emit(s=""):
        lines.append(s)
        print(s)

    emit("# Syscall and fault cost vs the host Linux kernel")
    emit()
    emit(f"oxide: {args.log}")
    if totals:
        emit(f"boot totals: {totals['calls']} syscalls, {totals['total_ms']} ms on CPU, "
             f"{totals['avg_ns']} ns average")
    emit()
    emit("| operation | oxide ns | linux ns | ratio | | verdict |")
    emit("|---|---:|---:|---:|---|---|")

    rows = []
    for nr, (name, hostkey, per_iter) in SYSCALLS.items():
        if nr not in sysrows or hostkey not in host:
            continue
        ours = sysrows[nr][2]
        theirs = max(1, host[hostkey] // per_iter)
        rows.append((ours / theirs, name, ours, theirs))
    for key, (name, hostkey, per_iter) in FAULTS.items():
        if key not in faultrows or hostkey not in host:
            continue
        ours = faultrows[key][2]
        theirs = max(1, host[hostkey] // per_iter)
        rows.append((ours / theirs, name, ours, theirs))

    for ratio, name, ours, theirs in sorted(rows, reverse=True):
        emit(f"| {name} | {ours:,} | {theirs:,} | {ratio:.0f}x | {bar(ratio)} | {verdict(ratio)} |")

    if any(nr in sysrows for nr in UNCOMPARED):
        emit()
        emit("## Measured, not compared")
        emit()
        emit("| operation | oxide ns | why no ratio |")
        emit("|---|---:|---|")
        for nr, (name, why) in UNCOMPARED.items():
            if nr in sysrows:
                emit(f"| {name} | {sysrows[nr][2]:,} | {why} |")

    if blk:
        emit()
        emit("## Block device")
        emit()
        emit("| op | count | total ms | avg |")
        emit("|---|---:|---:|---:|")
        for op in ("read", "write", "flush", "other"):
            if op in blk:
                cnt, ms, avg = blk[op]
                emit(f"| {op} | {cnt:,} | {ms:,} | {avg/1000:.1f} us |")

    emit()
    emit("Both sides are measured. The host figure is a tight loop over one shape "
         "of the call; the oxide figure is the average over every such call a real "
         "desktop boot made. Read a ratio as an order of magnitude, not a score.")
    emit()
    emit("Run-to-run variance on the oxide side is large — the boot does not make "
         "the same mix of calls twice, and the socket rows swing by tens of percent "
         "between runs. A change is only demonstrated here when it moves a row by "
         "more than about half, or moves it across a verdict band. Anything smaller "
         "needs repeated runs or a hosted microbenchmark.")

    # Ratchet, not a fixed bar. Holding every push to 20x when five operations
    # are above it means every push is bypassed, and a bypassed gate is not a
    # gate. Hold each operation to what it measured last, with room for the
    # run-to-run variance the footer describes, and let --accept record an
    # improvement so the bar only ever moves down.
    base = load_ratios(args.baseline_ratios)
    regressed = []
    for ratio, name, _ours, _theirs in rows:
        prev = base.get(name)
        if prev is not None and ratio > prev * RATCHET_TOLERANCE:
            regressed.append((name, prev, ratio))
    if regressed:
        emit()
        emit("## Regressions against the ratio baseline")
        emit()
        emit("| operation | was | now |")
        emit("|---|---:|---:|")
        for name, prev, now in regressed:
            emit(f"| {name} | {prev:.0f}x | {now:.0f}x |")
    if args.accept:
        merged = dict(base)
        for ratio, name, _o, _t in rows:
            if name not in merged or ratio < merged[name]:
                merged[name] = ratio
        save_ratios(args.baseline_ratios, merged)
        print(f"\nratio baseline updated: {args.baseline_ratios}")
    worst = max((r for r, *_ in rows), default=0)
    if args.markdown:
        args.markdown.write_text("\n".join(lines) + "\n")
    if args.html:
        args.html.write_text(chart.render(sorted(rows, reverse=True), blk, totals, args.log))
        print(f"\nchart: {args.html}")
    _ = worst
    return 1 if regressed else 0


if __name__ == "__main__":
    sys.exit(main())
