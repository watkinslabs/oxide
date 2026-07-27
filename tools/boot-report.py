#!/usr/bin/env python3
"""Structured metrics for a boot capture.

Hand-parsing boot logs with ad-hoc greps is how we produced two wrong
conclusions ("few log lines means idle"; a feature that traces MUNMAP mistaken
for mount tracing). This turns a capture into the same numbers every time, so
runs are comparable and regressions are visible instead of argued about.

Usage:
    tools/boot-report.py <capture.log> [--json] [--baseline <other.log>]
"""
import re, sys, json, collections

# systemd's own failure vocabulary. 'resources' means the spawn itself failed
# (e.g. EEXIST) -- a hard error, categorically different from 'timeout'.
FAIL_KINDS = {
    "spawn_eexist":  re.compile(r"Failed to spawn '.*?' task: File exists"),
    "result_resources": re.compile(r"\.service: Failed with result 'resources'"),
    "result_timeout":   re.compile(r"\.service: Failed with result 'timeout'"),
    "result_exitcode":  re.compile(r"\.service: Failed with result 'exit-code'"),
    "start_timeout":    re.compile(r"\.service: start operation timed out"),
    "dbus_conn_term":   re.compile(r"Unexpected error response on installing .*: Connection terminated"),
    "dbus_activation_timeout": re.compile(r"StartServiceByName.*Timeout was reached"),
    "failed_to_start":  re.compile(r"MESSAGE=Failed to start ([a-z0-9@.\-]+\.service)"),
}
KERNEL_KINDS = {
    "soft_lockup":   re.compile(r"\[WATCHDOG\] soft lockup"),
    "no_progress":   re.compile(r"\[WATCHDOG\] no-progress"),
    "preempt_leak":  re.compile(r"\[PREEMPT-LEAK\]"),
    "panic":         re.compile(r"\bpanic\b|\bOops\b|\bBUG\b", re.I),
    "enotdir_dirfd": re.compile(r"\[ENOTDIR\] .*why=dirfd-base"),
}
TS = re.compile(r"^\[(\d+\.\d+)\]")
# Under SMP the UART is written concurrently by several CPUs and their bytes
# interleave MID-TOKEN, splicing two numbers into one bogus timestamp (a 295s
# boot yielded a "41113.93"). Anything beyond this is shredded output, not a
# clock reading -- and treating it as real reported 41,102s of "silence"
# inside that 295s run. Drop such lines; also COUNT them, because concurrent
# unserialised console writes are themselves a kernel defect worth surfacing.
# A real boot never jumps more than this between consecutive emitted lines --
# even a genuine multi-second stall is far below it. A larger jump (in either
# direction) is spliced output, not a clock reading.
MAX_FORWARD_JUMP_S = 600.0
# A stall this long is never normal: the tick alone should emit sooner.
SILENT_GAP_MIN_S = 5.0


def parse(path):
    starts, execs, lines = {}, [], 0
    stamps = []
    corrupt_ts = 0
    fails = collections.Counter()
    kern = collections.Counter()
    units_failed = collections.Counter()
    targets, last_ts = [], 0.0
    absurd_deadlines = set()
    for line in open(path, errors="ignore"):
        lines += 1
        m = TS.match(line)
        if m:
            ts = float(m.group(1))
            if (stamps and (ts > stamps[-1] + MAX_FORWARD_JUMP_S
                            or ts + MAX_FORWARD_JUMP_S < stamps[-1])):
                corrupt_ts += 1
                continue
            last_ts = ts
            stamps.append(ts)
        s = re.search(r"MESSAGE=Starting ([a-z0-9@.\-]+\.service)", line)
        if s and m and s.group(1) not in starts:
            starts[s.group(1)] = float(m.group(1))
        e = re.search(r"EXECLOAD begin .*path=(\S+?)\]", line)
        if e and m:
            execs.append((float(m.group(1)), e.group(1)))
        t = re.search(r"Reached target ([a-z0-9.\-]+)", line)
        if t:
            targets.append(t.group(1))
        for k, rx in FAIL_KINDS.items():
            hit = rx.search(line)
            if hit:
                fails[k] += 1
                if k == "failed_to_start":
                    units_failed[hit.group(1)] += 1
        for k, rx in KERNEL_KINDS.items():
            if rx.search(line):
                kern[k] += 1
        d = re.search(r"wake_dl_ns=(\d{19,})", line)
        if d:
            absurd_deadlines.add(d.group(1))
    # Silent gaps: wall-clock stretches where the kernel emitted NOTHING.
    # The whole machine stalling for 14-28s at a time is the dominant symptom
    # behind the D-Bus activation timeouts -- five unrelated services blow
    # their 90s deadline and are then all processed inside one ~6s window,
    # which is a backlog draining after a stall, not five independent faults.
    # Timestamps are NOT monotonic under SMP: lines from different CPUs
    # interleave, so a raw consecutive delta can be negative or wildly wrong.
    # Sorting first is what makes this metric valid on multi-CPU captures --
    # without it an SMP=4 boot reported 41,102s of "silence" inside a 295s run,
    # which is how this bug was caught.
    silent = []
    ordered = sorted(stamps)
    for i in range(len(ordered) - 1):
        d = ordered[i + 1] - ordered[i]
        if d >= SILENT_GAP_MIN_S:
            silent.append((round(ordered[i], 1), round(d, 1)))
    silent.sort(key=lambda x: -x[1])

    gaps = []
    for svc, t0 in starts.items():
        key = svc.replace(".service", "").split("@")[0]
        cand = [et for et, p in execs if key in p and et >= t0]
        if cand:
            gaps.append((svc, cand[0] - t0))
    gaps.sort(key=lambda r: -r[1])
    vals = sorted(g for _, g in gaps)
    return {
        "log": path,
        "lines": lines,
        "guest_seconds": last_ts,
        "targets_reached": targets,
        "graphical_target": "graphical.target" in targets,
        "exec_count": len(execs),
        "service_gap": {
            "n": len(vals),
            "median_s": round(vals[len(vals) // 2], 2) if vals else None,
            "max_s": round(vals[-1], 1) if vals else None,
            "slowest": [(s, round(g, 1)) for s, g in gaps[:6]],
        },
        "userspace_failures": dict(fails),
        "units_failed_to_start": dict(units_failed),
        "kernel_events": dict(kern),
        "absurd_wake_deadlines": sorted(absurd_deadlines),
        "corrupt_timestamps": corrupt_ts,
        "silent_gaps": {
            "count": len(silent),
            "total_s": round(sum(d for _, d in silent), 1),
            "max_s": silent[0][1] if silent else 0.0,
            "worst": silent[:5],
        },
    }


def verdict(r):
    """The single question that matters, answered the same way every run."""
    if r["kernel_events"].get("panic") or r["kernel_events"].get("soft_lockup"):
        return "KERNEL-FAULT"
    if not r["targets_reached"]:
        return "NO-BOOT"
    if r["graphical_target"]:
        return "GRAPHICAL-TARGET" if r["userspace_failures"] else "GRAPHICAL-CLEAN"
    return "PARTIAL-BOOT"


def render(r, base=None):
    out = []
    out.append(f"boot-report: {r['log']}")
    out.append(f"  verdict            : {verdict(r)}")
    out.append(f"  guest time         : {r['guest_seconds']:.1f}s   log lines: {r['lines']}   execs: {r['exec_count']}")
    out.append(f"  graphical.target   : {'YES' if r['graphical_target'] else 'no'}")
    out.append(f"  targets reached    : {len(r['targets_reached'])}")
    g = r["service_gap"]
    out.append(f"  service start->exec: n={g['n']} median={g['median_s']}s max={g['max_s']}s")
    for s, v in g["slowest"]:
        out.append(f"      {s:34} {v:7.1f}s")
    if r["kernel_events"]:
        out.append("  kernel events      :")
        for k, v in sorted(r["kernel_events"].items()):
            out.append(f"      {k:22} {v}")
    if r["userspace_failures"]:
        out.append("  userspace failures :")
        for k, v in sorted(r["userspace_failures"].items(), key=lambda x: -x[1]):
            out.append(f"      {k:26} {v}")
    if r["units_failed_to_start"]:
        out.append("  units failed       : " + ", ".join(
            f"{u}({n})" for u, n in sorted(r["units_failed_to_start"].items(), key=lambda x: -x[1])))
    if r.get("corrupt_timestamps"):
        out.append(f"  CORRUPT CONSOLE    : {r['corrupt_timestamps']} lines with spliced timestamps "
                   f"(concurrent unserialised UART writes -- an SMP console-locking defect)")
    sg = r["silent_gaps"]
    if sg["count"]:
        out.append(f"  SILENT STALLS      : {sg['count']} gaps >={SILENT_GAP_MIN_S}s, total {sg['total_s']}s, worst {sg['max_s']}s")
        for at, d in sg["worst"]:
            out.append(f"      {d:6.1f}s of total silence starting at t={at}s")
    if r["absurd_wake_deadlines"]:
        out.append(f"  ABSURD wake_dl_ns  : {r['absurd_wake_deadlines']}")
    if base:
        out.append(f"\n  vs baseline {base['log']}:")
        out.append(f"      guest time  {base['guest_seconds']:.1f}s -> {r['guest_seconds']:.1f}s")
        out.append(f"      gap median  {base['service_gap']['median_s']}s -> {g['median_s']}s")
        out.append(f"      gap max     {base['service_gap']['max_s']}s -> {g['max_s']}s")
        bf = sum(base["userspace_failures"].values())
        nf = sum(r["userspace_failures"].values())
        out.append(f"      failures    {bf} -> {nf}")
        out.append(f"      silent gaps {base['silent_gaps']['count']} ({base['silent_gaps']['total_s']}s) -> {sg['count']} ({sg['total_s']}s)")
    return "\n".join(out)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        sys.exit(2)
    rep = parse(args[0])
    base = None
    if "--baseline" in sys.argv:
        base = parse(sys.argv[sys.argv.index("--baseline") + 1])
    if "--json" in sys.argv:
        print(json.dumps(rep, indent=2))
    else:
        print(render(rep, base))
