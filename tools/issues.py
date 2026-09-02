#!/usr/bin/env python3
"""Issue-ledger engine behind tools/issues.sh — see that header for the contract.

Ledger: scratch/known_issues.md, one row per issue:
    | Id | Status | Class | Sev | Issue | Evidence | Owner |
Id is stable (`KI-NNNN`, never reused). Fixed rows move to
scratch/archive/fixed-issues.md keeping their id. Bare `|` in cell text must be
escaped as `\\|` (code spans included) — an unescaped pipe breaks row parsing.
"""
import os, re, subprocess, sys
from datetime import date

CLASSES = ("COVERAGE", "DEFECT", "INFRA", "MISSING", "PERF")
SEVS = ("blocker", "critical", "high", "med", "low")
EVIDENCE_CAP = 2000
SPLIT = re.compile(r"(?<!\\)\|")
ID_RE = re.compile(r"^KI-\d{4,}$")
HEADER = "| Id | Status | Class | Sev | Issue | Evidence | Owner |"


def root():
    return subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()


def ledger_path():
    return os.environ.get("ISSUES_LEDGER") or os.path.join(root(), "scratch/known_issues.md")


def archive_path():
    return os.environ.get("ISSUES_ARCHIVE") or os.path.join(root(), "scratch/archive/fixed-issues.md")


def cells(line):
    parts = SPLIT.split(line.rstrip())
    if len(parts) < 3 or parts[0].strip() or parts[-1].strip():
        return None
    return [p.strip() for p in parts[1:-1]]


def load(path):
    """Return (lines, rows) where rows = [(lineno, cells)]."""
    lines = open(path).read().splitlines()
    rows = [(i, c) for i, l in enumerate(lines) if l.startswith("| KI-") and (c := cells(l)) is not None]
    return lines, rows


def status_kw(c):
    return c[1].split()[0]


def live(rows):
    return [(i, c) for i, c in rows if status_kw(c) in ("OPEN", "IN-PROGRESS")]


def fmt_row(c):
    return "| " + " | ".join(c) + " |"


def count_line(rows):
    lv = live(rows)
    n_open = sum(1 for _, c in lv if status_kw(c) == "OPEN")
    return f"**Live issue count: {len(lv)}** — {n_open} `OPEN`, {len(lv) - n_open} `IN-PROGRESS`."


def rewrite(path, lines, rows):
    for i, l in enumerate(lines):
        if l.startswith("**Live issue count"):
            lines[i] = count_line(rows)
            break
    open(path, "w").write("\n".join(lines) + "\n")


def find(rows, rid):
    for i, c in rows:
        if c[0] == rid:
            return i, c
    sys.exit(f"issues: no row {rid}")


def next_id():
    seen = [0]
    for p in (ledger_path(), archive_path()):
        if os.path.exists(p):
            seen += [int(m.group(1)) for m in re.finditer(r"\| KI-(\d+) \|", open(p).read())]
    return f"KI-{max(seen) + 1:04d}"


def brief(c, width=110):
    issue = re.sub(r"\s+", " ", c[4])
    return f"{c[0]}  {c[1].split()[0]:<11} {c[2]:<8} {c[3]:<8} {issue[:width]}"


def cmd_query(args):
    _, rows = load(ledger_path())
    want = {}
    pat = None
    for a in args:
        k, _, v = a.partition("=")
        if k == "grep":
            pat = re.compile(v, re.I)
        elif k in ("status", "class", "sev", "owner"):
            want[k] = v.lower()
        else:
            sys.exit(f"issues: unknown query key {k!r} (status/class/sev/owner/grep)")
    idx = {"status": 1, "class": 2, "sev": 3, "owner": 6}
    out = []
    for _, c in live(rows):
        if any(c[idx[k]].split()[0].lower() != v for k, v in want.items() if k != "owner"):
            continue
        if "owner" in want and want["owner"] not in c[6].lower():
            continue
        if pat and not pat.search(fmt_row(c)):
            continue
        out.append(brief(c))
    print("\n".join(out) if out else "issues: no match", file=sys.stdout if out else sys.stderr)
    return 0 if out else 1


def cmd_show(rid):
    _, rows = load(ledger_path())
    _, c = find(rows, rid)
    for label, v in zip(("Id", "Status", "Class", "Sev", "Issue", "Evidence", "Owner"), c):
        print(f"{label}: {v}")


def cmd_add(cls, sev, owner, issue, evidence):
    if cls not in CLASSES:
        sys.exit(f"issues: class must be one of {'/'.join(CLASSES)}")
    if sev not in SEVS:
        sys.exit(f"issues: sev must be one of {'/'.join(SEVS)}")
    if len(evidence) > EVIDENCE_CAP:
        sys.exit(f"issues: evidence is {len(evidence)} chars, cap {EVIDENCE_CAP} — trim or archive the detail")
    esc = lambda s: re.sub(r"(?<!\\)\|", r"\\|", s.replace("\n", " ").strip())
    rid = next_id()
    lines, rows = load(ledger_path())
    row = [rid, "OPEN", cls, sev, esc(issue), esc(evidence), esc(owner)]
    last = rows[-1][0] if rows else lines.index(HEADER) + 1
    lines.insert(last + 1, fmt_row(row))
    rewrite(ledger_path(), lines, load_rows(lines))
    print(rid)


def load_rows(lines):
    return [(i, c) for i, l in enumerate(lines) if l.startswith("| KI-") and (c := cells(l)) is not None]


def cmd_claim(rid, branch):
    lines, rows = load(ledger_path())
    i, c = find(rows, rid)
    if status_kw(c) != "OPEN":
        sys.exit(f"issues: {rid} is {c[1]}, not OPEN")
    c[1] = f"IN-PROGRESS {branch}"
    c[4] = f"[CLAIMED {branch} {date.today().isoformat()}] {c[4]}"
    lines[i] = fmt_row(c)
    rewrite(ledger_path(), lines, load_rows(lines))


def cmd_fix(rid, sha):
    lines, rows = load(ledger_path())
    i, c = find(rows, rid)
    if status_kw(c) == "FIXED":
        sys.exit(f"issues: {rid} already {c[1]}")
    c[1] = f"FIXED {sha}"
    del lines[i]
    rewrite(ledger_path(), lines, load_rows(lines))
    with open(archive_path(), "a") as f:
        f.write(fmt_row(c) + "\n")


def cmd_summary():
    _, rows = load(ledger_path())
    count, ct, st, bad = {}, {}, {}, False
    for _, c in live(rows):
        cls, sev = c[2], c[3].lower()
        if cls not in CLASSES:
            print(f"issues: unknown class {cls}", file=sys.stderr); bad = True; continue
        if sev not in SEVS:
            print(f"issues: unknown severity {sev}", file=sys.stderr); bad = True; continue
        count[cls, sev] = count.get((cls, sev), 0) + 1
        ct[cls] = ct.get(cls, 0) + 1
        st[sev] = st.get(sev, 0) + 1
    if bad:
        sys.exit(2)
    print("| Class | blocker | critical | high | med | low | Total |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for cls in CLASSES:
        print(f"| {cls} | " + " | ".join(str(count.get((cls, s), 0)) for s in SEVS) + f" | {ct.get(cls, 0)} |")
    print("| **Total** | " + " | ".join(f"**{st.get(s, 0)}**" for s in SEVS) + f" | **{sum(st.values())}** |")


def cmd_check():
    lines, rows = load(ledger_path())
    ok = True
    def err(m):
        nonlocal ok
        print(f"issues: {m}", file=sys.stderr); ok = False
    if sum(1 for l in lines if l == HEADER) != 1:
        err("ledger must contain exactly one Id-shaped issue table header")
    legacy = [l[:60] for l in lines if re.match(r"^\| (OPEN|IN-PROGRESS|FIXED)", l)]
    for l in legacy:
        err(f"id-less row (use --add): {l}")
    seen = set()
    for i, c in rows:
        rid = c[0]
        if len(c) != 7:
            err(f"{rid}: {len(c)} cells (unescaped `|` in text? escape as \\|)"); continue
        if not ID_RE.match(rid):
            err(f"bad id {rid}")
        if rid in seen:
            err(f"duplicate id {rid}")
        seen.add(rid)
        kw = status_kw(c)
        if kw == "FIXED":
            err(f"{rid} is FIXED; move it to the archive (issues.sh --fix does this)")
        elif kw not in ("OPEN", "IN-PROGRESS"):
            err(f"{rid}: unknown status {c[1]!r}")
        if c[2] not in CLASSES:
            err(f"{rid}: unknown class {c[2]!r}")
        if c[3].lower() not in SEVS:
            err(f"{rid}: unknown severity {c[3]!r}")
        if len(c[5]) > EVIDENCE_CAP:
            err(f"{rid}: evidence {len(c[5])} chars exceeds cap {EVIDENCE_CAP}")
    want = count_line(rows)
    have = next((l for l in lines if l.startswith("**Live issue count")), None)
    if have != want:
        err(f"count line stale: have {have!r}, want {want!r}")
    return 0 if ok else 1


def main(argv):
    cmd = argv[0] if argv else ""
    if cmd == "--summary":
        cmd_summary()
    elif cmd == "--check":
        return cmd_check()
    elif cmd == "--status-count":
        _, rows = load(ledger_path())
        for st in ("OPEN", "IN-PROGRESS", "FIXED"):
            print(f"{st}\t{sum(1 for _, c in rows if status_kw(c) == st)}")
    elif cmd == "--count":
        p = ledger_path()
        _, rows = load(p)
        print(f"{os.path.basename(p):<40} {len(rows)}")
    elif cmd == "--query":
        return cmd_query(argv[1:])
    elif cmd == "--show" and len(argv) == 2:
        cmd_show(argv[1])
    elif cmd == "--add" and len(argv) == 6:
        cmd_add(*argv[1:])
    elif cmd == "--claim" and len(argv) == 3:
        cmd_claim(argv[1], argv[2])
    elif cmd == "--fix" and len(argv) == 3:
        cmd_fix(argv[1], argv[2])
    elif cmd == "":
        sys.stdout.write(open(ledger_path()).read())
    else:
        sys.exit(f"issues: bad usage {argv!r} — see tools/issues.sh header")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
