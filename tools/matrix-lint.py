#!/usr/bin/env python3
"""Validate the syscall compliance matrix's table shape.

Every row of `## Main Matrix` must have exactly the columns its header
declares, and Status must be one of the legend's values. A script that edits
the table with an off-by-one column index otherwise corrupts rows silently:
the status lands in Branch, the branch overwrites Linux refs, and the evidence
text spills past the trailing pipe -- damage that reads as plausible in a diff
and is invisible in the rendered table. That happened; this is the guard.
"""
import contextlib, io, os, re, subprocess, sys, tempfile

# Split on `|` only where it is NOT backslash-escaped. Naive `str.split("|")`
# is what let `F784` through: it treated every pipe-bearing row as unparseable,
# skipped it, read the absence as "this syscall has no row", and appended 66
# duplicates. A parser that drops what it cannot read reports absence, not error.
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")

# Statuses come from the legend table in the matrix itself, never a copy here.
# The hardcoded set this replaced had drifted: it lacked `NEEDS-REWORK`, which
# the legend defines and 15 rows use, so the lint failed on clean main and would
# have been dismissed as broken by the first person to wire it up.
LEGEND_RE = re.compile(r"\|\s*`([A-Z][A-Z-]*)`\s*\|")


def legend_statuses(lines):
    out, inside = set(), False
    for l in lines:
        if l.startswith("## Status Legend"):
            inside = True
            continue
        if inside:
            if l.startswith("## "):
                break
            m = LEGEND_RE.match(l)
            if m:
                out.add(m.group(1))
    return out

# An IMPL row claims FULL Linux semantics. If its own Evidence admits a
# remaining divergence, the row contradicts itself -- and the honest text is
# what makes the overstated status survive review, because a reader who gets
# as far as the prose sees the caveat and assumes the status reflects it.
# These phrases mean "we do not do what Linux does", as distinct from prose
# describing what a fix REMOVED (hence the required negative-claim shape).
OVERSTATED = re.compile(
    r"(NOT matched|not implemented\b|is absent\b|we do not\b|unimplemented\b|"
    r"remains? (?:open|unmatched)|no counterpart)", re.I)

# Past-tense prose describes the state a fix REMOVED, which is the opposite of a
# disclosed gap: "which had no counterpart before" means the counterpart now
# exists. Matching it flagged rows 82, 264 and 316, all of which are correctly
# `IMPL`. Checked BEFORE `OVERSTATED` so the negative-claim shape stays narrow.
PAST_TENSE = re.compile(
    r"(had no counterpart|was absent|were absent|had not been implemented|"
    r"was not implemented|previously (?:absent|unimplemented))", re.I)


def current_evidence(ev):
    """Return the claim after the latest explicit closure marker.

    Matrix evidence is chronological. A gap before `Closed in B...` describes
    what that branch removed; only the suffix can contradict today's status.
    """
    return ev.rsplit("Closed in", 1)[-1]

def check_no_duplicate(path):
    """A second copy of the matrix is a split source of truth in the ledger.

    One existed at the repo root while `scratch/` was the maintained copy: it
    had drifted 107 rows behind and was ahead on none, so an agent reading it
    would have re-done finished work. CLAUDE.md already says plans live in
    scratch/, never the repo root -- this makes the rule checkable.
    """
    other = "syscall-compliance-matrix.md"
    if os.path.basename(path) == other and os.path.dirname(path).endswith("scratch"):
        if os.path.exists(other):
            print(f"matrix-lint: duplicate ledger at ./{other} -- scratch/ is canonical "
                  f"(CLAUDE.md: plans live in scratch/, never the repo root)")
            return 1
    return 0


def table(lines):
    """Locate `## Main Matrix`, return (start, header names, column count).

    Shared by the lint and the `--counts` reader so a second consumer cannot
    grow its own parser and disagree with the gate. `F784` is the whole reason
    this file exists: it counted rows with a parser that split on bare `|`,
    silently dropped the 65 pipe-bearing rows, and reported the absence as
    "untracked". Any counter that re-derives the split has re-created that bug.
    """
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("## Main Matrix"))
    except StopIteration:
        return None
    header = next(l for l in lines[start:] if l.startswith("| Nr |"))
    names = [c.strip() for c in UNESCAPED_PIPE.split(header)]
    return start, names, len(names)


def iter_rows(lines, start, ncol):
    """Yield (line_no, fields) for each numbered row, escape-aware.

    Yields malformed rows too (fields length != ncol) so the lint can fail on
    them; a caller that only wants well-formed rows filters on `len(f)`.
    """
    for i, l in enumerate(lines[start:], start=start + 1):
        if not l.startswith("| ") or l.startswith("| Nr |") or set(l) <= set("|-: "):
            continue
        f = UNESCAPED_PIPE.split(l)
        if not f[1].strip().isdigit():
            continue
        yield i, f


def counts(path):
    """Print `STATUS<TAB>count` for every legend status, plus `ROWS<TAB>n`.

    Consumed by `xtask stats`. Statuses come from the legend, so a status added
    there appears here without editing this function, and a row the lint would
    reject is counted as `MALFORMED` rather than silently dropped.
    """
    lines = open(path).read().split("\n")
    t = table(lines)
    if t is None:
        print("matrix-lint: no '## Main Matrix' section", file=sys.stderr)
        return 1
    start, names, ncol = t
    st_i = names.index("Status")
    valid = legend_statuses(lines)
    if not valid:
        print("matrix-lint: could not parse the '## Status Legend' table", file=sys.stderr)
        return 1
    tally = dict.fromkeys(valid, 0)
    tally["MALFORMED"] = 0
    rows = 0
    for _, f in iter_rows(lines, start, ncol):
        rows += 1
        if len(f) != ncol:
            tally["MALFORMED"] += 1
            continue
        st = f[st_i].strip().strip("`")
        tally[st] = tally.get(st, 0) + 1
    print(f"ROWS\t{rows}")
    for k in sorted(tally):
        print(f"{k}\t{tally[k]}")
    return 0


def main(path, live_branches=None):
    lines = open(path).read().split("\n")
    t = table(lines)
    if t is None:
        print("matrix-lint: no '## Main Matrix' section"); return 1
    start, names, ncol = t
    st_i = names.index("Status")
    VALID = legend_statuses(lines)
    if not VALID:
        print("matrix-lint: could not parse the '## Status Legend' table"); return 1
    bad = check_no_duplicate(path)
    seen_nr = {}
    # Branches that still exist locally or on the remote. An IN-PROGRESS row
    # naming anything else is stale by definition.
    if live_branches is None:
        try:
            live_branches = set(
                b.strip().lstrip("* ").split("/")[-1]
                for b in subprocess.run(["git", "branch", "-a"], capture_output=True,
                                        text=True).stdout.splitlines())
        except Exception:
            live_branches = set()
    for i, l in enumerate(lines[start:], start=start + 1):
        if not l.startswith("| ") or l.startswith("| Nr |") or set(l) <= set("|-: "):
            continue
        f = UNESCAPED_PIPE.split(l)
        nr = f[1].strip()
        if not nr.isdigit():
            continue
        if len(f) != ncol:
            # Either direction is now an error. Too FEW fields means the row is
            # shifted: a value written one column off. Too MANY means a bare '|'
            # inside a cell (write '\|'), which used to be a warning -- and that
            # warning named all 65 rows `F784` went on to duplicate. Nobody saw
            # it, because this lint was never wired into a gate. Warnings that
            # nothing reads are not verification.
            how = "shifted" if len(f) < ncol else r"unescaped '|' in a cell (write '\|')"
            print(f"{path}:{i}: row {nr} has {len(f)-2} columns, header declares {ncol-2} ({how})")
            bad += 1
            continue
        # One row per syscall number. Two rows disagree on Status, and every
        # reader takes whichever it reaches first.
        if nr in seen_nr:
            print(f"{path}:{i}: row {nr} duplicates the row at line {seen_nr[nr]} "
                  f"-- one row per syscall number")
            bad += 1
        else:
            seen_nr[nr] = i
        st_raw = f[st_i].strip()
        st = st_raw.strip("`")
        # Every status is written `IMPL`, not IMPL. An unbackticked one still
        # reads fine to a human and still matches `.strip("`")`, so it survives
        # review and survived this lint -- but it silently drops out of every
        # count that greps for the backticked form. Row 103 sat like that.
        if st in VALID and not (st_raw.startswith("`") and st_raw.endswith("`")):
            print(f"{path}:{i}: row {nr} Status={st_raw!r} is not backticked -- "
                  f"it drops out of any count matching `STATUS`")
            bad += 1
        if st not in VALID:
            print(f"{path}:{i}: row {nr} Status={st!r} not in legend")
            bad += 1
        elif st == "IN-PROGRESS":
            # IN-PROGRESS means a live lane is touching this row RIGHT NOW.
            # Left on merged work it tells the next agent the row is owned,
            # which is how duplicate lanes get opened -- the single most
            # expensive mistake in this repo (see CLAUDE.md "Claim work before
            # starting"). Verify the named branch still exists.
            br = f[names.index("Branch")].strip().strip("`")
            if br and br not in live_branches:
                print(f"{path}:{i}: row {nr} is IN-PROGRESS but branch {br!r} "
                      f"no longer exists -- the work merged; use PARTIAL/IMPL")
                bad += 1
        elif st == "IMPL":
            ev = "|".join(f[names.index("Evidence / next audit"):])  # noqa: rejoin cell
            ev_now = PAST_TENSE.sub("", current_evidence(ev))
            m = OVERSTATED.search(ev_now)
            if m:
                print(f"{path}:{i}: row {nr} is IMPL but its Evidence admits "
                      f"a gap ({m.group(0)!r}) -- use PARTIAL")
                bad += 1
    if bad:
        print(f"matrix-lint: FAIL ({bad} problem(s))")
        return 1
    print(f"matrix-lint: ok ({len(seen_nr)} rows, {len(seen_nr)} distinct syscalls)")
    return 1 if bad else 0


SELFTEST_HEAD = """## Status Legend
| Status | Meaning |
|---|---|
| `IMPL` | complete |
| `PARTIAL` | incomplete |
| `IN-PROGRESS` | claimed |

## Main Matrix
| Nr | ABI | Syscall | Linux entry | Subsystem | Systems touched | Oxide route | Status | Branch | Linux refs | Required harness | Evidence / next audit |
|---:|---|---|---|---|---|---|---|---|---|---|---|"""


def selftest_row(nr=900, status="`IMPL`", branch="-", evidence="complete"):
    return (f"| {nr} | common | `probe` | `sys_probe` | test | test | route | "
            f"{status} | {branch} | ref | harness | {evidence} |")


def selftest_run(rows, live_branches=None):
    """Run one isolated fixture and normalize its temporary path/line number."""
    with tempfile.TemporaryDirectory(prefix="matrix-lint-selftest-") as td:
        path = os.path.join(td, "fixture.md")
        with open(path, "w") as out:
            out.write(SELFTEST_HEAD + "\n" + "\n".join(rows) + "\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(path, set() if live_branches is None else live_branches)
    lines = []
    for line in buf.getvalue().splitlines():
        line = line.replace(path, "<fixture>")
        lines.append(re.sub(r":\d+: row", ":<LINE>: row", line))
    return rc, lines


def selftest_case(name, rows, want_rc, want_lines, live_branches=None):
    rc, lines = selftest_run(rows, live_branches)
    if (rc, lines) != (want_rc, want_lines):
        print(f"matrix-lint self-test: FAIL {name}: got rc={rc}, lines={lines!r}; "
              f"want rc={want_rc}, lines={want_lines!r}")
        return 1
    return 0


def selftest():
    """Prove each gate invariant fails alone and names its own reason."""
    fail = 0
    ok = ["matrix-lint: ok (1 rows, 1 distinct syscalls)"]
    fail += selftest_case("clean", [selftest_row()], 0, ok)
    fail += selftest_case("closed-history",
        [selftest_row(evidence="not implemented. Closed in B1: complete")], 0, ok)
    fail += selftest_case("past-tense",
        [selftest_row(evidence="was not implemented before")], 0, ok)
    fail += selftest_case("duplicate", [selftest_row(), selftest_row()], 1, [
        "<fixture>:<LINE>: row 900 duplicates the row at line 11 -- one row per syscall number",
        "matrix-lint: FAIL (1 problem(s))",
    ])
    fail += selftest_case("unescaped-pipe",
        [selftest_row(evidence="bad | split")], 1, [
        "<fixture>:<LINE>: row 900 has 13 columns, header declares 12 "
        "(unescaped '|' in a cell (write '\\|'))",
        "matrix-lint: FAIL (1 problem(s))",
    ])
    fail += selftest_case("shifted", [
        "| 900 | common | `probe` | `sys_probe` | test | test | route | `IMPL` | - | ref | harness |",
    ], 1, [
        "<fixture>:<LINE>: row 900 has 11 columns, header declares 12 (shifted)",
        "matrix-lint: FAIL (1 problem(s))",
    ])
    fail += selftest_case("unbackticked", [selftest_row(status="IMPL")], 1, [
        "<fixture>:<LINE>: row 900 Status='IMPL' is not backticked -- "
        "it drops out of any count matching `STATUS`",
        "matrix-lint: FAIL (1 problem(s))",
    ])
    fail += selftest_case("invalid-status", [selftest_row(status="`BOGUS`")], 1, [
        "<fixture>:<LINE>: row 900 Status='BOGUS' not in legend",
        "matrix-lint: FAIL (1 problem(s))",
    ])
    fail += selftest_case("stale-claim", [
        selftest_row(status="`IN-PROGRESS`", branch="dead-branch"),
    ], 1, [
        "<fixture>:<LINE>: row 900 is IN-PROGRESS but branch 'dead-branch' no longer exists "
        "-- the work merged; use PARTIAL/IMPL",
        "matrix-lint: FAIL (1 problem(s))",
    ])
    fail += selftest_case("overstated", [
        selftest_row(evidence="this remains open"),
    ], 1, [
        "<fixture>:<LINE>: row 900 is IMPL but its Evidence admits a gap ('remains open') "
        "-- use PARTIAL",
        "matrix-lint: FAIL (1 problem(s))",
    ])
    if fail:
        return 1
    print("matrix-lint: self-test PASS (7 isolated mutants, 3 green controls)")
    return 0

if __name__ == "__main__":
    argv = sys.argv[1:]
    want_counts = "--counts" in argv
    want_selftest = "--self-test" in argv
    argv = [a for a in argv if a not in ("--counts", "--self-test")]
    if want_counts and want_selftest:
        print("matrix-lint: --counts and --self-test are mutually exclusive", file=sys.stderr)
        sys.exit(2)
    path = argv[0] if argv else "scratch/syscall-compliance-matrix.md"
    sys.exit(selftest() if want_selftest else counts(path) if want_counts else main(path))
