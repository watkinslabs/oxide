#!/usr/bin/env python3
"""Validate the syscall compliance matrix's table shape.

Every row of `## Main Matrix` must have exactly the columns its header
declares, and Status must be one of the legend's values. A script that edits
the table with an off-by-one column index otherwise corrupts rows silently:
the status lands in Branch, the branch overwrites Linux refs, and the evidence
text spills past the trailing pipe -- damage that reads as plausible in a diff
and is invisible in the rendered table. That happened; this is the guard.
"""
import re, subprocess, sys

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

def check_no_duplicate(path):
    """A second copy of the matrix is a split source of truth in the ledger.

    One existed at the repo root while `scratch/` was the maintained copy: it
    had drifted 107 rows behind and was ahead on none, so an agent reading it
    would have re-done finished work. CLAUDE.md already says plans live in
    scratch/, never the repo root -- this makes the rule checkable.
    """
    import os
    other = "syscall-compliance-matrix.md"
    if os.path.basename(path) == other and os.path.dirname(path).endswith("scratch"):
        if os.path.exists(other):
            print(f"matrix-lint: duplicate ledger at ./{other} -- scratch/ is canonical "
                  f"(CLAUDE.md: plans live in scratch/, never the repo root)")
            return 1
    return 0


ALLOW_FILE = "tools/matrix-overstated-allow.txt"


def load_overstated_allow():
    """Rows already `IMPL` whose Evidence discloses a gap, each with a reason.

    Same shape as the stack-depth gate: a finding that predates the gate is
    RECORDED rather than silently tolerated or bulk-flipped, so the gate can go
    green today and still fail on the next NEW violation. Entries only leave
    this file when the owning lane resolves the row -- a lane may not add itself
    to it to make its own row pass.
    """
    import os
    out = set()
    if not os.path.exists(ALLOW_FILE):
        return out
    for l in open(ALLOW_FILE):
        l = l.split("#", 1)[0].strip()
        if l.isdigit():
            out.add(l)
    return out


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


def main(path):
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
    overstated_allow = load_overstated_allow()
    allowed_hit = []
    # Branches that still exist locally or on the remote. An IN-PROGRESS row
    # naming anything else is stale by definition.
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
            ev_now = PAST_TENSE.sub("", ev)
            m = OVERSTATED.search(ev_now)
            if m and nr not in overstated_allow:
                print(f"{path}:{i}: row {nr} is IMPL but its Evidence admits "
                      f"a gap ({m.group(0)!r}) -- use PARTIAL")
                bad += 1
            elif m:
                allowed_hit.append(nr)
    if bad:
        print(f"matrix-lint: FAIL ({bad} problem(s))")
        return 1
    print(f"matrix-lint: ok ({len(seen_nr)} rows, {len(seen_nr)} distinct syscalls)")
    return 1 if bad else 0

if __name__ == "__main__":
    argv = sys.argv[1:]
    want_counts = "--counts" in argv
    argv = [a for a in argv if a != "--counts"]
    path = argv[0] if argv else "scratch/syscall-compliance-matrix.md"
    sys.exit(counts(path) if want_counts else main(path))
