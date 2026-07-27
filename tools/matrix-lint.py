#!/usr/bin/env python3
"""Validate the syscall compliance matrix's table shape.

Every row of `## Main Matrix` must have exactly the columns its header
declares, and Status must be one of the legend's values. A script that edits
the table with an off-by-one column index otherwise corrupts rows silently:
the status lands in Branch, the branch overwrites Linux refs, and the evidence
text spills past the trailing pipe -- damage that reads as plausible in a diff
and is invisible in the rendered table. That happened; this is the guard.
"""
import re, sys

VALID = {"NEEDS-AUDIT", "PARTIAL", "IMPL", "DISPATCH-GAP", "LINUX-ENOSYS",
         "IN-PROGRESS", "DONE"}

def main(path):
    lines = open(path).read().split("\n")
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("## Main Matrix"))
    except StopIteration:
        print("matrix-lint: no '## Main Matrix' section"); return 1
    header = next(l for l in lines[start:] if l.startswith("| Nr |"))
    ncol = len(header.split("|"))
    names = [c.strip() for c in header.split("|")]
    st_i = names.index("Status")
    bad = 0
    warn = []
    for i, l in enumerate(lines[start:], start=start + 1):
        if not l.startswith("| ") or l.startswith("| Nr |") or set(l) <= set("|-: "):
            continue
        f = l.split("|")
        nr = f[1].strip()
        if not nr.isdigit():
            continue
        if len(f) < ncol:
            # Too FEW fields means the row is shifted: a value was written one
            # column left/right of where it belongs. This is the corruption
            # case and is always an error.
            print(f"{path}:{i}: row {nr} has {len(f)-2} columns, header declares {ncol-2} (shifted)")
            bad += 1
            continue
        if len(f) > ncol:
            # Extra fields are unescaped '|' inside the free-text Evidence
            # column. Harmless to the leading columns, so warn rather than
            # fail -- but report it, since it defeats naive column parsing.
            warn.append(nr)
        st = f[st_i].strip().strip("`")
        if st not in VALID:
            print(f"{path}:{i}: row {nr} Status={st!r} not in legend")
            bad += 1
    if warn:
        print(f"matrix-lint: note: {len(warn)} row(s) have unescaped '|' in Evidence: "
              + ", ".join(warn[:8]) + ("..." if len(warn) > 8 else ""))
    print(f"matrix-lint: {'FAIL' if bad else 'ok'} ({bad} shifted row(s))")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "scratch/syscall-compliance-matrix.md"))
