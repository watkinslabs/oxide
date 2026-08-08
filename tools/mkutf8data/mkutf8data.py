#!/usr/bin/env python3
"""Generate crates/shared/utf8/data/utf8data.bin from the Unicode character
database carried by Python's `unicodedata` module.

Emitted tables (see `crates/shared/utf8/src/blob.rs` for the reader):

  ccc     canonical combining class, range-compressed
  ign     Default_Ignorable_Code_Point, range-compressed; these normalize to
          the empty string and act as segment breaks
  nfdi    NFD expansion, fully expanded to a fixpoint, ignorables removed
  nfdicf  NFD + full case fold expansion, applied to a fixpoint

Hangul syllables (AC00..D7A3) are excluded from both expansion tables: their
decomposition is algorithmic and the reader computes it. The self-test checks
the algorithm against `unicodedata` for all 11172 of them.

Usage:  python3 tools/mkutf8data/mkutf8data.py [--check]
        --check regenerates in memory and fails if the committed blob differs.
"""

import argparse
import os
import struct
import sys
import unicodedata

MAGIC = b"OXUTF8\x00\x00"
FORMAT_VERSION = 1
HEADER_LEN = 40

SURROGATE_FIRST = 0xD800
SURROGATE_LAST = 0xDFFF
MAX_CODEPOINT = 0x10FFFF

HANGUL_SBASE = 0xAC00
HANGUL_LBASE = 0x1100
HANGUL_VBASE = 0x1161
HANGUL_TBASE = 0x11A7
HANGUL_LCOUNT = 19
HANGUL_VCOUNT = 21
HANGUL_TCOUNT = 28
HANGUL_NCOUNT = HANGUL_VCOUNT * HANGUL_TCOUNT
HANGUL_SCOUNT = HANGUL_LCOUNT * HANGUL_NCOUNT

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BLOB_PATH = os.path.join(REPO_ROOT, "crates", "shared", "utf8", "data", "utf8data.bin")
FIXTURE_PATH = os.path.join(REPO_ROOT, "crates", "shared", "utf8", "data", "foldcases.txt")


# Default_Ignorable_Code_Point is a derived property; `unicodedata` exposes only
# the primitives it is derived from. The derivation (UAX #44):
#
#   Default_Ignorable_Code_Point =
#         Other_Default_Ignorable_Code_Point
#       + Cf (Format)
#       + Variation_Selector
#       - White_Space
#       - FFF9..FFFB (interlinear annotation)
#       - 13430..1343F (Egyptian hieroglyph format controls)
#       - Prepended_Concatenation_Mark
#
# Other_Default_Ignorable_Code_Point and Variation_Selector are themselves
# enumerated properties with no algorithmic definition, so their members are
# listed here. `--check` plus the membership self-test below pin the result.
OTHER_DEFAULT_IGNORABLE = [
    (0x034F, 0x034F), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x2065, 0x2065),
    (0x3164, 0x3164), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0xE0000, 0xE0000),
    (0xE0002, 0xE001F), (0xE0080, 0xE00FF), (0xE01F0, 0xE0FFF),
]
VARIATION_SELECTOR = [
    (0x180B, 0x180D), (0x180F, 0x180F), (0xFE00, 0xFE0F), (0xE0100, 0xE01EF),
]
INTERLINEAR_ANNOTATION = [(0xFFF9, 0xFFFB)]
EGYPTIAN_FORMAT_CONTROLS = [(0x13430, 0x1343F)]
PREPENDED_CONCATENATION_MARK = [
    (0x0600, 0x0605), (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891),
    (0x08E2, 0x08E2), (0x110BD, 0x110BD), (0x110CD, 0x110CD),
]

# Codepoints whose Default_Ignorable membership the derivation above must
# reproduce. Guards against a stale hand-listed range silently changing the
# blob's meaning.
DI_EXPECT_MEMBER = [0x00AD, 0x200B, 0x200D, 0x034F, 0xFE0F, 0xE0101, 0x2065]
DI_EXPECT_NONMEMBER = [0x0020, 0x0041, 0x00E9, 0x0301, 0x0600, 0xFFF9, 0x13430]


def expand_ranges(ranges):
    out = set()
    for lo, hi in ranges:
        out.update(range(lo, hi + 1))
    return out


def all_codepoints():
    for cp in range(0, MAX_CODEPOINT + 1):
        if SURROGATE_FIRST <= cp <= SURROGATE_LAST:
            continue
        yield cp


def default_ignorable_set():
    di = expand_ranges(OTHER_DEFAULT_IGNORABLE) | expand_ranges(VARIATION_SELECTOR)
    for cp in all_codepoints():
        if unicodedata.category(chr(cp)) == "Cf":
            di.add(cp)
    di -= expand_ranges(INTERLINEAR_ANNOTATION)
    di -= expand_ranges(EGYPTIAN_FORMAT_CONTROLS)
    di -= expand_ranges(PREPENDED_CONCATENATION_MARK)
    di -= {cp for cp in di if chr(cp).isspace()}
    for cp in DI_EXPECT_MEMBER:
        assert cp in di, "U+%04X should be Default_Ignorable" % cp
    for cp in DI_EXPECT_NONMEMBER:
        assert cp not in di, "U+%04X should not be Default_Ignorable" % cp
    return di


def is_hangul_syllable(cp):
    return HANGUL_SBASE <= cp < HANGUL_SBASE + HANGUL_SCOUNT


def hangul_decompose(cp):
    si = cp - HANGUL_SBASE
    li = si // HANGUL_NCOUNT
    vi = (si % HANGUL_NCOUNT) // HANGUL_TCOUNT
    ti = si % HANGUL_TCOUNT
    out = chr(HANGUL_LBASE + li) + chr(HANGUL_VBASE + vi)
    if ti:
        out += chr(HANGUL_TBASE + ti)
    return out


def nfd_fixpoint(s):
    while True:
        t = unicodedata.normalize("NFD", s)
        if t == s:
            return s
        s = t


def nfdicf_fixpoint(s):
    while True:
        t = unicodedata.normalize("NFD", s.casefold())
        if t == s:
            return s
        s = t


def strip_ignorable(s, di):
    return "".join(c for c in s if ord(c) not in di)


def build_tables():
    di = default_ignorable_set()

    ccc = []            # (cp, class)
    nfdi = {}           # cp -> expansion string
    nfdicf = {}
    for cp in all_codepoints():
        ch = chr(cp)
        cls = unicodedata.combining(ch)
        if cls:
            ccc.append((cp, cls))
        if cp in di or is_hangul_syllable(cp):
            continue
        d = strip_ignorable(nfd_fixpoint(ch), di)
        f = strip_ignorable(nfdicf_fixpoint(ch), di)
        assert d, "U+%04X decomposes to nothing" % cp
        assert f, "U+%04X folds to nothing" % cp
        # An expansion holding an ignorable would need a segment break inside
        # it, which the reader's expansion walk has no way to express.
        assert not any(ord(c) in di for c in d + f), "U+%04X expands to an ignorable" % cp
        if d != ch:
            nfdi[cp] = d
        if f != ch:
            nfdicf[cp] = f
    return di, ccc, nfdi, nfdicf


def compress(cps):
    """Sorted codepoint set -> list of (start, end) ranges."""
    out = []
    for cp in sorted(cps):
        if out and out[-1][1] + 1 == cp:
            out[-1][1] = cp
        else:
            out.append([cp, cp])
    return [(lo, hi) for lo, hi in out]


def compress_ccc(pairs):
    """Sorted (cp, class) -> list of (start, end, class) ranges."""
    out = []
    for cp, cls in sorted(pairs):
        if out and out[-1][2] == cls and out[-1][1] + 1 == cp:
            out[-1][1] = cp
        else:
            out.append([cp, cp, cls])
    return [(lo, hi, cls) for lo, hi, cls in out]


def build_pool(tables):
    pool = bytearray()
    index = {}
    entries = []
    for table in tables:
        rows = []
        for cp in sorted(table):
            s = table[cp].encode("utf-8")
            off = index.get(s)
            if off is None:
                off = len(pool)
                index[s] = off
                pool += s
            rows.append((cp, off, len(s)))
        entries.append(rows)
    return entries, bytes(pool)


def serialize():
    di, ccc_pairs, nfdi, nfdicf = build_tables()
    ccc_ranges = compress_ccc(ccc_pairs)
    ign_ranges = compress(di)
    (nfdi_rows, nfdicf_rows), pool = build_pool([nfdi, nfdicf])

    major, minor, rev = (int(x) for x in unicodedata.unidata_version.split("."))
    blob = bytearray()
    blob += MAGIC
    blob += struct.pack(
        "<8I",
        FORMAT_VERSION,
        (major << 16) | (minor << 8) | rev,
        len(ccc_ranges),
        len(ign_ranges),
        len(nfdi_rows),
        len(nfdicf_rows),
        len(pool),
        0,
    )
    assert len(blob) == HEADER_LEN
    for lo, hi, cls in ccc_ranges:
        blob += struct.pack("<3I", lo, hi, cls)
    for lo, hi in ign_ranges:
        blob += struct.pack("<2I", lo, hi)
    for rows in (nfdi_rows, nfdicf_rows):
        for cp, off, ln in rows:
            blob += struct.pack("<3I", cp, off, ln)
    blob += pool
    stats = {
        "unicode": unicodedata.unidata_version,
        "ccc_ranges": len(ccc_ranges),
        "ign_ranges": len(ign_ranges),
        "nfdi": len(nfdi_rows),
        "nfdicf": len(nfdicf_rows),
        "pool": len(pool),
        "bytes": len(blob),
    }
    return bytes(blob), stats


# --- self-test: the generated tables, walked the way the reader walks them,
# must reproduce what `unicodedata`/`str.casefold` say. ---

def reader_expand(cp, table, di):
    """Mirror of the reader's per-codepoint expansion lookup."""
    if cp in di:
        return ""
    if is_hangul_syllable(cp):
        return hangul_decompose(cp)
    return table.get(cp, chr(cp))


def reader_normalize(s, table, di, ccc_of):
    """Mirror of the whole reader: expand each codepoint, then stable-sort each
    run of combining marks by class. An ignorable emits nothing but ends the run
    it sits in, exactly as the cursor treats it."""
    out = []
    run = []

    def flush():
        out.extend(sorted(run, key=lambda c: ccc_of(ord(c))))
        run.clear()

    for ch in s:
        cp = ord(ch)
        if cp in di:
            flush()
            continue
        for c in reader_expand(cp, table, di):
            if ccc_of(ord(c)) == 0:
                flush()
                out.append(c)
            else:
                run.append(c)
    flush()
    return "".join(out)


def selftest(quiet=False):
    di, ccc_pairs, nfdi, nfdicf = build_tables()
    ccc_map = dict(ccc_pairs)
    ccc_of = lambda cp: ccc_map.get(cp, 0)

    for cp in range(HANGUL_SBASE, HANGUL_SBASE + HANGUL_SCOUNT):
        assert hangul_decompose(cp) == unicodedata.normalize("NFD", chr(cp)), \
            "hangul algorithm differs at U+%04X" % cp

    checked = 0
    for cp in all_codepoints():
        if cp % 7 and not (0x40 <= cp <= 0x2FFF):
            continue  # sample the space, walk the dense Latin/Greek/Cyrillic part
        ch = chr(cp)
        want_d = reader_normalize(strip_ignorable(nfd_fixpoint(ch), di), {}, di, ccc_of)
        want_f = reader_normalize(strip_ignorable(nfdicf_fixpoint(ch), di), {}, di, ccc_of)
        got_d = reader_normalize(ch, nfdi, di, ccc_of)
        got_f = reader_normalize(ch, nfdicf, di, ccc_of)
        assert got_d == want_d, "NFDI mismatch at U+%04X" % cp
        assert got_f == want_f, "NFDICF mismatch at U+%04X" % cp
        checked += 1

    # Whole-string cases: the property the kernel depends on is that two
    # spellings of one name fold to the same sequence.
    fold = lambda s: reader_normalize(s, nfdicf, di, ccc_of)
    pairs_equal = [
        ("ABC", "abc"), ("Stra\u00dfe", "STRASSE"), ("\u00c9", "e\u0301"),
        ("\u1e9e", "\u00df"), ("\u0130", "i\u0307"), ("\u03a3", "\u03c2"),
        ("q\u0323\u0301", "q\u0301\u0323"), ("A\u00adB", "ab"),
        ("\uac00", "\u1100\u1161"),
    ]
    for a, b in pairs_equal:
        assert fold(a) == fold(b), "expected fold-equal: %r vs %r" % (a, b)
    pairs_differ = [
        ("abc", "abd"), ("\u00e9", "\u00e8"), ("a", "\u0430"),
        # An ignorable breaks the run, so the marks either side cannot reorder.
        ("e\u0301\u00ad\u0323", "e\u0323\u00ad\u0301"),
        # Same combining class: the sort is stable, so order is significant.
        ("a\u0316\u0323", "a\u0323\u0316"),
    ]
    for a, b in pairs_differ:
        assert fold(a) != fold(b), "expected fold-unequal: %r vs %r" % (a, b)

    if not quiet:
        print("selftest: %d codepoints cross-checked against unicodedata %s"
              % (checked, unicodedata.unidata_version))


def fixture_cases(di):
    """Inputs whose folded form the Rust reader is pinned against."""
    import random
    rng = random.Random(0)
    marks = [0x0300, 0x0301, 0x0316, 0x0323, 0x0327, 0x0334, 0x05B0, 0x093C, 0x3099]
    bases = [ord(c) for c in "aAqQ\u00e9\u00c9\u00df\u1e9e\u0130\u03a3\u03c2\u0410\u0430"
             "\uac00\ud55c\u1100\u1161\u4e2d\U0001f600"]
    ignorable = sorted(di)[:64]

    cases = ["", "a", "ABC", "Stra\u00dfe", "STRASSE", "\u00c9cole", "\u00e9cole",
             "\u0130stanbul", "\u03a3\u03c2\u03c3", "\uac00\ud55c\uad6d",
             "\u1100\u1161\u1112\u1161\u11ab", ".", "..", "a" * 255,
             "\u0301abc", "\u0323\u0301", "\u00ad", "a\u00ad\u0301"]
    for _ in range(400):
        n = rng.randint(1, 8)
        s = []
        for _ in range(n):
            s.append(chr(rng.choice(bases)))
            for _ in range(rng.randint(0, 3)):
                s.append(chr(rng.choice(marks)))
            if rng.random() < 0.2:
                s.append(chr(rng.choice(ignorable)))
        cases.append("".join(s))
    return cases


def write_fixtures(path):
    di, ccc_pairs, nfdi, nfdicf = build_tables()
    ccc_map = dict(ccc_pairs)
    ccc_of = lambda cp: ccc_map.get(cp, 0)
    out = ["# Generated by tools/mkutf8data/mkutf8data.py -- do not edit.",
           "# <input utf-8, hex> <case-folded normalized form, hex>",
           "# unicode %s" % unicodedata.unidata_version]
    for s in fixture_cases(di):
        folded = reader_normalize(s, nfdicf, di, ccc_of)
        out.append("%s %s" % (s.encode("utf-8").hex(), folded.encode("utf-8").hex()))
    open(path, "w").write("\n".join(out) + "\n")
    return len(out) - 3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed blob differs from a fresh generation")
    ap.add_argument("--no-selftest", action="store_true")
    args = ap.parse_args()

    blob, stats = serialize()
    if not args.no_selftest:
        selftest()

    if args.check:
        with open(BLOB_PATH, "rb") as f:
            have = f.read()
        if have != blob:
            print("utf8data.bin is stale: regenerate with tools/mkutf8data/mkutf8data.py",
                  file=sys.stderr)
            return 1
        print("utf8data.bin matches unicodedata %s" % stats["unicode"])
        return 0

    with open(BLOB_PATH, "wb") as f:
        f.write(blob)
    print("wrote %s: %d fold cases" % (FIXTURE_PATH, write_fixtures(FIXTURE_PATH)))
    print("wrote %s: %d bytes, unicode %s, ccc=%d ign=%d nfdi=%d nfdicf=%d pool=%d"
          % (BLOB_PATH, stats["bytes"], stats["unicode"], stats["ccc_ranges"],
             stats["ign_ranges"], stats["nfdi"], stats["nfdicf"], stats["pool"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
