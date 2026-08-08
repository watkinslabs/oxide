#!/usr/bin/env python3
"""Audit process-global state that a hosted test suite can reach unowned.

The same defect has been found four times by accident, each time after it
flaked (`scratch/issues.d/B1949`, `B1955`, `B1956`, `B1957`). Its shape never
changes: a hosted test binary is ONE process, libtest runs its bodies on many
threads, and some state the code under test consults is global to that process
rather than private to a test. A fixture takes a private `Mutex`/`RwLock` so
its OWN tests do not race each other -- and nothing structurally requires any
other test to take it. `Mutex` excludes holders; it cannot exclude a
non-holder. So the next test written forgets, and the suite flakes months
later under an unrelated change.

The precondition is grep-able, which is what this tool does. It enumerates the
candidates and answers, per candidate, the one question that separates a fixed
crate from a flake waiting to happen:

    does an accessor assert ownership at the choke point every path passes
    through, or does correctness rest on a convention a test can forget?

A crate that has been fixed carries the answer in its source: a claim module
holding a per-thread depth counter raised on acquire and lowered in `Drop`,
plus an `assert_*` called from the ONE function every entry path crosses.
That structure is the single source of truth for "guarded" -- there is no
hand-maintained list of blessed choke points here, because a second list is a
second thing to forget.

Rules, each independently diagnosable:

  fixture-lock      a test-declared serialisation static (unit-payload
                    Mutex/RwLock) whose ownership nothing enforces.
  fixture-state     a test-declared static carrying a payload -- mock records,
                    counters, installed hooks -- shared by the whole binary.
  singleton-pin     test code calls a parameterless production accessor that
                    returns process-global state, pinning every test in the
                    binary to one instance.
  hosted-selection  a global with two cfg-selected definitions where the
                    discriminant is `test` or a feature rather than the
                    target: a downstream crate that forgets the feature then
                    compiles the per-CPU storage into a hosted build, where
                    every libtest worker shares one slot (`B1956`).

Exit status is 0 when every unguarded candidate is already recorded in the
backlog file and none has been fixed-but-not-removed. A NEW unguarded
candidate fails at PR time, which is the whole point: the backlog can only
shrink.
"""
import contextlib, io, os, re, sys, tempfile

BACKLOG = "tools/hosted-global-state-backlog.tsv"
ROOTS = ("crates",)
SKIP_DIRS = {"target", "vendor", "vendors", ".git", "node_modules"}

# Types whose value is mutable through a shared reference, i.e. every one of
# them is a way for two libtest worker threads to see each other.
GLOBAL_TY = re.compile(
    r"\b(Mutex|RwLock|Spinlock|SpinLock|RwSpinlock|Atomic[A-Za-z0-9]+|OnceLock|"
    r"OnceCell|Once|Lazy|LazyLock|RefCell|UnsafeCell|SyncUnsafeCell|Cell)\b")
UNIT_PAYLOAD = re.compile(r"\b(Mutex|RwLock|Spinlock|SpinLock)\s*<\s*\(\s*\)\s*>")
STATIC_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?static\s+(mut\s+)?([A-Z_][A-Z_0-9]*)\s*:\s*(.+?)\s*=",
                         re.M)
FN_DECL = re.compile(r"\bfn\s+([a-z_][a-z_0-9]*)\s*\(")
# A parameterless accessor cannot be handed a key, so every caller in the
# process necessarily lands on the same instance.
NOARG_PUB_FN = re.compile(r"^\s*pub(?:\([^)]*\))?\s+fn\s+([a-z_][a-z_0-9]*)\s*\(\s*\)", re.M)
KERNEL_GATE = 'target_os = "oxide-kernel"'
TESTY_STEMS = ("tests", "test_support", "test_claim", "hosted_fixture", "test_util")


def is_testy_path(rel):
    """True when the file exists only to serve tests."""
    parts = rel.split(os.sep)
    if "tests" in parts[:-1]:
        return True
    stem = os.path.basename(rel)[:-3]
    return stem in TESTY_STEMS or stem.endswith("_tests") or stem.startswith("test_")


def brace_region(text, open_at):
    """Return the index just past the block whose `{` is at or after open_at."""
    i = text.find("{", open_at)
    if i < 0:
        return len(text)
    depth = 0
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text)


def attr_regions(text, needle):
    """Spans of `#[cfg(<needle>...)] mod x { .. }` / fn / impl blocks."""
    spans = []
    for m in re.finditer(r"#\[cfg\([^\]]*" + re.escape(needle) + r"[^\]]*\)\]", text):
        end = brace_region(text, m.end())
        spans.append((m.start(), end))
    return spans


def in_spans(spans, pos):
    return any(a <= pos <= b for a, b in spans)


class Src:
    def __init__(self, path, crate, rel):
        self.path, self.crate, self.rel, self._tests = path, crate, rel, None
        with open(path, errors="replace") as fh:
            self.text = fh.read()
        self.file_gated = re.search(r"#!\[cfg\([^\]]*" + re.escape(KERNEL_GATE), self.text) is not None
        self.file_test_only = re.search(r"#!\[cfg\(test\)\]", self.text) is not None
        self.kernel_spans = attr_regions(self.text, KERNEL_GATE)
        self.test_spans = attr_regions(self.text, "test)") + attr_regions(self.text, "test,")
        self.testy = is_testy_path(rel)
        parts = rel.split(os.sep)
        self.binary = "lib" if parts[0] == "src" else (
            "tests/" + parts[1][:-3] if parts[0] == "tests" and len(parts) == 2 else
            "tests/" + parts[1] if parts[0] == "tests" else None)

    def line_of(self, pos):
        return self.text.count("\n", 0, pos) + 1

    def hosted(self, pos):
        return not self.file_gated and not in_spans(self.kernel_spans, pos)

    def test_scope(self, pos):
        return self.testy or self.file_test_only or in_spans(self.test_spans, pos)

    def test_fns(self):
        """(name, body) per `#[test]`, brace-matched so bodies do not bleed."""
        if self._tests is not None:
            return self._tests
        out = []
        for m in re.finditer(r"#\[(?:tokio::)?test[^\]]*\]", self.text):
            f = FN_DECL.search(self.text, m.end())
            if not f or f.start() - m.end() > 400:
                continue
            out.append((f.group(1), self.text[f.end():brace_region(self.text, f.end()) + 1]))
        self._tests = out
        return out


def crate_of(path, root):
    d = os.path.dirname(path)
    while len(d) >= len(root):
        cargo = os.path.join(d, "Cargo.toml")
        if os.path.exists(cargo):
            with open(cargo, errors="replace") as fh:
                m = re.search(r'^\s*name\s*=\s*"([^"]+)"', fh.read(), re.M)
            return (m.group(1) if m else os.path.basename(d)), d
        d = os.path.dirname(d)
    return None, None


def collect(base):
    srcs = []
    for root in ROOTS:
        top = os.path.join(base, root)
        for dirpath, dirnames, files in os.walk(top):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for f in files:
                if not f.endswith(".rs"):
                    continue
                path = os.path.join(dirpath, f)
                name, cdir = crate_of(path, top)
                if not name:
                    continue
                rel = os.path.relpath(path, cdir)
                s = Src(path, name, rel)
                if s.binary:
                    srcs.append(s)
    return srcs


def claim_modules(srcs):
    """Files that implement the enforced-ownership structure, and their reach.

    A claim module holds a per-thread depth counter and at least one `assert_*`
    that reads it. It only COUNTS as a guard once that assertion is called from
    a file which is not itself test-only -- i.e. from the choke point on the
    ordinary path, which is the one place a forgetful test cannot avoid.
    """
    claims, asserts = {}, {}
    for s in srcs:
        if "thread_local!" not in s.text or "Cell" not in s.text:
            continue
        names = [m.group(1) for m in re.finditer(r"\bfn\s+(assert_[a-z_0-9]+)\s*\(", s.text)]
        if names:
            claims[s.path] = names
            for n in names:
                asserts.setdefault((s.crate, n), s.path)
    enforced = set()
    for s in srcs:
        if s.testy:
            continue
        for (crate, name), decl in asserts.items():
            if crate == s.crate and s.path != decl and re.search(r"\b" + name + r"\s*\(", s.text):
                enforced.add(decl)
    return {p: ns for p, ns in claims.items() if p in enforced}


class Cand:
    def __init__(self, rule, src, name, line, detail):
        self.rule, self.src, self.name, self.line, self.detail = rule, src, name, line, detail
        self.guarded, self.exposure, self.claimants = False, 0, 0

    def exposed(self):
        """True when a test in this binary reaches the state without claiming.

        `claimants == exposure` means the convention currently holds for every
        test in the binary: nobody has forgotten yet. That is not a guarantee,
        but it is not today's defect either -- and the moment a test is added
        that does not claim, this turns true and the gate fails, which is the
        occurrence the four incidents were.
        """
        return self.exposure > 0 and self.claimants < self.exposure

    def key(self):
        return (self.src.crate + "/" + self.src.rel.replace(os.sep, "/"), self.name, self.rule)


# `thread_local!` storage is per OS thread, so two libtest workers cannot see
# each other through it -- it is the FIX the fixed crates use, not the defect.
def thread_local_spans(text):
    return [(m.start(), brace_region(text, m.end()))
            for m in re.finditer(r"\bthread_local!\s*", text)]


# Initialise-once storage whose payload is immutable hands every observer the
# same value and can carry nothing from one test to the next.
IMMUTABLE_ONCE = re.compile(r"^\s*(?:std::sync::|core::cell::|once_cell::[a-z:]*)?"
                            r"(Once|OnceLock|OnceCell|Lazy|LazyLock)\s*(<(?P<p>.*)>)?\s*$")


def carries_state(ty):
    m = IMMUTABLE_ONCE.match(ty.strip())
    if not m:
        return True
    return bool(GLOBAL_TY.search(m.group("p") or ""))


def find_statics(srcs, guarded_files):
    out = []
    for s in srcs:
        tls = thread_local_spans(s.text)
        for m in STATIC_DECL.finditer(s.text):
            mut, name, ty = m.group(1), m.group(2), m.group(3)
            if not (mut or GLOBAL_TY.search(ty)):
                continue
            if in_spans(tls, m.start()) or not (mut or carries_state(ty)):
                continue
            if not s.hosted(m.start()) or not s.test_scope(m.start()):
                continue
            rule = "fixture-lock" if UNIT_PAYLOAD.search(ty) else "fixture-state"
            c = Cand(rule, s, name, s.line_of(m.start()), ty.strip())
            c.guarded = s.path in guarded_files
            out.append(c)
    return out


def find_singletons(srcs, guarded_files):
    """Parameterless production accessors over module-global state, called from tests."""
    accessors = {}
    for s in srcs:
        if s.testy or s.binary != "lib":
            continue
        statics = {m.group(2) for m in STATIC_DECL.finditer(s.text)
                   if GLOBAL_TY.search(m.group(3) or "")}
        if not statics:
            continue
        for m in NOARG_PUB_FN.finditer(s.text):
            if not s.hosted(m.start()) or s.test_scope(m.start()):
                continue
            body = s.text[m.end():brace_region(s.text, m.end()) + 1]
            hit = [g for g in statics if re.search(r"\b" + g + r"\b", body)]
            if hit:
                accessors[(s.crate, m.group(1))] = (s, sorted(hit)[0], s.line_of(m.start()))
    # A pin is answered by a choke point on EITHER side: the crate that owns
    # the singleton can assert on entry, or the calling crate can assert at the
    # one function its own tests reach the singleton through -- which is where
    # the three fixed crates put it, because that is where the tests are.
    guarded_crates = {s.crate for s in srcs if s.path in guarded_files}
    out, seen = [], set()
    for s in srcs:
        callers = s.test_fns()
        if not callers:
            continue
        for (crate, fn), (decl, gname, dline) in accessors.items():
            if crate == s.crate and decl.path == s.path:
                continue
            qualified = re.compile(r"\b(?:" + re.escape(crate.replace("-", "_")) +
                                   r"|crate|self|super)\s*::(?:\s*[a-z_][a-z_0-9]*\s*::)*\s*"
                                   + fn + r"\s*\(\s*\)")
            n = sum(1 for _, body in callers if qualified.search(body))
            if not n:
                continue
            k = (s.crate, s.binary, crate, fn)
            if k in seen:
                continue
            seen.add(k)
            c = Cand("singleton-pin", s, f"{crate}::{fn}", 0,
                     f"pins {crate}::{gname}; {n} test(s) in this binary")
            c.claimants, c.exposure = n, len(callers)
            c.guarded = crate in guarded_crates or s.crate in guarded_crates
            out.append(c)
    return out


def find_hosted_selection(srcs):
    """A global whose storage is chosen by `test`/feature rather than by target."""
    out = []
    for s in srcs:
        defs = {}
        for m in re.finditer(r"#\[cfg\(([^\]]*)\)\]\s*(?:pub(?:\([^)]*\))?\s+)?"
                             r"(?:static\s+(?:mut\s+)?([A-Z_][A-Z_0-9]*)|thread_local!)", s.text):
            cfg, name = m.group(1), m.group(2)
            if name is None:
                blk = s.text[m.end():brace_region(s.text, m.end()) + 1]
                got = re.search(r"static\s+([A-Z_][A-Z_0-9]*)", blk)
                if not got:
                    continue
                name = got.group(1)
            defs.setdefault(name, []).append((cfg, s.line_of(m.start())))
        for name, seen in defs.items():
            if len(seen) < 2:
                continue
            if all("target_os" in cfg or "target_arch" in cfg for cfg, _ in seen):
                continue
            bad = [(cfg, ln) for cfg, ln in seen
                   if re.search(r"\btest\b", cfg) or "feature" in cfg]
            if not bad:
                continue
            c = Cand("hosted-selection", s, name, bad[0][1],
                     "storage selected by " + "; ".join(cfg for cfg, _ in seen))
            out.append(c)
    return out


def accessors_of(src, name):
    """Functions in the declaring file whose body touches the static.

    Matching every `fn` in the file instead over-counts claimants -- a test
    that calls an unrelated helper would read as having taken the lock, which
    is precisely the false assurance this tool exists to remove.
    """
    out = set()
    for m in FN_DECL.finditer(src.text):
        body = src.text[m.end():brace_region(src.text, m.end()) + 1]
        if re.search(r"\b" + re.escape(name) + r"\b", body):
            out.add(m.group(1))
    return out


def measure_exposure(cands, srcs):
    """How many tests share the binary, and how many reference the owner module."""
    per_binary = {}
    for s in srcs:
        per_binary.setdefault((s.crate, s.binary), []).append(s)
    for c in cands:
        if c.rule == "singleton-pin":
            continue
        files = per_binary.get((c.src.crate, c.src.binary), [])
        owner = {c.name} | accessors_of(c.src, c.name)
        total = claim = 0
        for f in files:
            for _, body in f.test_fns():
                total += 1
                if any(re.search(r"\b" + re.escape(n) + r"\b", body) for n in owner):
                    claim += 1
        c.exposure, c.claimants = total, claim


def read_backlog(base):
    path = os.path.join(base, BACKLOG)
    rows = {}
    if not os.path.exists(path):
        return rows
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            f = line.split("\t")
            if len(f) != 4:
                rows[("MALFORMED", str(n), "")] = line
                continue
            rows[(f[0], f[1], f[2])] = f[3]
    return rows


def audit(base):
    srcs = collect(base)
    guarded_files = set(claim_modules(srcs))
    cands = find_statics(srcs, guarded_files) + find_singletons(srcs, guarded_files) \
        + find_hosted_selection(srcs)
    measure_exposure(cands, srcs)
    cands.sort(key=lambda c: (c.rule, c.key()))
    return cands


def report(cands, listing=False):
    for c in cands:
        if listing or not c.guarded:
            where = f"{c.key()[0]}:{c.line}" if c.line else c.key()[0]
            mark = "GUARDED  " if c.guarded else "UNGUARDED"
            print(f"{mark} {c.rule:17} {where} {c.name} "
                  f"[{c.claimants}/{c.exposure} tests claim] {c.detail}")


def main(base=".", listing=False):
    cands = audit(base)
    backlog = read_backlog(base)
    bad = 0
    for k, v in backlog.items():
        if k[0] == "MALFORMED":
            print(f"hosted-global-audit: {BACKLOG}:{k[1]}: expected 4 tab-separated fields "
                  f"(path, name, rule, reason)")
            bad += 1
        elif not v.strip():
            print(f"hosted-global-audit: {BACKLOG}: {k[0]} {k[1]} has no reason -- "
                  f"a backlog row is a claim on future work, not permission")
            bad += 1
    unguarded = {c.key(): c for c in cands if not c.guarded and c.exposed()}
    for k, c in sorted(unguarded.items()):
        if k in backlog:
            continue
        at = f"{k[0]}:{c.line}" if c.line else k[0]
        print(f"{at}: {c.rule} `{c.name}` is unowned -- "
              f"{c.claimants}/{c.exposure} tests in this binary claim it, and nothing "
              f"makes the rest; add a choke-point assertion or record it in {BACKLOG}")
        bad += 1
    for k in sorted(backlog):
        if k[0] == "MALFORMED" or k in unguarded:
            continue
        print(f"{BACKLOG}: {k[0]} `{k[1]}` ({k[2]}) is no longer unguarded -- "
              f"delete the row so the backlog can only shrink")
        bad += 1
    if listing:
        report(cands, listing=True)
    if bad:
        print(f"hosted-global-audit: FAIL ({bad} problem(s))")
        return 1
    guarded = sum(1 for c in cands if c.guarded)
    print(f"hosted-global-audit: ok ({len(cands)} candidates: {guarded} guarded, "
          f"{len(cands) - guarded - len(unguarded)} claimed by every test in their binary, "
          f"{len(unguarded)} in backlog)")
    return 0


# ---- self-test -------------------------------------------------------------
#
# Each mutant injects ONE defect into an otherwise clean fixture tree and
# requires that defect's own diagnostic, so a rule cannot pass by tripping
# another rule's check. Green controls prove the tool stays silent on the
# shapes it must NOT flag -- an enforced choke point, and a target-selected
# global.

CARGO = '[package]\nname = "fixt"\nversion = "0.0.0"\n'

CLEAN_SRC = """
pub struct Claim;
std::thread_local! { static DEPTH: core::cell::Cell<u32> = const { core::cell::Cell::new(0) }; }
static OWNED: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(crate) fn assert_owned() { assert!(DEPTH.with(core::cell::Cell::get) > 0, "held"); }
pub(crate) fn claim() -> Claim { let _g = OWNED.lock(); Claim }
"""

CHOKE_SRC = """
pub fn admit() { crate::test_support::assert_owned(); }
#[test]
fn a_test_that_claims() { let _c = crate::test_support::claim(); admit(); }
"""


def write_fixture(td, files):
    root = os.path.join(td, "crates", "fixt")
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    with open(os.path.join(root, "Cargo.toml"), "w") as fh:
        fh.write(CARGO)
    for rel, body in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(body)
    return td


def selftest_run(files, backlog=None):
    with tempfile.TemporaryDirectory(prefix="hosted-global-selftest-") as td:
        write_fixture(td, files)
        if backlog is not None:
            os.makedirs(os.path.join(td, "tools"), exist_ok=True)
            with open(os.path.join(td, BACKLOG), "w") as fh:
                fh.write(backlog)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(td)
        return rc, buf.getvalue().splitlines()


def case(name, files, want_rc, want, backlog=None):
    rc, lines = selftest_run(files, backlog)
    if rc != want_rc or lines != want:
        print(f"hosted-global-audit self-test: FAIL {name}: got rc={rc}, lines={lines!r}; "
              f"want rc={want_rc}, lines={want!r}")
        return 1
    return 0


def selftest():
    fail = 0
    base = {"src/test_support.rs": CLEAN_SRC, "src/work.rs": CHOKE_SRC}
    fail += case("green-enforced-choke-point", base, 0,
                 ["hosted-global-audit: ok (1 candidates: 1 guarded, 0 claimed by every test in their binary, 0 in backlog)"])

    # Green control: hosted-ness chosen by TARGET is the correct shape and must
    # not be confused with the feature-selected one below.
    tgt = dict(base)
    tgt["src/count.rs"] = (
        '#[cfg(target_os = "oxide-kernel")] static COUNT: AtomicU32 = AtomicU32::new(0);\n'
        '#[cfg(not(target_os = "oxide-kernel"))] static COUNT: AtomicU32 = AtomicU32::new(0);\n')
    fail += case("green-target-selected-global", tgt, 0,
                 ["hosted-global-audit: ok (1 candidates: 1 guarded, 0 claimed by every test in their binary, 0 in backlog)"])

    # Green control: a backlog row that still describes an unguarded candidate.
    lock = dict(base)
    lock["src/tests.rs"] = ("static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());\n"
                            "#[test] fn one() { let _g = SERIAL.lock(); }\n"
                            "#[test] fn two() { let _ = 1; }\n")
    fail += case("green-backlogged-row", lock, 0,
                 ["hosted-global-audit: ok (2 candidates: 1 guarded, 0 claimed by every test in their binary, 1 in backlog)"],
                 backlog="fixt/src/tests.rs\tSERIAL\tfixture-lock\tclaimed by C999\n")

    fail += case("fixture-lock", lock, 1, [
        "fixt/src/tests.rs:1: fixture-lock `SERIAL` is unowned -- 1/3 tests in this binary "
        f"claim it, and nothing makes the rest; add a choke-point assertion or record it in {BACKLOG}",
        "hosted-global-audit: FAIL (1 problem(s))",
    ])

    state = dict(base)
    state["src/tests.rs"] = ("static SEEN: std::sync::Mutex<Vec<u8>> = "
                             "std::sync::Mutex::new(Vec::new());\n"
                             "#[test] fn one() { let _ = &SEEN; }\n")
    fail += case("fixture-state", state, 1, [
        "fixt/src/tests.rs:1: fixture-state `SEEN` is unowned -- 1/2 tests in this binary "
        f"claim it, and nothing makes the rest; add a choke-point assertion or record it in {BACKLOG}",
        "hosted-global-audit: FAIL (1 problem(s))",
    ])

    # The singleton case needs a crate with no enforced choke point at all, so
    # the clean support module is deliberately absent here.
    pin = {"src/reg.rs": ("static REGISTRY: std::sync::Mutex<u32> = std::sync::Mutex::new(0);\n"
                          "pub fn initial() -> u32 { *REGISTRY.lock().unwrap() }\n"),
           "src/tests.rs": ("#[test] fn one() { let _ = crate::reg::initial(); }\n"
                            "#[test] fn two() { let _ = 1; }\n")}
    fail += case("singleton-pin", pin, 1, [
        "fixt/src/tests.rs: singleton-pin `fixt::initial` is unowned -- 1/2 tests in this "
        "binary claim it, and nothing makes the rest; add a choke-point assertion or record "
        f"it in {BACKLOG}",
        "hosted-global-audit: FAIL (1 problem(s))",
    ])

    sel = dict(base)
    sel["src/count.rs"] = (
        '#[cfg(any(test, feature = "hosted"))] static COUNT: AtomicU32 = AtomicU32::new(0);\n'
        '#[cfg(not(any(test, feature = "hosted")))] static COUNT: AtomicU32 = AtomicU32::new(0);\n')
    fail += case("hosted-selection", sel, 1, [
        'fixt/src/count.rs:1: hosted-selection `COUNT` is unowned -- 0/1 tests in this binary '
        'claim it, and nothing makes the rest; add a choke-point assertion or record it in '
        f'{BACKLOG}',
        "hosted-global-audit: FAIL (1 problem(s))",
    ])

    # A claim module whose assertion nothing calls is exactly the convention the
    # four incidents relied on; it must NOT read as guarded.
    unenforced = {"src/test_support.rs": CLEAN_SRC,
                  "src/work.rs": ("#[test]\nfn a_test() { let _c = crate::test_support::claim(); }\n"
                                  "#[test]\nfn forgetful() { let _ = 1; }\n")}
    fail += case("unenforced-claim-module", unenforced, 1, [
        "fixt/src/test_support.rs:4: fixture-lock `OWNED` is unowned -- 1/2 tests in this binary "
        f"claim it, and nothing makes the rest; add a choke-point assertion or record it in {BACKLOG}",
        "hosted-global-audit: FAIL (1 problem(s))",
    ])

    fail += case("stale-backlog-row", base, 1, [
        f"{BACKLOG}: fixt/src/gone.rs `GONE` (fixture-lock) is no longer unguarded -- "
        "delete the row so the backlog can only shrink",
        "hosted-global-audit: FAIL (1 problem(s))",
    ], backlog="fixt/src/gone.rs\tGONE\tfixture-lock\tclaimed by C999\n")

    fail += case("backlog-row-without-reason", lock, 1, [
        f"hosted-global-audit: {BACKLOG}: fixt/src/tests.rs SERIAL has no reason -- "
        "a backlog row is a claim on future work, not permission",
        "hosted-global-audit: FAIL (1 problem(s))",
    ], backlog="fixt/src/tests.rs\tSERIAL\tfixture-lock\t\n")

    fail += case("malformed-backlog-row", base, 1, [
        f"hosted-global-audit: {BACKLOG}:1: expected 4 tab-separated fields "
        "(path, name, rule, reason)",
        "hosted-global-audit: FAIL (1 problem(s))",
    ], backlog="fixt/src/tests.rs\tSERIAL\n")

    if fail:
        return 1
    print("hosted-global-audit: self-test PASS (8 isolated mutants, 3 green controls)")
    return 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--self-test" in argv:
        sys.exit(selftest())
    if "--write-backlog" in argv:
        rows = sorted([c for c in audit(".") if not c.guarded and c.exposed()],
                      key=lambda c: c.key())
        with open(BACKLOG, "w") as fh:
            fh.write("# Unguarded process-global state a hosted test suite can reach.\n"
                     "# Fields: path\\tname\\trule\\treason. A row is a claim on future work,\n"
                     "# never permission for the defect (CLAUDE.md). Delete a row when the\n"
                     "# candidate gains a choke-point assertion; the gate refuses stale rows.\n")
            for c in {c.key(): c for c in rows}.values():
                fh.write(f"{c.key()[0]}\t{c.name}\t{c.rule}\tunclaimed; "
                         f"{c.claimants}/{c.exposure} tests claimed it at the C294 baseline\n")
        print(f"hosted-global-audit: wrote {len(rows)} rows to {BACKLOG}")
        sys.exit(0)
    sys.exit(main(".", listing="--list" in argv))
