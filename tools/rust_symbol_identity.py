#!/usr/bin/env python3
"""Stable identity for a Rust symbol — what the stack gates key their lists on.

WHY THIS EXISTS
---------------
A mangled symbol is not stable across builds. Rust `v0` mangling embeds a crate
DISAMBIGUATOR (`Cs4Ogy96R9r3j_`) that is a hash of the crate's name, version and
the metadata flags it was compiled with, so the same source function is a
different string in a default build than in a `--features debug-all` build:

  _RNvNtNtCseQ963CMHBD6_5kmain5kmain5entry11kernel_main
  _RNvNtNtCs1Yf3GkQE07G_5kmain5kmain5entry11kernel_main

Keying an allowlist on that made the gate's verdict depend on WHICH build last
exported `target/artifacts`: the same tree passed or failed on build provenance
alone. The legacy `_ZN..17h<16 hex>E` mangling has the same problem in its
trailing hash. An unreliable gate gets disabled, and the class it guards comes
back — so identity is the demangled path, which survives a disambiguator change.

WHY DEMANGLE RATHER THAN STRIP
------------------------------
Deleting `Cs<hash>_` textually looks cheaper and is wrong twice. `v0` back
references (`B<base-62>_`) are BYTE OFFSETS into the mangled string, so removing
bytes silently re-points them; and the disambiguator is base-62, so its own
LENGTH varies (11 digits usually, 10 about one crate in 62) and shifts every
offset after it even when nothing else changed. Only a parse resolves the
offsets, so this demangles for real.

The result is also what a reviewer wants to read in an allowlist.

PRECISION
---------
Identity must not collide two genuinely different functions:

  * A monomorphised generic keeps its arguments — `Driver::probe` instantiated
    for `VirtioSndOps` and for `VirtioGpuOps` are two identities, not one.
  * A closure keeps its index — `foo::{closure#0}` and `foo::{closure#1}`.
  * A trait impl keeps its self type and trait — `<T as Trait>::method`.

What is deliberately dropped: crate disambiguators, the legacy hash, and the
`.llvm.<hash>` suffix LLVM appends to internal-linkage clones. Two symbols CAN
still share an identity (two versions of one crate in the graph; a `.llvm.`
clone alongside its original), so callers must treat identity as many-to-one and
resolve a group conservatively — the deepest member owns the budget.

Non-Rust symbols (`_start`, `oxide_syscall_entry`) are already stable and are
returned unchanged.
"""

import re

# `.llvm.14624981511977 `-style suffixes on internal-linkage clones: the number
# is a per-build hash. Other suffixes (`.cold`, `.part.0`) name a real, distinct
# piece of code and are kept.
LLVM_SUFFIX = re.compile(r"\.llvm\.[0-9A-Za-z_]+$")

# Fallback only, when a symbol will not parse: `Cs<base-62>_` crate
# disambiguators. Offsets are then wrong, so this is strictly a last resort.
V0_DISAMBIG = re.compile(r"Cs[0-9A-Za-z]{1,16}_")

# Legacy mangling's trailing `17h<16 hex>` component.
LEGACY_HASH = re.compile(r"^h[0-9a-f]{16}$")

BASIC_TYPES = {
    "a": "i8", "b": "bool", "c": "char", "d": "f64", "e": "str", "f": "f32",
    "h": "u8", "i": "isize", "j": "usize", "l": "i32", "m": "u32", "n": "i128",
    "o": "u128", "s": "i16", "t": "u16", "u": "()", "v": "...", "x": "i64",
    "y": "u64", "z": "!", "p": "_",
}

# `$LT$`-style escapes in legacy mangling.
LEGACY_ESCAPES = {
    "$SP$": "@", "$BP$": "*", "$RF$": "&", "$LT$": "<", "$GT$": ">",
    "$LP$": "(", "$RP$": ")", "$C$": ",", "$u7e$": "~", "$u20$": " ",
    "$u27$": "'", "$u5b$": "[", "$u5d$": "]", "$u7b$": "{", "$u7d$": "}",
    "$u3b$": ";", "$u2b$": "+", "$u21$": "!", "$u22$": '"',
}


class DemangleError(Exception):
    pass


class V0:
    """Recursive-descent `v0` demangler (RFC 2603 grammar).

    Back references are followed by re-entering the same string at the recorded
    offset, which is the whole reason this parses instead of pattern-matching.
    """

    MAX_DEPTH = 300

    def __init__(self, s):
        self.s = s
        self.pos = 0
        self.depth = 0
        self.binders = 0          # bound-lifetime depth, for `'a` naming

    # -- primitives ---------------------------------------------------------
    def peek(self):
        return self.s[self.pos] if self.pos < len(self.s) else ""

    def take(self):
        if self.pos >= len(self.s):
            raise DemangleError("truncated")
        c = self.s[self.pos]
        self.pos += 1
        return c

    def eat(self, c):
        if self.peek() == c:
            self.pos += 1
            return True
        return False

    def base62(self):
        """`{digit|a-z|A-Z}* '_'` — empty is 0, otherwise value+1."""
        digits = ""
        while self.peek() and self.peek() != "_":
            digits += self.take()
        if not self.eat("_"):
            raise DemangleError("unterminated base-62")
        if not digits:
            return 0
        v = 0
        for c in digits:
            if c.isdigit():
                d = ord(c) - ord("0")
            elif c.islower():
                d = ord(c) - ord("a") + 10
            elif c.isupper():
                d = ord(c) - ord("A") + 36
            else:
                raise DemangleError(f"bad base-62 digit {c!r}")
            v = v * 62 + d
        return v + 1

    def disambiguator(self):
        # `s_` is the FIRST disambiguated occurrence, i.e. 1 — absence is 0.
        return self.base62() + 1 if self.eat("s") else 0

    def ident(self):
        punycode = self.eat("u")
        # A leading `0` IS the whole length — `00` is a zero-length name (a
        # closure) followed by the next component, not the number zero twice.
        if self.peek() == "0":
            digits = self.take()
        else:
            digits = ""
            while self.peek().isdigit():
                digits += self.take()
        if not digits:
            raise DemangleError("identifier without length")
        self.eat("_")                       # separator before a leading digit
        n = int(digits)
        if self.pos + n > len(self.s):
            raise DemangleError("identifier past end")
        name = self.s[self.pos:self.pos + n]
        self.pos += n
        # Punycode names are vanishingly rare in this tree; keeping them raw
        # is deterministic, which is all identity needs.
        return f"punycode${name}" if punycode else name

    def backref(self, printer):
        """`B<base-62>_` — parse `printer` at that absolute offset."""
        off = self.base62()
        if off >= len(self.s):
            raise DemangleError("back reference past end")
        here = self.pos
        self.pos = off
        try:
            return printer()
        finally:
            self.pos = here

    def nest(self, f):
        self.depth += 1
        if self.depth > self.MAX_DEPTH:
            raise DemangleError("recursion limit")
        try:
            return f()
        finally:
            self.depth -= 1

    # -- grammar ------------------------------------------------------------
    def path(self, in_value=False):
        return self.nest(lambda: self._path(in_value))

    def _path(self, in_value):
        tag = self.take()
        if tag == "C":
            self.disambiguator()            # the unstable part, dropped
            return self.ident()
        if tag == "M":
            self.impl_path()
            return f"<{self.type()}>"
        if tag == "X":
            self.impl_path()
            t = self.type()
            return f"<{t} as {self.path()}>"
        if tag == "Y":
            t = self.type()
            return f"<{t} as {self.path()}>"
        if tag == "N":
            ns = self.take()
            parent = self.path(in_value)
            dis = self.disambiguator()
            name = self.ident()
            if ns.isupper():
                # Special namespace: closures and shims, where the index is
                # the only thing telling two of them apart.
                kind = {"C": "closure", "S": "shim"}.get(ns, ns)
                inner = f"{kind}:{name}" if name else kind
                return f"{parent}::{{{inner}#{dis}}}"
            return f"{parent}::{name}"
        if tag == "I":
            p = self.path(in_value)
            args = []
            while not self.eat("E"):
                args.append(self.generic_arg())
            sep = "::" if in_value else ""
            return f"{p}{sep}<{', '.join(args)}>"
        if tag == "B":
            return self.backref(lambda: self.path(in_value))
        raise DemangleError(f"bad path tag {tag!r}")

    def impl_path(self):
        """Parsed and discarded — the module an impl lives in is not part of
        the name any Rust reader would write, and rustc's own demangler drops
        it too. It must still be CONSUMED so offsets stay right."""
        self.disambiguator()
        self.path()

    def lifetime(self, idx=None):
        if idx is None:
            idx = self.base62()
        if idx == 0:
            return "'_"
        depth = self.binders - idx
        return f"'{chr(ord('a') + depth)}" if 0 <= depth < 26 else f"'_{depth}"

    def binder(self):
        n = self.base62()
        self.binders += n
        return n

    def generic_arg(self):
        if self.eat("L"):
            return self.lifetime()
        if self.eat("K"):
            return self.const()
        return self.type()

    def type(self):
        return self.nest(self._type)

    def _type(self):
        c = self.peek()
        if c in BASIC_TYPES:
            # A basic type is a single char and never a path tag, but `p` and
            # the path tags overlap nowhere, so ordering here is safe.
            self.take()
            return BASIC_TYPES[c]
        tag = self.take()
        if tag == "A":
            t = self.type()
            return f"[{t}; {self.const()}]"
        if tag == "S":
            return f"[{self.type()}]"
        if tag == "T":
            parts = []
            while not self.eat("E"):
                parts.append(self.type())
            if len(parts) == 1:
                return f"({parts[0]},)"
            return f"({', '.join(parts)})"
        if tag in ("R", "Q"):
            lt = f"{self.lifetime()} " if self.eat("L") else ""
            mut = "mut " if tag == "Q" else ""
            return f"&{lt}{mut}{self.type()}"
        if tag == "P":
            return f"*const {self.type()}"
        if tag == "O":
            return f"*mut {self.type()}"
        if tag == "F":
            return self.fn_sig()
        if tag == "D":
            return self.dyn_bounds()
        if tag == "B":
            return self.backref(self.type)
        self.pos -= 1
        return self.path()

    def fn_sig(self):
        outer = self.binders
        if self.eat("G"):
            self.binder()
        unsafe = "unsafe " if self.eat("U") else ""
        abi = ""
        if self.eat("K"):
            abi = 'extern "C" ' if self.eat("C") else f'extern "{self.ident()}" '
        args = []
        while not self.eat("E"):
            args.append(self.type())
        ret = self.type()
        self.binders = outer
        tail = "" if ret == "()" else f" -> {ret}"
        return f"{unsafe}{abi}fn({', '.join(args)}){tail}"

    def dyn_bounds(self):
        outer = self.binders
        if self.eat("G"):
            self.binder()
        traits = []
        while not self.eat("E"):
            traits.append(self.dyn_trait())
        if not self.eat("L"):
            raise DemangleError("dyn bounds without trailing lifetime")
        idx = self.base62()
        self.binders = outer
        # An erased lifetime (0) is not printed: `dyn Trait`, not `dyn Trait + '_`.
        if idx:
            traits.append(self.lifetime(idx))
        return f"dyn {' + '.join(traits)}"

    def dyn_trait(self):
        p = self.path()
        bindings = []
        while self.eat("p"):
            name = self.ident()
            bindings.append(f"{name} = {self.type()}")
        if not bindings:
            return p
        if p.endswith(">"):
            return f"{p[:-1]}, {', '.join(bindings)}>"
        return f"{p}<{', '.join(bindings)}>"

    def const(self):
        if self.eat("B"):
            return self.backref(self.const)
        if self.eat("p"):
            return "_"
        ty = self.type()
        neg = self.eat("n")
        digits = ""
        while self.peek() and self.peek() != "_":
            digits += self.take()
        if not self.eat("_"):
            raise DemangleError("unterminated const")
        if not digits:
            return "0"
        v = int(digits, 16)
        if ty == "bool":
            return "true" if v else "false"
        if ty == "char":
            return f"'\\u{{{digits}}}'"
        return f"-{v}" if neg else str(v)


def demangle_v0(sym):
    p = V0(sym[2:])
    while p.peek().isdigit():          # encoding version, if a future one lands
        p.take()
    out = p.path(in_value=True)
    # A trailing instantiating-crate path and vendor suffix may follow; both
    # are build detail, so reaching a clean path is enough.
    return out


def demangle_legacy(sym):
    """`_ZN` length-prefixed components, minus the trailing `17h<hex>`."""
    body = sym[3:] if sym.startswith("_ZN") else sym[2:]
    parts, i = [], 0
    while i < len(body):
        if body[i] == "E":
            break
        j = i
        while j < len(body) and body[j].isdigit():
            j += 1
        if j == i:
            raise DemangleError("legacy component without length")
        n = int(body[i:j])
        if j + n > len(body):
            raise DemangleError("legacy component past end")
        parts.append(body[j:j + n])
        i = j + n
    if not parts:
        raise DemangleError("empty legacy symbol")
    if LEGACY_HASH.match(parts[-1]):
        parts.pop()
    out = "::".join(parts)
    for esc, ch in LEGACY_ESCAPES.items():
        out = out.replace(esc, ch)
    return out.replace("..", "::")


def identity(sym):
    """-> stable name for `sym`, unchanged if it is not a Rust symbol.

    Never raises: a symbol this cannot parse still needs A key, so it falls
    back to the raw string with crate disambiguators stripped. That fallback is
    only as stable as the offsets it leaves behind, so `unparsed()` exists to
    let a caller count how often it fires.
    """
    core = LLVM_SUFFIX.sub("", sym)
    # A surviving `.cold` / `.0` names a DISTINCT piece of code, so it is kept
    # on the end of the identity rather than folded into the base symbol.
    core, dot, suffix = core.partition(".")
    tail = dot + suffix
    try:
        if core.startswith("_R"):
            return demangle_v0(core) + tail
        if core.startswith("_ZN"):
            return demangle_legacy(core) + tail
    except (DemangleError, IndexError, ValueError):
        return V0_DISAMBIG.sub("C", core) + tail
    return core + tail


def unparsed(sym):
    """-> True when `identity` had to fall back instead of demangling."""
    core = LLVM_SUFFIX.sub("", sym)
    if not (core.startswith("_R") or core.startswith("_ZN")):
        return False
    try:
        demangle_v0(core) if core.startswith("_R") else demangle_legacy(core)
        return False
    except (DemangleError, IndexError, ValueError):
        return True


# Two builds of one tree differ only in these; anything the demangler keeps must
# survive them. Exercised by the gates' self-tests.
SELF_TEST_CASES = [
    # Same function, two crate disambiguators -> one identity.
    ("_RNvNtNtCseQ963CMHBD6_5kmain5kmain5entry11kernel_main",
     "kmain::kmain::entry::kernel_main"),
    ("_RNvNtNtCs1Yf3GkQE07G_5kmain5kmain5entry11kernel_main",
     "kmain::kmain::entry::kernel_main"),
    # Trait impl on a monomorphised generic: the argument is what tells two
    # instantiations apart, so it stays. Note the back references (`B5_`,
    # `B1b_`) — byte offsets that only a parse can resolve.
    ("_RNvXs5_NtNtCs9IRfSLnXgC5_6virtio9resources5childINtB5_17VirtioChildDriver"
     "NtNtCs6rZ8VyAfRRo_8pci_boot12virtio_child17PciVirtioChildBusNtB1b_12VirtioSndOps"
     "ENtNtCs41xDJckoIHG_3drv5model6Driver5probeB1d_",
     "<virtio::resources::child::VirtioChildDriver<pci_boot::virtio_child::PciVirtioChildBus, "
     "pci_boot::virtio_child::VirtioSndOps> as drv::model::Driver>::probe"),
    ("_RNvXs5_NtNtCs9IRfSLnXgC5_6virtio9resources5childINtB5_17VirtioChildDriver"
     "NtNtCs6rZ8VyAfRRo_8pci_boot12virtio_child17PciVirtioChildBusNtB1b_12VirtioGpuOps"
     "ENtNtCs41xDJckoIHG_3drv5model6Driver5probeB1d_",
     "<virtio::resources::child::VirtioChildDriver<pci_boot::virtio_child::PciVirtioChildBus, "
     "pci_boot::virtio_child::VirtioGpuOps> as drv::model::Driver>::probe"),
    # Legacy mangling: the trailing hash is the same kind of build detail.
    ("_ZN5sched4live8schedule6switch8schedule17h0123456789abcdefE",
     "sched::live::schedule::switch::schedule"),
    # Not a Rust symbol — already stable, returned as-is.
    ("_start", "_start"),
    ("oxide_syscall_dispatch", "oxide_syscall_dispatch"),
]


def self_test():
    for sym, want in SELF_TEST_CASES:
        got = identity(sym)
        assert got == want, f"{sym}\n  got  {got}\n  want {want}"
    # Closures differ by index, and nothing else.
    a = identity("_RNCNvNtCs1234_5crate3mod4func0")
    b = identity("_RNCNvNtCs1234_5crate3mod4funcs_0")
    assert a == "crate::mod::func::{closure#0}", a
    assert b == "crate::mod::func::{closure#1}", b
    # THE case textual stripping cannot handle. Same path, same generic
    # arguments, disambiguators of DIFFERENT LENGTH (11 digits vs 10) — so the
    # back reference to the second argument is `Bx_` in one and `Bv_` in the
    # other. Deleting `Cs..._` leaves two different strings; resolving the
    # offsets gives one identity.
    long_d = "_RINvNtCs1234567890a_5crate3mod4funcNtB2_3FooBx_E"
    short_d = "_RINvNtCs123456789_5crate3mod4funcNtB2_3FooBv_E"
    assert identity(long_d) == "crate::mod::func::<crate::mod::Foo, crate::mod::Foo>", identity(long_d)
    assert identity(long_d) == identity(short_d), (identity(long_d), identity(short_d))
    assert V0_DISAMBIG.sub("C", long_d) != V0_DISAMBIG.sub("C", short_d), \
        "this vector only proves something if stripping DOES differ"
    assert not unparsed(long_d)
    # A `.llvm.<hash>` clone folds onto its original; `.cold` and `.0` are real
    # distinct code and stay.
    assert identity("_RNvCs1234_5crate4func.llvm.9876543") == "crate::func"
    assert identity("_RNvCs1234_5crate4func.cold") == "crate::func.cold"
    # Garbage still yields a key rather than an exception.
    assert identity("_RNvNOTAVALIDSYMBOL") == "_RNvNOTAVALIDSYMBOL"
    print("rust-symbol-identity: self-test PASS "
          "(disambiguator, back-reference shift, generics, closures, legacy)")
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test())
