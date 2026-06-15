// fnmatch (docs/59§6 G8). Shell wildcard matching: *, ?, [..] (ranges +
// [!..]/[^..] negation), POSIX [:class:]/[.coll.]/[=equiv=] sub-brackets,
// with FNM_NOESCAPE / FNM_PATHNAME / FNM_PERIOD. The matcher runs on byte
// slices (oracle-tested vs host fnmatch); the C export converts the
// NUL-terminated args.
pub const FNM_NOMATCH: i32 = 1;
const FNM_PATHNAME: i32 = 1; // glibc bit values
const FNM_NOESCAPE: i32 = 2;
const FNM_PERIOD: i32 = 4;

// POSIX [:name:] character class membership (C locale, ASCII).
fn class_match(name: &[u8], c: u8) -> bool {
    match name {
        b"alnum" => c.is_ascii_alphanumeric(),
        b"alpha" => c.is_ascii_alphabetic(),
        b"blank" => c == b' ' || c == b'\t',
        b"cntrl" => c.is_ascii_control(),
        b"digit" => c.is_ascii_digit(),
        b"graph" => c.is_ascii_graphic(),
        b"lower" => c.is_ascii_lowercase(),
        b"print" => c.is_ascii_graphic() || c == b' ',
        b"punct" => c.is_ascii_punctuation(),
        b"space" => c == b' ' || (b'\t'..=b'\r').contains(&c), // SP \t \n \v \f \r
        b"upper" => c.is_ascii_uppercase(),
        b"xdigit" => c.is_ascii_hexdigit(),
        _ => false,
    }
}

// Returns Some((matched, index after ']')) or None if the bracket is
// malformed (no closing ']', or an unterminated [:/[./[= sub-bracket), in
// which case the leading '[' is a literal — matching glibc.
fn bracket(p: &[u8], start: usize, ch: u8, noescape: bool) -> Option<(bool, usize)> {
    let mut i = start + 1;
    let neg = matches!(p.get(i), Some(b'!') | Some(b'^'));
    if neg { i += 1; }
    let first = i;
    let mut matched = false;
    while i < p.len() {
        if p[i] == b']' && i > first { return Some((matched ^ neg, i + 1)); }
        // POSIX sub-brackets: [:class:], [.coll.], [=equiv=]. Each runs to a
        // matching `kind]` closer; absence → malformed bracket (None).
        if p[i] == b'[' && i + 1 < p.len() && matches!(p[i + 1], b':' | b'.' | b'=') {
            let kind = p[i + 1];
            let mut j = i + 2;
            while j + 1 < p.len() && !(p[j] == kind && p[j + 1] == b']') { j += 1; }
            if !(j + 1 < p.len() && p[j] == kind && p[j + 1] == b']') { return None; }
            let inner = &p[i + 2..j];
            if kind == b':' {
                if class_match(inner, ch) { matched = true; }
                i = j + 2;
                continue;
            }
            // [.x.] / [=x=]: C-locale collating/equivalence element. Only a
            // single-byte element is representable; treat it as that literal
            // (and a possible range low endpoint). Multi-byte → no match.
            if inner.len() != 1 { i = j + 2; continue; }
            let lo = inner[0];
            if j + 3 < p.len() && p[j + 2] == b'-' && p[j + 3] != b']' {
                let hi = p[j + 3];
                if ch >= lo && ch <= hi { matched = true; }
                i = j + 4;
            } else {
                if ch == lo { matched = true; }
                i = j + 2;
            }
            continue;
        }
        let lo = if p[i] == b'\\' && !noescape && i + 1 < p.len() { i += 1; p[i] } else { p[i] };
        // range lo-hi (the '-' must not be the closing ']')
        if i + 2 < p.len() && p[i + 1] == b'-' && p[i + 2] != b']' {
            let hi = p[i + 2];
            if ch >= lo && ch <= hi { matched = true; }
            i += 3;
        } else {
            if ch == lo { matched = true; }
            i += 1;
        }
    }
    None
}

/// # C: true if pattern p matches string s under `flags`
pub(crate) fn fnmatch_slice(p: &[u8], s: &[u8], flags: i32) -> bool {
    let pathname = flags & FNM_PATHNAME != 0;
    let noescape = flags & FNM_NOESCAPE != 0;
    let period = flags & FNM_PERIOD != 0;
    rec(p, 0, s, 0, pathname, noescape, period)
}

#[allow(clippy::too_many_arguments)]
fn rec(p: &[u8], mut pi: usize, s: &[u8], mut si: usize, pathname: bool, noescape: bool, period: bool) -> bool {
    while pi < p.len() {
        let leading = period && (si == 0 || (pathname && si > 0 && s[si - 1] == b'/'));
        match p[pi] {
            b'*' => {
                while pi < p.len() && p[pi] == b'*' { pi += 1; }
                if leading && si < s.len() && s[si] == b'.' { return false; }
                if pi == p.len() {
                    return !(pathname && s[si..].contains(&b'/'));
                }
                let mut k = si;
                loop {
                    if rec(p, pi, s, k, pathname, noescape, period) { return true; }
                    if k == s.len() { return false; }
                    if pathname && s[k] == b'/' { return false; }
                    k += 1;
                }
            }
            b'?' => {
                if si == s.len() { return false; }
                if pathname && s[si] == b'/' { return false; }
                if leading && s[si] == b'.' { return false; }
                pi += 1; si += 1;
            }
            b'[' => {
                if si == s.len() { return false; }
                if (pathname && s[si] == b'/') || (leading && s[si] == b'.') { return false; }
                match bracket(p, pi, s[si], noescape) {
                    Some((true, next)) => { pi = next; si += 1; }
                    Some((false, _)) => return false,
                    None => { if s[si] != b'[' { return false; } pi += 1; si += 1; }
                }
            }
            b'\\' if !noescape => {
                pi += 1;
                let lit = if pi < p.len() { p[pi] } else { b'\\' };
                if si == s.len() || s[si] != lit { return false; }
                if pi < p.len() { pi += 1; }
                si += 1;
            }
            c => {
                if si == s.len() || s[si] != c { return false; }
                pi += 1; si += 1;
            }
        }
    }
    si == s.len()
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use crate::string::len::strlen_impl;
    // # C: int fnmatch(const char *pattern, const char *string, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn fnmatch(pattern: *const u8, string: *const u8, flags: i32) -> i32 {
        // SAFETY: pattern/string are NUL-terminated; we view them as slices
        // of their strlen length for the matcher.
        unsafe {
            let p = core::slice::from_raw_parts(pattern, strlen_impl(pattern));
            let s = core::slice::from_raw_parts(string, strlen_impl(string));
            if fnmatch_slice(p, s, flags) { 0 } else { FNM_NOMATCH }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    fn host(p: &str, s: &str, flags: i32) -> bool {
        let cp = format!("{p}\0");
        let cs = format!("{s}\0");
        // SAFETY: both NUL-terminated; host fnmatch reads them.
        let r = unsafe { libc::fnmatch(cp.as_ptr() as *const _, cs.as_ptr() as *const _, flags) };
        r == 0
    }

    proptest! {
        #[test]
        fn matches_host(p in "[ab*?.:=^\\\\\\[\\]!/-]{0,10}", s in "[ab.:/= ]{0,8}", pn in any::<bool>(), pd in any::<bool>()) {
            let flags = (if pn { FNM_PATHNAME } else { 0 }) | (if pd { FNM_PERIOD } else { 0 });
            let ours = fnmatch_slice(p.as_bytes(), s.as_bytes(), flags);
            prop_assert_eq!(ours, host(&p, &s, flags), "p={:?} s={:?} flags={}", p, s, flags);
        }
        #[test]
        fn star_and_class(s in "[abc/.]{0,10}") {
            for p in ["*", "a*", "*c", "a?c", "[abc]*", "[!a]*", "*/*", "a*c"] {
                let ours = fnmatch_slice(p.as_bytes(), s.as_bytes(), 0);
                prop_assert_eq!(ours, host(p, &s, 0), "p={:?} s={:?}", p, s);
                let ours_pn = fnmatch_slice(p.as_bytes(), s.as_bytes(), FNM_PATHNAME);
                prop_assert_eq!(ours_pn, host(p, &s, FNM_PATHNAME), "PATHNAME p={:?} s={:?}", p, s);
            }
        }
    }
}
