// Shared-object search-path resolution (docs/59§5). Order matches glibc:
// DT_RPATH (no $ORIGIN here) → LD_LIBRARY_PATH → DT_RUNPATH → ld.so.cache
// (cache.rs) → trusted default dirs. This module covers the path-list /
// candidate-building half; cache lookup is cache.rs. Alloc-free: candidates
// are built into a caller-provided buffer (the rtld has no heap yet).

pub const PATH_MAX: usize = 4096;

/// Trusted default dirs, searched last (glibc system default), in order.
pub const DEFAULT_DIRS: [&[u8]; 4] = [b"/lib64", b"/usr/lib64", b"/lib", b"/usr/lib"];

/// Join `dir` + '/' + `name` + NUL into `out`. Returns the C-string length
/// (excluding the NUL) or None if it would not fit.
///
/// # C: build "dir/name\0" into out; None on overflow
pub fn join_path(dir: &[u8], name: &[u8], out: &mut [u8]) -> Option<usize> {
    let need = dir.len() + 1 + name.len() + 1; // '/', name, NUL
    if need > out.len() { return None; }
    let mut n = 0;
    out[..dir.len()].copy_from_slice(dir);
    n += dir.len();
    out[n] = b'/';
    n += 1;
    out[n..n + name.len()].copy_from_slice(name);
    n += name.len();
    out[n] = 0;
    Some(n)
}

/// Iterator over a colon-separated path list (LD_LIBRARY_PATH). Empty
/// segments are skipped (glibc maps them to cwd, which the rtld disallows
/// for AT_SECURE; we omit cwd-search entirely).
pub struct Colon<'a> { rest: &'a [u8] }

impl<'a> Colon<'a> {
    /// # C: O(1)
    pub fn new(s: &'a [u8]) -> Self { Colon { rest: s } }
}

impl<'a> Iterator for Colon<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        while !self.rest.is_empty() {
            let end = self.rest.iter().position(|&b| b == b':').unwrap_or(self.rest.len());
            let seg = &self.rest[..end];
            self.rest = if end < self.rest.len() { &self.rest[end + 1..] } else { &[] };
            if !seg.is_empty() { return Some(seg); }
        }
        None
    }
}

/// True if `name` is an explicit path (contains '/') — used verbatim, not
/// searched, per the dynamic-linker contract.
/// # C: O(n)
pub fn is_path(name: &[u8]) -> bool { name.contains(&b'/') }

/// Resolve `name` to a NUL-terminated path in `out`, using `exists` to probe
/// the filesystem. `ld_library_path` is the colon list (may be empty).
/// Returns the C-string length, or None if nothing matched / overflow.
///
/// # C: first existing of (LD_LIBRARY_PATH dirs.., DEFAULT_DIRS..)/name
pub fn resolve<F: Fn(&[u8]) -> bool>(
    name: &[u8],
    ld_library_path: &[u8],
    out: &mut [u8],
    exists: F,
) -> Option<usize> {
    if is_path(name) {
        let need = name.len() + 1;
        if need > out.len() { return None; }
        out[..name.len()].copy_from_slice(name);
        out[name.len()] = 0;
        return if exists(&out[..name.len()]) { Some(name.len()) } else { None };
    }
    for dir in Colon::new(ld_library_path) {
        if let Some(n) = join_path(dir, name, out) {
            if exists(&out[..n]) { return Some(n); }
        }
    }
    for dir in DEFAULT_DIRS {
        if let Some(n) = join_path(dir, name, out) {
            if exists(&out[..n]) { return Some(n); }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_basic() {
        let mut b = [0u8; 64];
        let n = join_path(b"/lib64", b"libc.so.6", &mut b).unwrap();
        assert_eq!(&b[..n], b"/lib64/libc.so.6");
        assert_eq!(b[n], 0);
    }
    #[test]
    fn join_overflow() {
        let mut b = [0u8; 8];
        assert_eq!(join_path(b"/usr/lib64", b"libfoo.so", &mut b), None);
    }
    #[test]
    fn colon_split() {
        let got: std::vec::Vec<&[u8]> = Colon::new(b"/a::/b/c:/d").collect();
        assert_eq!(got, std::vec![&b"/a"[..], &b"/b/c"[..], &b"/d"[..]]);
        assert_eq!(Colon::new(b"").count(), 0);
    }
    #[test]
    fn resolve_prefers_ld_library_path() {
        let mut out = [0u8; PATH_MAX];
        // only /opt/lib/libx.so.1 exists
        let n = resolve(b"libx.so.1", b"/opt/lib:/other", &mut out, |p| p == b"/opt/lib/libx.so.1").unwrap();
        assert_eq!(&out[..n], b"/opt/lib/libx.so.1");
    }
    #[test]
    fn resolve_falls_back_to_default_dirs() {
        let mut out = [0u8; PATH_MAX];
        let n = resolve(b"libc.so.6", b"", &mut out, |p| p == b"/usr/lib64/libc.so.6").unwrap();
        assert_eq!(&out[..n], b"/usr/lib64/libc.so.6");
    }
    #[test]
    fn resolve_explicit_path() {
        let mut out = [0u8; PATH_MAX];
        let n = resolve(b"/lib/ld-linux.so", b"", &mut out, |p| p == b"/lib/ld-linux.so").unwrap();
        assert_eq!(&out[..n], b"/lib/ld-linux.so");
        assert!(resolve(b"/nope/x.so", b"", &mut out, |_| false).is_none());
    }
    #[test]
    fn resolve_none_when_missing() {
        let mut out = [0u8; PATH_MAX];
        assert!(resolve(b"libmissing.so", b"/a:/b", &mut out, |_| false).is_none());
    }
}
