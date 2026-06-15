//! netgr — /etc/netgroup: setnetgrent/getnetgrent[_r]/endnetgrent/innetgr
//! (docs/59§6 G13). A netgroup line is `name (host,user,domain) ... [othergrp]`
//! where a member is a parenthesized triple (empty field → NULL pointer in
//! getnetgrent) or a bare name referencing another netgroup (expanded). Pure
//! parser + matcher are hosted-tested; iteration uses a process-global cursor.
#![allow(clippy::upper_case_acronyms)]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

// One member triple; None = empty field (wildcard in innetgr / NULL in getent).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Triple { pub host: Option<String>, pub user: Option<String>, pub domain: Option<String> }

fn field(s: &str) -> Option<String> { let t = s.trim(); if t.is_empty() { None } else { Some(t.into()) } }

// Parse one `(host,user,domain)` triple starting at `s` (no leading paren).
fn parse_triple(inner: &str) -> Triple {
    let mut it = inner.splitn(3, ',');
    let host = field(it.next().unwrap_or(""));
    let user = field(it.next().unwrap_or(""));
    let domain = field(it.next().unwrap_or(""));
    Triple { host, user, domain }
}

/// Expand `name`'s triples from the file map, following bare-name references
/// (cycle-guarded). Returns the flat triple list.
/// # C: flatten a netgroup to its (host,user,domain) triples
pub(crate) fn expand(map: &[(String, Vec<Member>)], name: &str) -> Vec<Triple> {
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut stack: Vec<String> = alloc::vec![name.into()];
    while let Some(g) = stack.pop() {
        if seen.contains(&g) { continue; }
        seen.push(g.clone());
        if let Some((_, members)) = map.iter().find(|(n, _)| *n == g) {
            for m in members { match m { Member::T(t) => out.push(t.clone()), Member::Ref(r) => stack.push(r.clone()) } }
        }
    }
    out
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Member { T(Triple), Ref(String) }

/// Parse the whole /etc/netgroup into (name, members). Continuation lines
/// (trailing backslash) are joined.
/// # C: parse /etc/netgroup into per-group member lists
pub(crate) fn parse(text: &str) -> Vec<(String, Vec<Member>)> {
    let mut joined = String::new();
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = match raw.split_once('#') { Some((h, _)) => h, None => raw };
        if line.trim().is_empty() && joined.is_empty() { continue; }
        if let Some(stripped) = line.trim_end().strip_suffix('\\') { joined.push_str(stripped); joined.push(' '); continue; }
        joined.push_str(line);
        if !joined.trim().is_empty() { if let Some(e) = parse_line(&joined) { out.push(e); } }
        joined.clear();
    }
    if !joined.trim().is_empty() { if let Some(e) = parse_line(&joined) { out.push(e); } }
    out
}

fn parse_line(line: &str) -> Option<(String, Vec<Member>)> {
    let line = line.trim();
    let (name, rest) = line.split_once(char::is_whitespace)?;
    let mut members = Vec::new();
    let mut s = rest.trim_start();
    while !s.is_empty() {
        if let Some(close) = s.strip_prefix('(') {
            let end = close.find(')')?;
            members.push(Member::T(parse_triple(&close[..end])));
            s = close[end + 1..].trim_start();
        } else {
            let tok_end = s.find(char::is_whitespace).unwrap_or(s.len());
            members.push(Member::Ref(s[..tok_end].into()));
            s = s[tok_end..].trim_start();
        }
    }
    Some((name.into(), members))
}

/// Does any triple match (host,user,domain)? A None query field matches
/// anything; a triple field of None (wildcard) matches anything.
/// # C: innetgr triple-membership test
pub(crate) fn matches(triples: &[Triple], host: Option<&str>, user: Option<&str>, domain: Option<&str>) -> bool {
    let f = |t: &Option<String>, q: Option<&str>| match q { None => true, Some(qq) => match t { None => true, Some(tt) => tt == qq } };
    triples.iter().any(|t| f(&t.host, host) && f(&t.user, user) && f(&t.domain, domain))
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use crate::nss::shared::read_file;
    use crate::string::len::strlen_impl;
    use core::cell::UnsafeCell;

    struct Cur { triples: Vec<Triple>, i: usize, buf: [u8; 256] }
    struct St(UnsafeCell<Cur>);
    // SAFETY: netgroup iteration is glibc's not-thread-safe contract; this
    // process-global cursor is touched single-threaded by set/get/endnetgrent.
    unsafe impl Sync for St {}
    static S: St = St(UnsafeCell::new(Cur { triples: Vec::new(), i: 0, buf: [0; 256] }));

    unsafe fn opt_slice<'a>(p: *const u8) -> Option<&'a str> {
        // SAFETY: p is null or a NUL-terminated C string.
        unsafe { if p.is_null() { None } else { core::str::from_utf8(core::slice::from_raw_parts(p, strlen_impl(p))).ok() } }
    }

    /// # C: int setnetgrent(const char *netgroup)
    #[no_mangle]
    pub unsafe extern "C" fn setnetgrent(netgroup: *const u8) -> i32 {
        // SAFETY: netgroup NUL-terminated; loads + expands /etc/netgroup.
        unsafe {
            let c = &mut *S.0.get();
            c.triples.clear(); c.i = 0;
            let name = match opt_slice(netgroup) { Some(n) => n, None => return 0 };
            if let Some(b) = read_file(b"/etc/netgroup\0") {
                if let Ok(t) = core::str::from_utf8(&b) { c.triples = expand(&parse(t), name); }
            }
            1
        }
    }
    /// # C: void endnetgrent(void)
    #[no_mangle]
    pub unsafe extern "C" fn endnetgrent() {
        // SAFETY: frees the single-threaded global netgroup cursor.
        unsafe { let c = &mut *S.0.get(); c.triples = Vec::new(); c.i = 0; }
    }

    // Pack a triple's three fields into `buf` (NUL-terminated, empty → NULL
    // pointer); write the pointers into out params. Returns 1 (have entry).
    unsafe fn emit(t: &Triple, buf: &mut [u8], hp: *mut *mut u8, up: *mut *mut u8, dp: *mut *mut u8) -> i32 {
        // SAFETY: buf is writable; out params are writable pointer slots.
        unsafe {
            let mut pos = 0;
            for (fld, outp) in [(&t.host, hp), (&t.user, up), (&t.domain, dp)] {
                match fld {
                    None => *outp = core::ptr::null_mut(),
                    Some(v) => {
                        let bytes = v.as_bytes();
                        if pos + bytes.len() + 1 > buf.len() { *outp = core::ptr::null_mut(); continue; }
                        buf[pos..pos + bytes.len()].copy_from_slice(bytes);
                        buf[pos + bytes.len()] = 0;
                        *outp = buf[pos..].as_mut_ptr();
                        pos += bytes.len() + 1;
                    }
                }
            }
            1
        }
    }

    /// # C: int getnetgrent(char **hostp, char **userp, char **domainp)
    #[no_mangle]
    pub unsafe extern "C" fn getnetgrent(hostp: *mut *mut u8, userp: *mut *mut u8, domainp: *mut *mut u8) -> i32 {
        // SAFETY: out params are writable pointer slots per the glibc contract.
        unsafe {
            let c = &mut *S.0.get();
            if c.i >= c.triples.len() { return 0; }
            let t = c.triples[c.i].clone(); c.i += 1;
            let buf = &mut c.buf;
            emit(&t, buf, hostp, userp, domainp)
        }
    }
    /// # C: int getnetgrent_r(char **hostp, char **userp, char **domainp, char *buffer, size_t buflen)
    #[no_mangle]
    pub unsafe extern "C" fn getnetgrent_r(hostp: *mut *mut u8, userp: *mut *mut u8, domainp: *mut *mut u8, buffer: *mut u8, buflen: usize) -> i32 {
        // SAFETY: out params writable; buffer[0..buflen] writable per contract.
        unsafe {
            let c = &mut *S.0.get();
            if c.i >= c.triples.len() { return 0; }
            let t = c.triples[c.i].clone(); c.i += 1;
            let buf = core::slice::from_raw_parts_mut(buffer, buflen);
            emit(&t, buf, hostp, userp, domainp)
        }
    }
    /// # C: int innetgr(const char *netgroup, const char *host, const char *user, const char *domain)
    #[no_mangle]
    pub unsafe extern "C" fn innetgr(netgroup: *const u8, host: *const u8, user: *const u8, domain: *const u8) -> i32 {
        // SAFETY: all args null or NUL-terminated; loads + matches /etc/netgroup.
        unsafe {
            let name = match opt_slice(netgroup) { Some(n) => n, None => return 0 };
            let b = match read_file(b"/etc/netgroup\0") { Some(b) => b, None => return 0 };
            let t = match core::str::from_utf8(&b) { Ok(s) => expand(&parse(s), name), Err(_) => return 0 };
            if matches(&t, opt_slice(host), opt_slice(user), opt_slice(domain)) { 1 } else { 0 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_expand() {
        let text = "trusted (host1,user1,dom) (host2,,dom)\nall trusted (host3,bob,)\n";
        let map = parse(text);
        assert_eq!(map.len(), 2);
        let t = expand(&map, "all");
        // 'all' references trusted (2 triples) + its own 1 triple = 3
        assert_eq!(t.len(), 3);
        assert!(matches(&t, Some("host1"), Some("user1"), Some("dom")));
        assert!(matches(&t, Some("host2"), None, Some("dom"))); // empty user field = wildcard
        assert!(!matches(&t, Some("nope"), None, None));
    }

    #[test]
    fn wildcard_query() {
        let map = parse("g (h,u,d)\n");
        let t = expand(&map, "g");
        assert!(matches(&t, None, None, None)); // all-wildcard query matches
        assert!(matches(&t, Some("h"), None, None));
        assert!(!matches(&t, Some("x"), None, None));
    }
}
