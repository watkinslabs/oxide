// /etc/aliases (mail) database (docs/59§6 §9.1) — getaliasent/getaliasbyname
// (+_r) / setaliasent / endaliasent. Format: `name: m1, m2, ...` with `#`
// comments and folded continuation lines (a line starting with whitespace
// continues the previous). Non-`_r` use a process-global result; `_r` deep-copy
// into the caller buffer.
#![cfg(feature = "freestanding")]
use core::cell::UnsafeCell;
use alloc::string::String;
use alloc::vec::Vec;

#[repr(C)]
pub struct aliasent {
    pub alias_local: u64,
    pub alias_name: *mut u8,
    pub alias_members_len: usize,
    pub alias_members: *mut *mut u8,
}
const _: () = assert!(core::mem::size_of::<aliasent>() == 32);

#[derive(Clone)]
struct AliasVal { name: String, members: Vec<String> }

const BUF: usize = 4096;
const MAXMEM: usize = 256;
struct AState { ent: aliasent, buf: [u8; BUF], mem: [*mut u8; MAXMEM], v: Vec<AliasVal>, i: usize, loaded: bool }
struct St(UnsafeCell<AState>);
// SAFETY: getaliasent follows glibc's not-thread-safe contract; this global is
// touched single-threaded by set/get/endaliasent.
unsafe impl Sync for St {}
static S: St = St(UnsafeCell::new(AState {
    ent: aliasent { alias_local: 0, alias_name: core::ptr::null_mut(), alias_members_len: 0, alias_members: core::ptr::null_mut() },
    buf: [0; BUF], mem: [core::ptr::null_mut(); MAXMEM], v: Vec::new(), i: 0, loaded: false,
}));

// Parse /etc/aliases into (name, members) records, folding continuation lines.
fn parse(text: &str) -> Vec<AliasVal> {
    let mut out: Vec<AliasVal> = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("");
        if line.trim().is_empty() { continue; }
        if line.starts_with([' ', '\t']) {
            // continuation: append members to the last record
            if let Some(last) = out.last_mut() {
                for m in line.split(',') { let m = m.trim(); if !m.is_empty() { last.members.push(m.into()); } }
            }
            continue;
        }
        let (name, rest) = match line.split_once(':') { Some(v) => v, None => continue };
        let members = rest.split(',').map(|m| m.trim()).filter(|m| !m.is_empty()).map(String::from).collect();
        out.push(AliasVal { name: name.trim().into(), members });
    }
    out
}

// Pack a record into the static result; returns &ent or null on overflow.
unsafe fn fill(a: &AliasVal) -> *mut aliasent {
    // SAFETY: packs name + member strings + the member pointer array into the
    // single-threaded static buffers, bounded by BUF/MAXMEM.
    unsafe {
        let s = &mut *S.0.get();
        let bp = s.buf.as_mut_ptr();
        let mut pos = 0usize;
        let mut put = |b: &[u8]| -> *mut u8 {
            if pos + b.len() + 1 > BUF { return core::ptr::null_mut(); }
            core::ptr::copy_nonoverlapping(b.as_ptr(), bp.add(pos), b.len());
            *bp.add(pos + b.len()) = 0; let p = bp.add(pos); pos += b.len() + 1; p
        };
        s.ent.alias_name = put(a.name.as_bytes());
        let n = a.members.len().min(MAXMEM - 1);
        for (k, m) in a.members.iter().take(n).enumerate() { s.mem[k] = put(m.as_bytes()); }
        s.mem[n] = core::ptr::null_mut();
        s.ent.alias_members = s.mem.as_mut_ptr();
        s.ent.alias_members_len = n;
        s.ent.alias_local = 1;
        &mut s.ent
    }
}

unsafe fn load() {
    // SAFETY: lazily slurp + parse /etc/aliases into owned records.
    unsafe {
        let s = &mut *S.0.get();
        if s.loaded { return; }
        if let Some(b) = crate::nss::shared::read_file(b"/etc/aliases\0") {
            s.v = parse(core::str::from_utf8(&b).unwrap_or(""));
        }
        s.loaded = true;
    }
}

// # C: void setaliasent(void)
#[no_mangle]
pub unsafe extern "C" fn setaliasent() {
    // SAFETY: reset + force reload of the single-threaded alias cursor.
    unsafe { let s = &mut *S.0.get(); s.i = 0; s.loaded = false; s.v = Vec::new(); }
}
// # C: void endaliasent(void)
#[no_mangle]
pub unsafe extern "C" fn endaliasent() {
    // SAFETY: clear the single-threaded alias enumeration state.
    unsafe { let s = &mut *S.0.get(); s.i = 0; s.loaded = false; s.v = Vec::new(); }
}
// # C: struct aliasent *getaliasent(void)
#[no_mangle]
pub unsafe extern "C" fn getaliasent() -> *mut aliasent {
    // SAFETY: lazy-load, return the next record into the static result.
    unsafe {
        load();
        let a = { let s = &mut *S.0.get(); if s.i >= s.v.len() { return core::ptr::null_mut(); } let a = s.v[s.i].clone(); s.i += 1; a };
        fill(&a)
    }
}
// # C: struct aliasent *getaliasbyname(const char *name)
#[no_mangle]
pub unsafe extern "C" fn getaliasbyname(name: *const u8) -> *mut aliasent {
    // SAFETY: name NUL-terminated; scan all records for a matching alias_name.
    unsafe {
        load();
        let n = { let mut k = 0; while *name.add(k) != 0 { k += 1; } k };
        let want = core::slice::from_raw_parts(name, n);
        let v = { let s = &*S.0.get(); s.v.clone() };
        for a in &v { if a.name.as_bytes() == want { return fill(a); } }
        core::ptr::null_mut()
    }
}

const ERANGE: i32 = 34;
// Deep-copy the static aliasent into the caller's _r buffer.
unsafe fn pack_r(src: *mut aliasent, rb: *mut aliasent, buf: *mut u8, buflen: usize, result: *mut *mut aliasent) -> i32 {
    // SAFETY: src is the static result (or null); rb/buf the caller storage.
    // Layout: [(n+1) member ptrs, 8-aligned][name\0][member strings].
    unsafe {
        if src.is_null() { *result = core::ptr::null_mut(); return 0; }
        let n = (*src).alias_members_len;
        let arr = (buf as usize + 7) & !7;
        let mut pos = (arr - buf as usize) + (n + 1) * 8;
        if pos > buflen { *result = core::ptr::null_mut(); return ERANGE; }
        let strlen = |s: *const u8| { let mut i = 0; while *s.add(i) != 0 { i += 1; } i };
        let mut put = |s: *const u8| -> Option<*mut u8> {
            let l = strlen(s); if pos + l + 1 > buflen { return None; }
            core::ptr::copy_nonoverlapping(s, buf.add(pos), l); *buf.add(pos + l) = 0;
            let p = buf.add(pos); pos += l + 1; Some(p)
        };
        let nm = match put((*src).alias_name) { Some(p) => p, None => { *result = core::ptr::null_mut(); return ERANGE; } };
        let arr_ptr = arr as *mut *mut u8;
        for k in 0..n {
            match put(*(*src).alias_members.add(k)) { Some(p) => *arr_ptr.add(k) = p, None => { *result = core::ptr::null_mut(); return ERANGE; } }
        }
        *arr_ptr.add(n) = core::ptr::null_mut();
        (*rb).alias_local = (*src).alias_local; (*rb).alias_name = nm; (*rb).alias_members_len = n; (*rb).alias_members = arr_ptr;
        *result = rb; 0
    }
}
// # C: int getaliasent_r(struct aliasent*, char*, size_t, struct aliasent**)
#[no_mangle]
pub unsafe extern "C" fn getaliasent_r(rb: *mut aliasent, buf: *mut u8, buflen: usize, result: *mut *mut aliasent) -> i32 {
    // SAFETY: deep-copy the next entry into rb/buf.
    unsafe { pack_r(getaliasent(), rb, buf, buflen, result) }
}
// # C: int getaliasbyname_r(const char*, struct aliasent*, char*, size_t, struct aliasent**)
#[no_mangle]
pub unsafe extern "C" fn getaliasbyname_r(name: *const u8, rb: *mut aliasent, buf: *mut u8, buflen: usize, result: *mut *mut aliasent) -> i32 {
    // SAFETY: deep-copy the matched entry into rb/buf.
    unsafe { pack_r(getaliasbyname(name), rb, buf, buflen, result) }
}
