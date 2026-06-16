// /etc/gshadow database (docs/59§6 §9.1) — getsgnam/getsgent/setsgent/endsgent/
// fgetsgent/sgetsgent/putsgent (+_r). Line: `name:passwd:admin,..:member,..`.
// Non-`_r` use a process-global result; `_r` deep-copy into the caller buffer.
#![cfg(feature = "freestanding")]
use core::cell::UnsafeCell;
use core::ffi::c_void;
use alloc::string::String;
use alloc::vec::Vec;
use crate::stdio::file::FILE;
use crate::stdio::put::{fputc, fputs};
use crate::stdio::read::fgets;

#[repr(C)]
pub struct sgrp { pub sg_namp: *mut u8, pub sg_passwd: *mut u8, pub sg_adm: *mut *mut u8, pub sg_mem: *mut *mut u8 }
const _: () = assert!(core::mem::size_of::<sgrp>() == 32);

#[derive(Clone)]
struct GsVal { name: String, pwd: String, adm: Vec<String>, mem: Vec<String> }

const BUF: usize = 4096;
const MAXL: usize = 256;
struct GsState { ent: sgrp, buf: [u8; BUF], adm: [*mut u8; MAXL], mem: [*mut u8; MAXL], v: Vec<GsVal>, i: usize, loaded: bool }
struct St(UnsafeCell<GsState>);
// SAFETY: getsgent follows glibc's not-thread-safe contract; this global is
// touched single-threaded by set/get/endsgent.
unsafe impl Sync for St {}
static S: St = St(UnsafeCell::new(GsState {
    ent: sgrp { sg_namp: core::ptr::null_mut(), sg_passwd: core::ptr::null_mut(), sg_adm: core::ptr::null_mut(), sg_mem: core::ptr::null_mut() },
    buf: [0; BUF], adm: [core::ptr::null_mut(); MAXL], mem: [core::ptr::null_mut(); MAXL], v: Vec::new(), i: 0, loaded: false,
}));

fn parse_line(line: &str) -> Option<GsVal> {
    let l = line.trim_end_matches(['\n', '\r']);
    if l.is_empty() || l.starts_with('#') { return None; }
    let mut it = l.splitn(4, ':');
    let name = it.next()?; let pwd = it.next().unwrap_or(""); let adm = it.next().unwrap_or(""); let mem = it.next().unwrap_or("");
    let csv = |s: &str| s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).map(String::from).collect();
    Some(GsVal { name: name.into(), pwd: pwd.into(), adm: csv(adm), mem: csv(mem) })
}
fn parse(text: &str) -> Vec<GsVal> { text.lines().filter_map(parse_line).collect() }

// Pack a record into the static result; null on overflow.
unsafe fn fill(g: &GsVal) -> *mut sgrp {
    // SAFETY: pack name/pwd + the two member lists into the single-threaded
    // static buffers, bounded by BUF/MAXL.
    unsafe {
        let s = &mut *S.0.get();
        let bp = s.buf.as_mut_ptr();
        let mut pos = 0usize;
        let mut put = |b: &[u8]| -> *mut u8 {
            if pos + b.len() + 1 > BUF { return core::ptr::null_mut(); }
            core::ptr::copy_nonoverlapping(b.as_ptr(), bp.add(pos), b.len());
            *bp.add(pos + b.len()) = 0; let p = bp.add(pos); pos += b.len() + 1; p
        };
        s.ent.sg_namp = put(g.name.as_bytes());
        s.ent.sg_passwd = put(g.pwd.as_bytes());
        let na = g.adm.len().min(MAXL - 1);
        for (k, m) in g.adm.iter().take(na).enumerate() { s.adm[k] = put(m.as_bytes()); }
        s.adm[na] = core::ptr::null_mut();
        let nm = g.mem.len().min(MAXL - 1);
        for (k, m) in g.mem.iter().take(nm).enumerate() { s.mem[k] = put(m.as_bytes()); }
        s.mem[nm] = core::ptr::null_mut();
        s.ent.sg_adm = s.adm.as_mut_ptr();
        s.ent.sg_mem = s.mem.as_mut_ptr();
        &mut s.ent
    }
}

unsafe fn load() {
    // SAFETY: lazily slurp + parse /etc/gshadow.
    unsafe {
        let s = &mut *S.0.get();
        if s.loaded { return; }
        if let Some(b) = crate::nss::shared::read_file(b"/etc/gshadow\0") { s.v = parse(core::str::from_utf8(&b).unwrap_or("")); }
        s.loaded = true;
    }
}

// # C: void setsgent(void)
#[no_mangle]
pub unsafe extern "C" fn setsgent() {
    // SAFETY: reset + force reload of the single-threaded gshadow cursor.
    unsafe { let s = &mut *S.0.get(); s.i = 0; s.loaded = false; s.v = Vec::new(); }
}
// # C: void endsgent(void)
#[no_mangle]
pub unsafe extern "C" fn endsgent() {
    // SAFETY: clear the single-threaded gshadow enumeration state.
    unsafe { let s = &mut *S.0.get(); s.i = 0; s.loaded = false; s.v = Vec::new(); }
}
// # C: struct sgrp *getsgent(void)
#[no_mangle]
pub unsafe extern "C" fn getsgent() -> *mut sgrp {
    // SAFETY: lazy-load; return the next record into the static result.
    unsafe {
        load();
        let g = { let s = &mut *S.0.get(); if s.i >= s.v.len() { return core::ptr::null_mut(); } let g = s.v[s.i].clone(); s.i += 1; g };
        fill(&g)
    }
}
// # C: struct sgrp *getsgnam(const char *name)
#[no_mangle]
pub unsafe extern "C" fn getsgnam(name: *const u8) -> *mut sgrp {
    // SAFETY: name NUL-terminated; scan all records for a matching sg_namp.
    unsafe {
        load();
        let n = { let mut k = 0; while *name.add(k) != 0 { k += 1; } k };
        let want = core::slice::from_raw_parts(name, n);
        let v = { let s = &*S.0.get(); s.v.clone() };
        for g in &v { if g.name.as_bytes() == want { return fill(g); } }
        core::ptr::null_mut()
    }
}
// # C: struct sgrp *sgetsgent(const char *string)
#[no_mangle]
pub unsafe extern "C" fn sgetsgent(string: *const u8) -> *mut sgrp {
    // SAFETY: string is a NUL-terminated gshadow line; parse + fill the static.
    unsafe {
        let n = { let mut k = 0; while *string.add(k) != 0 { k += 1; } k };
        let s = core::str::from_utf8(core::slice::from_raw_parts(string, n)).unwrap_or("");
        match parse_line(s) { Some(g) => fill(&g), None => core::ptr::null_mut() }
    }
}
// # C: struct sgrp *fgetsgent(FILE *stream)
#[no_mangle]
pub unsafe extern "C" fn fgetsgent(stream: *mut c_void) -> *mut sgrp {
    // SAFETY: stream is a readable FILE*; read one line then parse it.
    unsafe {
        let mut line = [0u8; 1024];
        if fgets(line.as_mut_ptr(), line.len() as i32, stream as *mut FILE).is_null() { return core::ptr::null_mut(); }
        sgetsgent(line.as_ptr())
    }
}
// # C: int putsgent(const struct sgrp *g, FILE *stream)
#[no_mangle]
pub unsafe extern "C" fn putsgent(g: *const sgrp, stream: *mut c_void) -> i32 {
    // SAFETY: g is a valid sgrp; stream writable. Emit name:pwd:adm,..:mem,..\n.
    unsafe {
        let f = stream as *mut FILE;
        let ws = |p: *const u8, f: *mut FILE| { if !p.is_null() { fputs(p, f); } };
        let wlist = |arr: *const *mut u8, f: *mut FILE| {
            if arr.is_null() { return; }
            let mut k = 0; while !(*arr.add(k)).is_null() { if k > 0 { fputc(b',' as i32, f); } fputs(*arr.add(k), f); k += 1; }
        };
        ws((*g).sg_namp, f); fputc(b':' as i32, f);
        ws((*g).sg_passwd, f); fputc(b':' as i32, f);
        wlist((*g).sg_adm, f); fputc(b':' as i32, f);
        wlist((*g).sg_mem, f);
        if fputc(b'\n' as i32, f) < 0 { -1 } else { 0 }
    }
}

const ERANGE: i32 = 34;
// Deep-copy the static sgrp into the caller's _r buffer (name+pwd+2 lists).
unsafe fn pack_r(src: *mut sgrp, rb: *mut sgrp, buf: *mut u8, buflen: usize, result: *mut *mut sgrp) -> i32 {
    // SAFETY: src is the static result (or null); rb/buf the caller storage.
    unsafe {
        if src.is_null() { *result = core::ptr::null_mut(); return 0; }
        let count = |a: *const *mut u8| { let mut k = 0; if !a.is_null() { while !(*a.add(k)).is_null() { k += 1; } } k };
        let (na, nm) = (count((*src).sg_adm), count((*src).sg_mem));
        let arr = (buf as usize + 7) & !7;
        let mut pos = (arr - buf as usize) + (na + 1 + nm + 1) * 8;
        if pos > buflen { *result = core::ptr::null_mut(); return ERANGE; }
        let strlen = |s: *const u8| { let mut i = 0; while *s.add(i) != 0 { i += 1; } i };
        let mut put = |s: *const u8| -> Option<*mut u8> {
            if s.is_null() { return Some(core::ptr::null_mut()); }
            let l = strlen(s); if pos + l + 1 > buflen { return None; }
            core::ptr::copy_nonoverlapping(s, buf.add(pos), l); *buf.add(pos + l) = 0;
            let p = buf.add(pos); pos += l + 1; Some(p)
        };
        let er = |result: *mut *mut sgrp| { *result = core::ptr::null_mut(); ERANGE };
        let nmp = match put((*src).sg_namp) { Some(p) => p, None => return er(result) };
        let pwp = match put((*src).sg_passwd) { Some(p) => p, None => return er(result) };
        let adm_arr = arr as *mut *mut u8;
        for k in 0..na { match put(*(*src).sg_adm.add(k)) { Some(p) => *adm_arr.add(k) = p, None => return er(result) } }
        *adm_arr.add(na) = core::ptr::null_mut();
        let mem_arr = adm_arr.add(na + 1);
        for k in 0..nm { match put(*(*src).sg_mem.add(k)) { Some(p) => *mem_arr.add(k) = p, None => return er(result) } }
        *mem_arr.add(nm) = core::ptr::null_mut();
        (*rb).sg_namp = nmp; (*rb).sg_passwd = pwp; (*rb).sg_adm = adm_arr; (*rb).sg_mem = mem_arr;
        *result = rb; 0
    }
}
// # C: int getsgnam_r(const char*, struct sgrp*, char*, size_t, struct sgrp**)
#[no_mangle]
pub unsafe extern "C" fn getsgnam_r(name: *const u8, rb: *mut sgrp, buf: *mut u8, n: usize, result: *mut *mut sgrp) -> i32 {
    // SAFETY: deep-copy the matched entry into rb/buf.
    unsafe { pack_r(getsgnam(name), rb, buf, n, result) }
}
// # C: int getsgent_r(struct sgrp*, char*, size_t, struct sgrp**)
#[no_mangle]
pub unsafe extern "C" fn getsgent_r(rb: *mut sgrp, buf: *mut u8, n: usize, result: *mut *mut sgrp) -> i32 {
    // SAFETY: deep-copy the next entry into rb/buf.
    unsafe { pack_r(getsgent(), rb, buf, n, result) }
}
// # C: int sgetsgent_r(const char*, struct sgrp*, char*, size_t, struct sgrp**)
#[no_mangle]
pub unsafe extern "C" fn sgetsgent_r(string: *const u8, rb: *mut sgrp, buf: *mut u8, n: usize, result: *mut *mut sgrp) -> i32 {
    // SAFETY: parse `string` into the static then deep-copy into rb/buf.
    unsafe { pack_r(sgetsgent(string), rb, buf, n, result) }
}
// # C: int fgetsgent_r(FILE*, struct sgrp*, char*, size_t, struct sgrp**)
#[no_mangle]
pub unsafe extern "C" fn fgetsgent_r(stream: *mut c_void, rb: *mut sgrp, buf: *mut u8, n: usize, result: *mut *mut sgrp) -> i32 {
    // SAFETY: read+parse one line from the stream then deep-copy into rb/buf.
    unsafe { pack_r(fgetsgent(stream), rb, buf, n, result) }
}
