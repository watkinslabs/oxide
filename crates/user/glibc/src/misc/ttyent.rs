// /etc/ttys database (docs/59§6 §9.1) — getttyent/getttynam/setttyent/endttyent.
// BSD format: `name getty type [flags...] [window=...] [# comment]`; getty/type
// may be double-quoted. ty_status bits: TTY_ON(1)/TTY_SECURE(2). Linux usually
// lacks /etc/ttys → getttyent returns NULL. Non-reentrant process-global result.
#![cfg(feature = "freestanding")]
use core::cell::UnsafeCell;
use alloc::string::String;
use alloc::vec::Vec;

const TTY_ON: i32 = 0x01;
const TTY_SECURE: i32 = 0x02;
const BUF: usize = 512;

#[repr(C)]
pub struct ttyent {
    pub ty_name: *mut u8, pub ty_getty: *mut u8, pub ty_type: *mut u8,
    pub ty_status: i32, __pad: i32, pub ty_window: *mut u8, pub ty_comment: *mut u8,
}
const _: () = assert!(core::mem::size_of::<ttyent>() == 48);

struct TyState { ent: ttyent, buf: [u8; BUF], lines: Vec<String>, idx: usize, loaded: bool }
struct St(UnsafeCell<TyState>);
// SAFETY: getttyent follows glibc's not-thread-safe contract; this global is
// touched single-threaded by set/get/endttyent.
unsafe impl Sync for St {}
static S: St = St(UnsafeCell::new(TyState {
    ent: ttyent { ty_name: core::ptr::null_mut(), ty_getty: core::ptr::null_mut(), ty_type: core::ptr::null_mut(), ty_status: 0, __pad: 0, ty_window: core::ptr::null_mut(), ty_comment: core::ptr::null_mut() },
    buf: [0; BUF], lines: Vec::new(), idx: 0, loaded: false,
}));

// Tokenize, honoring "double quotes". Returns (token, rest-after).
fn token(s: &str) -> (&str, &str) {
    let s = s.trim_start_matches([' ', '\t']);
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.find('"') { return (&rest[..end], &rest[end + 1..]); }
        return (rest, "");
    }
    let end = s.find([' ', '\t']).unwrap_or(s.len());
    (&s[..end], &s[end..])
}

// Append `b`+NUL into buf at *pos; return the ptr or null on overflow.
unsafe fn put(buf: *mut u8, pos: &mut usize, b: &[u8]) -> *mut u8 {
    // SAFETY: buf has BUF bytes; bounds-checked append.
    unsafe {
        if *pos + b.len() + 1 > BUF { return core::ptr::null_mut(); }
        core::ptr::copy_nonoverlapping(b.as_ptr(), buf.add(*pos), b.len());
        *buf.add(*pos + b.len()) = 0;
        let p = buf.add(*pos); *pos += b.len() + 1; p
    }
}

// Parse one /etc/ttys line into the static ent. Returns null on a blank/comment.
unsafe fn parse(line: &str) -> *mut ttyent {
    // SAFETY: packs the parsed fields into the static result buffer.
    unsafe {
        let s = &mut *S.0.get();
        let l = line.trim_start_matches([' ', '\t']);
        if l.is_empty() || l.starts_with('#') { return core::ptr::null_mut(); }
        let (name, r1) = token(l);
        if name.is_empty() { return core::ptr::null_mut(); }
        let (getty, r2) = token(r1);
        let (ty, mut rest) = token(r2);
        let mut pos = 0usize;
        let bp = s.buf.as_mut_ptr();
        s.ent.ty_name = put(bp, &mut pos, name.as_bytes());
        s.ent.ty_getty = if getty.is_empty() { core::ptr::null_mut() } else { put(bp, &mut pos, getty.as_bytes()) };
        s.ent.ty_type = if ty.is_empty() { core::ptr::null_mut() } else { put(bp, &mut pos, ty.as_bytes()) };
        s.ent.ty_status = 0; s.ent.ty_window = core::ptr::null_mut(); s.ent.ty_comment = core::ptr::null_mut();
        loop {
            let (tok, r) = token(rest); rest = r;
            if tok.is_empty() { break; }
            match tok {
                "on" => s.ent.ty_status |= TTY_ON,
                "off" => s.ent.ty_status &= !TTY_ON,
                "secure" => s.ent.ty_status |= TTY_SECURE,
                _ if tok.starts_with("window=") => s.ent.ty_window = put(bp, &mut pos, tok[7..].as_bytes()),
                _ if tok.starts_with('#') => { let c = rest.trim_start(); s.ent.ty_comment = put(bp, &mut pos, c.as_bytes()); break; }
                _ => {}
            }
        }
        &mut s.ent
    }
}

unsafe fn load() {
    // SAFETY: lazily slurp /etc/ttys into owned line strings.
    unsafe {
        let s = &mut *S.0.get();
        if s.loaded { return; }
        if let Some(b) = crate::nss::shared::read_file(b"/etc/ttys\0") {
            s.lines = core::str::from_utf8(&b).unwrap_or("").lines().map(String::from).collect();
        }
        s.loaded = true;
    }
}

// # C: struct ttyent *getttyent(void)
#[no_mangle]
pub unsafe extern "C" fn getttyent() -> *mut ttyent {
    // SAFETY: lazy-load, then return successive non-comment entries.
    unsafe {
        load();
        loop {
            let line = {
                let s = &mut *S.0.get();
                if s.idx >= s.lines.len() { return core::ptr::null_mut(); }
                let l = s.lines[s.idx].clone();
                s.idx += 1;
                l
            };
            let e = parse(&line);
            if !e.is_null() { return e; }
        }
    }
}
// # C: struct ttyent *getttynam(const char *tty)
#[no_mangle]
pub unsafe extern "C" fn getttynam(tty: *const u8) -> *mut ttyent {
    // SAFETY: tty NUL-terminated; scan all entries for a matching ty_name.
    unsafe {
        let n = { let mut k = 0; while *tty.add(k) != 0 { k += 1; } k };
        let want = core::slice::from_raw_parts(tty, n);
        setttyent();
        loop {
            let e = getttyent();
            if e.is_null() { return core::ptr::null_mut(); }
            let nm = (*e).ty_name;
            let nl = { let mut k = 0; while *nm.add(k) != 0 { k += 1; } k };
            if core::slice::from_raw_parts(nm, nl) == want { return e; }
        }
    }
}
// # C: int setttyent(void) — 1 if /etc/ttys opened, 0 if it could not (glibc).
#[no_mangle]
pub unsafe extern "C" fn setttyent() -> i32 {
    // SAFETY: reset the cursor and (re)load /etc/ttys; success mirrors glibc's
    // fopen result (0 when the file is absent).
    unsafe {
        let s = &mut *S.0.get();
        s.idx = 0; s.loaded = true;
        match crate::nss::shared::read_file(b"/etc/ttys\0") {
            Some(b) => { s.lines = core::str::from_utf8(&b).unwrap_or("").lines().map(String::from).collect(); 1 }
            None => { s.lines = Vec::new(); 0 }
        }
    }
}
// # C: int endttyent(void)
#[no_mangle]
pub unsafe extern "C" fn endttyent() -> i32 {
    // SAFETY: reset the single-threaded global ttys cursor + free its lines.
    unsafe { let s = &mut *S.0.get(); s.idx = 0; s.loaded = false; s.lines = Vec::new(); } 1
}
