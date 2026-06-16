//! nss — passwd/group/shadow (docs/59§3, §6 G14). The file-format parsers
//! live in `crate::nss` (the workspace nss crate); this module exposes the
//! glibc C ABI: struct passwd/group/spwd + getpwnam/getpwuid/getgrnam/
//! getgrgid (backed by the `files` backend /etc/passwd|group). nsswitch.conf
//! dispatch beyond `files`, the _r reentrant variants and set/get/endpwent
//! iteration are follow-ups. Struct packing (Rust Passwd → C strings in a
//! caller buffer) is pure + hosted-tested; file I/O is freestanding.
#![allow(clippy::upper_case_acronyms)]
extern crate alloc;
#[cfg(feature = "freestanding")]
use alloc::vec::Vec;

pub mod r#enum;
pub mod shadow;
#[cfg(feature = "freestanding")]
pub mod putent;
#[cfg(feature = "freestanding")]
pub mod aliases;

#[repr(C)]
pub struct passwd {
    pub pw_name: *mut u8,
    pub pw_passwd: *mut u8,
    pub pw_uid: u32,
    pub pw_gid: u32,
    pub pw_gecos: *mut u8,
    pub pw_dir: *mut u8,
    pub pw_shell: *mut u8,
}
const _: () = assert!(core::mem::size_of::<passwd>() == 48);

#[repr(C)]
pub struct group {
    pub gr_name: *mut u8,
    pub gr_passwd: *mut u8,
    pub gr_gid: u32,
    __pad: u32,
    pub gr_mem: *mut *mut u8,
}
const _: () = assert!(core::mem::size_of::<group>() == 32);

#[repr(C)]
pub struct spwd {
    pub sp_namp: *mut u8,
    pub sp_pwdp: *mut u8,
    pub sp_lstchg: i64,
    pub sp_min: i64,
    pub sp_max: i64,
    pub sp_warn: i64,
    pub sp_inact: i64,
    pub sp_expire: i64,
    pub sp_flag: u64,
}
const _: () = assert!(core::mem::size_of::<spwd>() == 72);

// Append `s` + NUL into buf at `pos`; return (ptr-into-buf, new pos) or None.
fn put(buf: &mut [u8], pos: usize, s: &[u8]) -> Option<(*mut u8, usize)> {
    let end = pos + s.len() + 1;
    if end > buf.len() { return None; }
    buf[pos..pos + s.len()].copy_from_slice(s);
    buf[pos + s.len()] = 0;
    let p = buf[pos..].as_mut_ptr();
    Some((p, end))
}

/// Pack a parsed Passwd into `buf` (NUL-terminated strings) + fill `out`'s
/// pointers/ids. Pure; false if buf too small.
///
/// # C: serialize Passwd strings into buf, point out at them
pub(crate) fn pack_passwd(p: &libnss::Passwd, buf: &mut [u8], out: &mut passwd) -> bool {
    out.pw_uid = p.uid;
    out.pw_gid = p.gid;
    let mut pos = 0;
    for (field, dst) in [
        (&p.name, &mut out.pw_name as *mut *mut u8),
        (&p.passwd, &mut out.pw_passwd as *mut *mut u8),
        (&p.gecos, &mut out.pw_gecos as *mut *mut u8),
        (&p.home, &mut out.pw_dir as *mut *mut u8),
        (&p.shell, &mut out.pw_shell as *mut *mut u8),
    ] {
        match put(buf, pos, field.as_bytes()) {
            Some((ptr, np)) => {
                // SAFETY: dst is a field of `out`, valid for this write.
                unsafe { *dst = ptr; }
                pos = np;
            }
            None => return false,
        }
    }
    true
}

/// Pack a parsed Group into `buf` + the `memv` member-pointer array; point
/// `out` at them. Pure; false if buffers too small.
///
/// # C: serialize Group strings + member vector, point out at them
pub(crate) fn pack_group(g: &libnss::Group, buf: &mut [u8], memv: &mut [*mut u8], out: &mut group) -> bool {
    out.gr_gid = g.gid;
    out.__pad = 0;
    if g.members.len() + 1 > memv.len() { return false; }
    let mut pos = 0;
    match put(buf, pos, g.name.as_bytes()) { Some((p, np)) => { out.gr_name = p; pos = np; } None => return false }
    match put(buf, pos, g.passwd.as_bytes()) { Some((p, np)) => { out.gr_passwd = p; pos = np; } None => return false }
    for (k, m) in g.members.iter().enumerate() {
        match put(buf, pos, m.as_bytes()) { Some((p, np)) => { memv[k] = p; pos = np; } None => return false }
    }
    memv[g.members.len()] = core::ptr::null_mut();
    out.gr_mem = memv.as_mut_ptr();
    true
}

/// Pack a parsed Shadow into `buf` (NUL-terminated name+hash) + fill `out`'s
/// pointers/longs. Pure; false if buf too small.
///
/// # C: serialize Shadow strings into buf, point out at them
pub(crate) fn pack_shadow(s: &libnss::Shadow, buf: &mut [u8], out: &mut spwd) -> bool {
    out.sp_lstchg = s.last_change; out.sp_min = s.min; out.sp_max = s.max;
    out.sp_warn = s.warn; out.sp_inact = s.inactive; out.sp_expire = s.expire;
    out.sp_flag = !0u64; // glibc reads -1 (all-ones) when reserved field absent
    let mut pos = 0;
    match put(buf, pos, s.name.as_bytes()) { Some((p, np)) => { out.sp_namp = p; pos = np; } None => return false }
    match put(buf, pos, s.passwd_hash.as_bytes()) { Some((p, _)) => { out.sp_pwdp = p; } None => return false }
    true
}

#[cfg(feature = "freestanding")]
pub(crate) mod shared {
    //! Freestanding helpers shared by mod.rs `exports`, `r#enum`, `shadow`:
    //! whole-file slurp + static-buffer packers for the non-`_r` get* calls.
    use super::*;
    use crate::arch::syscall::{sys1, sys3, sys4};
    use crate::internal::nr;
    use core::cell::UnsafeCell;

    pub(crate) const PWBUF: usize = 1024;
    pub(crate) const MEMMAX: usize = 64;

    pub(crate) struct PwState { pub ent: passwd, pub buf: [u8; PWBUF] }
    pub(crate) struct GrState { pub ent: group, pub buf: [u8; PWBUF], pub mem: [*mut u8; MEMMAX] }
    pub(crate) struct SpState { pub ent: spwd, pub buf: [u8; PWBUF] }
    struct St { pw: UnsafeCell<PwState>, gr: UnsafeCell<GrState>, sp: UnsafeCell<SpState> }
    // SAFETY: the non-reentrant get* calls use these process-global statics
    // single-threaded (glibc's getpwent is likewise not thread-safe; threads
    // use the _r variants); no concurrent aliasing within the libc contract.
    unsafe impl Sync for St {}
    static S: St = St {
        pw: UnsafeCell::new(PwState { ent: ZERO_PW, buf: [0; PWBUF] }),
        gr: UnsafeCell::new(GrState { ent: ZERO_GR, buf: [0; PWBUF], mem: [core::ptr::null_mut(); MEMMAX] }),
        sp: UnsafeCell::new(SpState { ent: ZERO_SP, buf: [0; PWBUF] }),
    };
    pub(crate) const ZERO_PW: passwd = passwd { pw_name: core::ptr::null_mut(), pw_passwd: core::ptr::null_mut(), pw_uid: 0, pw_gid: 0, pw_gecos: core::ptr::null_mut(), pw_dir: core::ptr::null_mut(), pw_shell: core::ptr::null_mut() };
    pub(crate) const ZERO_GR: group = group { gr_name: core::ptr::null_mut(), gr_passwd: core::ptr::null_mut(), gr_gid: 0, __pad: 0, gr_mem: core::ptr::null_mut() };
    pub(crate) const ZERO_SP: spwd = spwd { sp_namp: core::ptr::null_mut(), sp_pwdp: core::ptr::null_mut(), sp_lstchg: 0, sp_min: 0, sp_max: 0, sp_warn: 0, sp_inact: 0, sp_expire: 0, sp_flag: 0 };

    /// # C: int openat(AT_FDCWD,path,O_RDONLY); read to EOF; close
    pub(crate) unsafe fn read_file(path: &[u8]) -> Option<Vec<u8>> {
        // SAFETY: path is NUL-terminated; openat read-only, read to EOF, close.
        unsafe {
            const AT_FDCWD: usize = (-100i64) as usize;
            let fd = sys4(nr::OPENAT, AT_FDCWD, path.as_ptr() as usize, 0, 0);
            if fd < 0 { return None; }
            let mut out = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let r = sys3(nr::READ, fd as usize, chunk.as_mut_ptr() as usize, chunk.len());
                if r <= 0 { break; }
                out.extend_from_slice(&chunk[..r as usize]);
            }
            sys1(nr::CLOSE, fd as usize);
            Some(out)
        }
    }

    /// # C: struct passwd *_fill(const struct Passwd*) into static buffer
    pub(crate) unsafe fn fill_pw(p: &libnss::Passwd) -> *mut passwd {
        // SAFETY: writes the static PwState single-threaded; returns its addr.
        unsafe {
            let st = &mut *S.pw.get();
            if pack_passwd(p, &mut st.buf, &mut st.ent) { &mut st.ent } else { core::ptr::null_mut() }
        }
    }
    /// # C: struct group *_fill(const struct Group*) into static buffer
    pub(crate) unsafe fn fill_gr(g: &libnss::Group) -> *mut group {
        // SAFETY: writes the static GrState single-threaded; returns its addr.
        unsafe {
            let st = &mut *S.gr.get();
            if pack_group(g, &mut st.buf, &mut st.mem, &mut st.ent) { &mut st.ent } else { core::ptr::null_mut() }
        }
    }
    /// # C: struct spwd *_fill(const struct Shadow*) into static buffer
    pub(crate) unsafe fn fill_sp(s: &libnss::Shadow) -> *mut spwd {
        // SAFETY: writes the static SpState single-threaded; returns its addr.
        unsafe {
            let st = &mut *S.sp.get();
            if pack_shadow(s, &mut st.buf, &mut st.ent) { &mut st.ent } else { core::ptr::null_mut() }
        }
    }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use super::shared::{fill_pw, fill_gr, read_file};
    use crate::string::len::strlen_impl;

    // # C: struct passwd *getpwnam(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn getpwnam(name: *const u8) -> *mut passwd {
        // SAFETY: name is NUL-terminated; parse /etc/passwd and match by name.
        unsafe {
            let buf = match read_file(b"/etc/passwd\0") { Some(b) => b, None => return core::ptr::null_mut() };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for p in libnss::parse_passwd(&buf) {
                if p.name.as_bytes() == want { return fill_pw(&p); }
            }
            core::ptr::null_mut()
        }
    }
    // # C: struct passwd *getpwuid(uid_t uid)
    #[no_mangle]
    pub unsafe extern "C" fn getpwuid(uid: u32) -> *mut passwd {
        // SAFETY: parse /etc/passwd and match the uid.
        unsafe {
            let buf = match read_file(b"/etc/passwd\0") { Some(b) => b, None => return core::ptr::null_mut() };
            for p in libnss::parse_passwd(&buf) {
                if p.uid == uid { return fill_pw(&p); }
            }
            core::ptr::null_mut()
        }
    }
    // # C: struct group *getgrnam(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn getgrnam(name: *const u8) -> *mut group {
        // SAFETY: name is NUL-terminated; parse /etc/group and match by name.
        unsafe {
            let buf = match read_file(b"/etc/group\0") { Some(b) => b, None => return core::ptr::null_mut() };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for g in libnss::parse_group(&buf) {
                if g.name.as_bytes() == want { return fill_gr(&g); }
            }
            core::ptr::null_mut()
        }
    }
    // # C: struct group *getgrgid(gid_t gid)
    #[no_mangle]
    pub unsafe extern "C" fn getgrgid(gid: u32) -> *mut group {
        // SAFETY: parse /etc/group and match the gid.
        unsafe {
            let buf = match read_file(b"/etc/group\0") { Some(b) => b, None => return core::ptr::null_mut() };
            for g in libnss::parse_group(&buf) {
                if g.gid == gid { return fill_gr(&g); }
            }
            core::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libnss::parse_passwd_line;

    #[test]
    fn pack_passwd_round_trip() {
        let p = parse_passwd_line("root:x:0:0:root:/root:/bin/bash").unwrap();
        let mut buf = [0u8; 256];
        let mut out = passwd { pw_name: core::ptr::null_mut(), pw_passwd: core::ptr::null_mut(), pw_uid: 9, pw_gid: 9, pw_gecos: core::ptr::null_mut(), pw_dir: core::ptr::null_mut(), pw_shell: core::ptr::null_mut() };
        assert!(pack_passwd(&p, &mut buf, &mut out));
        assert_eq!(out.pw_uid, 0);
        assert_eq!(out.pw_gid, 0);
        // SAFETY: pack_passwd set the pointers into `buf`; read back the strings.
        unsafe {
            let name = core::ffi::CStr::from_ptr(out.pw_name as *const i8).to_str().unwrap();
            let shell = core::ffi::CStr::from_ptr(out.pw_shell as *const i8).to_str().unwrap();
            assert_eq!(name, "root");
            assert_eq!(shell, "/bin/bash");
        }
    }

    #[test]
    fn struct_sizes_match_host() {
        assert_eq!(core::mem::size_of::<passwd>(), core::mem::size_of::<libc::passwd>());
        assert_eq!(core::mem::size_of::<group>(), core::mem::size_of::<libc::group>());
        assert_eq!(core::mem::size_of::<spwd>(), core::mem::size_of::<libc::spwd>());
    }

    #[test]
    fn pack_shadow_round_trip() {
        let s = libnss::parse_shadow_line("alice:$6$salt$hash:19000:0:99999:7:::").unwrap();
        let mut buf = [0u8; 256];
        let mut out = ZERO_SP_TEST;
        assert!(pack_shadow(&s, &mut buf, &mut out));
        assert_eq!(out.sp_lstchg, 19000);
        assert_eq!(out.sp_max, 99999);
        assert_eq!(out.sp_inact, -1);
        // SAFETY: pack_shadow set the pointers into `buf`; read the strings.
        unsafe {
            let name = core::ffi::CStr::from_ptr(out.sp_namp as *const i8).to_str().unwrap();
            let hash = core::ffi::CStr::from_ptr(out.sp_pwdp as *const i8).to_str().unwrap();
            assert_eq!(name, "alice");
            assert_eq!(hash, "$6$salt$hash");
        }
    }
    const ZERO_SP_TEST: spwd = spwd { sp_namp: core::ptr::null_mut(), sp_pwdp: core::ptr::null_mut(), sp_lstchg: 0, sp_min: 0, sp_max: 0, sp_warn: 0, sp_inact: 0, sp_expire: 0, sp_flag: 0 };
}
