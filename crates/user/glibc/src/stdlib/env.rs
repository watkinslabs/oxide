// Environment (docs/59§6 G7). `environ`/`__environ`/`_environ` is the char** the
// kernel hands us via envp (set in __libc_start_main). getenv reads it;
// setenv/unsetenv/putenv/clearenv manage a malloc'd owned copy
// (copy-on-first-write) under a spinlock. find_env/make_entry are pure
// and unit-tested; the global getenv is exercised by the boot smoke.
use crate::string::len::strlen_impl;

// Compare entry "NAME=..." against name[..nlen]; return value ptr if match.
pub(crate) unsafe fn entry_value(entry: *const u8, name: *const u8, nlen: usize) -> Option<*mut u8> {
    // SAFETY: entry and name are NUL-terminated; we read entry[0..=nlen]
    // and name[0..nlen], all within their strings.
    unsafe {
        let mut i = 0;
        while i < nlen {
            if *entry.add(i) != *name.add(i) { return None; }
            i += 1;
        }
        if *entry.add(nlen) == b'=' { Some(entry.add(nlen + 1) as *mut u8) } else { None }
    }
}

pub(crate) unsafe fn find_env(environ: *const *const u8, name: *const u8, nlen: usize) -> *mut u8 {
    // SAFETY: environ is a NULL-terminated array of NUL-terminated strings.
    unsafe {
        if environ.is_null() { return core::ptr::null_mut(); }
        let mut i = 0;
        loop {
            let e = *environ.add(i);
            if e.is_null() { return core::ptr::null_mut(); }
            if let Some(v) = entry_value(e, name, nlen) { return v; }
            i += 1;
        }
    }
}

// malloc a fresh "name=value\0" entry. null on OOM.
pub(crate) unsafe fn make_entry(name: *const u8, value: *const u8) -> *mut u8 {
    // SAFETY: name/value NUL-terminated; allocate exactly the joined size.
    unsafe {
        let nl = strlen_impl(name);
        let vl = strlen_impl(value);
        let p = crate::malloc::heap::malloc(nl + 1 + vl + 1);
        if p.is_null() { return p; }
        core::ptr::copy_nonoverlapping(name, p, nl);
        *p.add(nl) = b'=';
        core::ptr::copy_nonoverlapping(value, p.add(nl + 1), vl);
        *p.add(nl + 1 + vl) = 0;
        p
    }
}

#[cfg(feature = "freestanding")]
pub(crate) use imp::{current_environ, init_environ};

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[repr(transparent)]
    struct CharPP(UnsafeCell<*mut *mut u8>);
    // SAFETY: the char** is only mutated under LOCK; reads of the bare
    // pointer (getenv / program access) observe a consistent array.
    unsafe impl Sync for CharPP {}

    // # C: char **environ; (and __environ/_environ aliases below)
    #[no_mangle]
    static environ: CharPP = CharPP(UnsafeCell::new(core::ptr::null_mut()));
    // __environ/_environ are the same object (glibc keeps them aliased).
    core::arch::global_asm!(
        ".globl __environ",
        ".set __environ, environ",
        ".globl _environ",
        ".set _environ, environ",
    );
    unsafe extern "C" {
        #[link_name = "__environ"]
        static environ_dunder_alias: CharPP;
        #[link_name = "_environ"]
        static environ_single_alias: CharPP;
    }

    static OWNED: AtomicBool = AtomicBool::new(false);
    static CAP: AtomicUsize = AtomicUsize::new(0);
    static LOCK: AtomicBool = AtomicBool::new(false);

    fn lock() { while LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { core::hint::spin_loop(); } }
    fn unlock() { LOCK.store(false, Ordering::Release); }
    unsafe fn load() -> *mut *mut u8 {
        // SAFETY: reads the current environ array pointer.
        unsafe { *environ.0.get() }
    }
    unsafe fn store(p: *mut *mut u8) {
        // SAFETY: writes the environ array pointer under LOCK. The alias writes
        // keep non-PIE COPY relocations for __environ/_environ synchronized too.
        unsafe {
            *environ.0.get() = p;
            *environ_dunder_alias.0.get() = p;
            *environ_single_alias.0.get() = p;
        }
    }
    unsafe fn count(a: *mut *mut u8) -> usize {
        // SAFETY: a is null or a NULL-terminated array; scan stops at NULL.
        unsafe { let mut n = 0; if !a.is_null() { while !(*a.add(n)).is_null() { n += 1; } } n }
    }

    // called once by __libc_start_main with the kernel envp.
    pub(crate) unsafe fn init_environ(envp: *mut *mut u8) {
        // SAFETY: envp is the kernel-provided NULL-terminated env array.
        unsafe { store(envp); }
    }

    /// # C: the current environ array (for execv/execvp/system)
    pub(crate) fn current_environ() -> *mut *mut u8 {
        // SAFETY: a plain pointer load; the array stays valid for the process.
        unsafe { load() }
    }

    // ensure environ points at a malloc'd array with room for ≥1 more.
    unsafe fn ensure_owned() -> bool {
        // SAFETY: called under LOCK; (re)allocates the owned array.
        unsafe {
            let cur = load();
            if !OWNED.load(Ordering::Relaxed) {
                let n = count(cur);
                let cap = n + 8;
                let na = crate::malloc::heap::malloc((cap + 1) * 8) as *mut *mut u8;
                if na.is_null() { return false; }
                for i in 0..n { *na.add(i) = *cur.add(i); }
                *na.add(n) = core::ptr::null_mut();
                store(na);
                OWNED.store(true, Ordering::Relaxed);
                CAP.store(cap, Ordering::Relaxed);
            } else {
                let n = count(cur);
                if n + 1 > CAP.load(Ordering::Relaxed) {
                    let cap = (CAP.load(Ordering::Relaxed) + 1) * 2;
                    let na = crate::malloc::heap::realloc(cur as *mut u8, (cap + 1) * 8) as *mut *mut u8;
                    if na.is_null() { return false; }
                    store(na);
                    CAP.store(cap, Ordering::Relaxed);
                }
            }
            true
        }
    }

    // A valid environment variable name is non-empty and contains no '='.
    unsafe fn bad_name(name: *const u8) -> bool {
        // SAFETY: name is a NUL-terminated C string; scan to the terminator.
        unsafe {
            if *name == 0 { return true; }
            let mut i = 0;
            while *name.add(i) != 0 { if *name.add(i) == b'=' { return true; } i += 1; }
            false
        }
    }

    unsafe fn put_entry(name: *const u8, nlen: usize, entry: *mut u8) -> i32 {
        // SAFETY: under LOCK; replaces a matching entry or appends `entry`.
        unsafe {
            let cur = load();
            let n = count(cur);
            for i in 0..n {
                if entry_value(*cur.add(i), name, nlen).is_some() { *cur.add(i) = entry; return 0; }
            }
            if !ensure_owned() { return -1; }
            let cur = load();
            let n = count(cur);
            *cur.add(n) = entry;
            *cur.add(n + 1) = core::ptr::null_mut();
            0
        }
    }

    // # C: char *getenv(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn getenv(name: *const u8) -> *mut u8 {
        // SAFETY: name NUL-terminated; reads the environ array.
        unsafe { find_env(load() as *const *const u8, name, strlen_impl(name)) }
    }
    // # C: char *secure_getenv(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn secure_getenv(name: *const u8) -> *mut u8 {
        // SAFETY: no AT_SECURE tracking yet → same as getenv (safe: we are
        // not setuid-aware; refined at G9 hardening).
        unsafe { getenv(name) }
    }
    // # C: char *__secure_getenv(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn __secure_getenv(name: *const u8) -> *mut u8 {
        // SAFETY: internal alias has the same C-string contract as secure_getenv.
        unsafe { secure_getenv(name) }
    }
    // # C: int setenv(const char *name, const char *value, int overwrite)
    #[no_mangle]
    pub unsafe extern "C" fn setenv(name: *const u8, value: *const u8, overwrite: i32) -> i32 {
        // SAFETY: name/value NUL-terminated; mutates environ under LOCK.
        unsafe {
            if bad_name(name) { crate::internal::errno::set(22); return -1; }
            let nlen = strlen_impl(name);
            lock();
            if overwrite == 0 && !find_env(load() as *const *const u8, name, nlen).is_null() { unlock(); return 0; }
            let e = make_entry(name, value);
            if e.is_null() { unlock(); crate::internal::errno::set(12); return -1; }
            let r = put_entry(name, nlen, e);
            unlock();
            r
        }
    }
    // # C: int unsetenv(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn unsetenv(name: *const u8) -> i32 {
        // SAFETY: name NUL-terminated; compacts environ under LOCK.
        unsafe {
            if bad_name(name) { crate::internal::errno::set(22); return -1; }
            let nlen = strlen_impl(name);
            lock();
            let cur = load();
            let mut w = 0usize;
            let mut r = 0usize;
            if !cur.is_null() {
                while !(*cur.add(r)).is_null() {
                    if entry_value(*cur.add(r), name, nlen).is_none() { *cur.add(w) = *cur.add(r); w += 1; }
                    r += 1;
                }
                *cur.add(w) = core::ptr::null_mut();
            }
            unlock();
            0
        }
    }
    // # C: int putenv(char *string) — adopts the caller's "NAME=VALUE".
    #[no_mangle]
    pub unsafe extern "C" fn putenv(string: *mut u8) -> i32 {
        // SAFETY: string NUL-terminated "NAME=VALUE"; stored by reference.
        unsafe {
            let mut nlen = 0;
            while *string.add(nlen) != 0 && *string.add(nlen) != b'=' { nlen += 1; }
            if *string.add(nlen) != b'=' { return unsetenv(string); }
            lock();
            let r = put_entry(string, nlen, string);
            unlock();
            r
        }
    }
    // # C: int clearenv(void)
    #[no_mangle]
    pub unsafe extern "C" fn clearenv() -> i32 {
        // SAFETY: replace environ with an empty owned array under LOCK.
        unsafe {
            lock();
            let na = crate::malloc::heap::malloc(8) as *mut *mut u8;
            if na.is_null() { unlock(); return -1; }
            *na = core::ptr::null_mut();
            store(na);
            OWNED.store(true, Ordering::Relaxed);
            CAP.store(0, Ordering::Relaxed);
            unlock();
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{ffi::CString, vec::Vec};

    #[test]
    fn find_env_and_entry() {
        let entries = ["PATH=/bin", "HOME=/root", "TERM=xterm"];
        let cs: Vec<CString> = entries.iter().map(|s| CString::new(*s).unwrap()).collect();
        let mut arr: Vec<*const u8> = cs.iter().map(|c| c.as_ptr() as *const u8).collect();
        arr.push(core::ptr::null());
        let name = CString::new("HOME").unwrap();
        let bad = CString::new("NOPE").unwrap();
        // SAFETY: arr is NULL-terminated; names are NUL-terminated.
        unsafe {
            let v = find_env(arr.as_ptr(), name.as_ptr() as *const u8, 4);
            assert!(!v.is_null());
            assert_eq!(*v, b'/');
            assert_eq!(*v.add(1), b'r');
            assert!(find_env(arr.as_ptr(), bad.as_ptr() as *const u8, 4).is_null());
        }
    }
    #[test]
    fn make_entry_joins() {
        let n = CString::new("K").unwrap();
        let v = CString::new("vv").unwrap();
        // SAFETY: n/v NUL-terminated; e is a fresh "K=vv" we read then free.
        unsafe {
            let e = make_entry(n.as_ptr() as *const u8, v.as_ptr() as *const u8);
            assert!(!e.is_null());
            let bytes = core::slice::from_raw_parts(e, 5);
            assert_eq!(bytes, b"K=vv\0");
            crate::malloc::heap::free(e);
        }
    }
}
