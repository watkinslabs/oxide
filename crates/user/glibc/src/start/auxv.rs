// auxv walking (docs/59§6 G3). The kernel appends the auxiliary vector
// after envp on the initial stack: env words, a 0 terminator, then
// (a_type, a_val) pairs ending at AT_NULL. Word-granular walk — testable
// without a real stack. AT_RANDOM (25) → 16 random bytes used to seed the
// stack-protector canary; AT_PHDR/AT_ENTRY/etc. feed the rtld at G12.

pub const AT_NULL: usize = 0;
pub const AT_RANDOM: usize = 25;

// envp saved at __libc_start_main so getauxval(3) can walk the auxv after
// startup. Word-granular pointer; written once before main runs.
#[cfg(feature = "freestanding")]
mod saved {
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicUsize, Ordering};
    struct Cell(UnsafeCell<*const usize>);
    // SAFETY: written once in __libc_start_main before any thread exists, then
    // only read; no concurrent mutation of the stored envp pointer occurs.
    unsafe impl Sync for Cell {}
    static ENVP: Cell = Cell(UnsafeCell::new(core::ptr::null()));
    static SET: AtomicUsize = AtomicUsize::new(0);
    /// # C: stash the initial envp (→ auxv) for getauxval.
    pub(crate) fn store(envp: *const usize) {
        // SAFETY: single-threaded startup writes the saved envp slot once;
        // the SET flag guards readers against the pre-init null window.
        unsafe { *ENVP.0.get() = envp; }
        SET.store(1, Ordering::Release);
    }
    /// # C: the saved initial envp, or null before startup ran.
    pub(crate) fn load() -> *const usize {
        if SET.load(Ordering::Acquire) == 0 { return core::ptr::null(); }
        // SAFETY: SET observed; the slot was written once before main ran.
        unsafe { *ENVP.0.get() }
    }
}

/// # C: save initial envp for later getauxval lookups (called by __libc_start_main).
#[cfg(feature = "freestanding")]
pub(crate) fn save_envp(envp: *const usize) { saved::store(envp); }

// # C: unsigned long getauxval(unsigned long type)
#[cfg(feature = "freestanding")]
#[no_mangle]
pub unsafe extern "C" fn getauxval(at_type: core::ffi::c_ulong) -> core::ffi::c_ulong {
    const ENOENT: i32 = 2;
    // SAFETY: load() returns the kernel-provided envp saved at startup (or
    // null pre-init); find_auxval walks it within bounds to AT_NULL. Missing
    // entry → 0 + errno ENOENT, matching glibc.
    unsafe {
        let envp = saved::load();
        if envp.is_null() { crate::internal::errno::set(ENOENT); return 0; }
        match find_auxval(envp, at_type as usize) {
            Some(v) => v as core::ffi::c_ulong,
            None => { crate::internal::errno::set(ENOENT); 0 }
        }
    }
}

// Find an auxv entry's value. `envp` points at the first env word.
pub(crate) unsafe fn find_auxval(envp: *const usize, at_type: usize) -> Option<usize> {
    // SAFETY: envp is the kernel-provided env array; it is NUL-word
    // terminated and immediately followed by the auxv, so every step
    // stays inside the initial-stack block until AT_NULL ends it.
    unsafe {
        let mut p = envp;
        while *p != 0 { p = p.add(1); } // skip env strings
        p = p.add(1); // past the env terminator → auxv
        loop {
            let t = *p;
            if t == AT_NULL { return None; }
            let v = *p.add(1);
            if t == at_type { return Some(v); }
            p = p.add(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{find_auxval, AT_RANDOM};
    #[test]
    fn walks_env_then_auxv() {
        // [env0, env1, 0, AT_RANDOM, 0xCAFE, 6(unknown), 7, AT_NULL, 0]
        let words: [usize; 9] = [0x1000, 0x2000, 0, AT_RANDOM, 0xCAFE, 6, 7, 0, 0];
        let envp = words.as_ptr();
        // SAFETY: `words` is a live, properly terminated env+auxv layout.
        assert_eq!(unsafe { find_auxval(envp, AT_RANDOM) }, Some(0xCAFE));
        // SAFETY: same live, terminated env+auxv layout as above.
        assert_eq!(unsafe { find_auxval(envp, 99) }, None);
    }
}
