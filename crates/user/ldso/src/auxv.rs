// Initial-process-stack parsing (docs/31§4 step 5). At process entry SP
// points at the SysV initial stack:
//   [argc][argv0..argv(argc-1)][NULL][envp..][NULL][auxv pairs..][AT_NULL]
// The rtld reads argc/argv/envp and the auxv (AT_PHDR/AT_ENTRY/AT_BASE/...)
// to find the app the kernel already mapped. Raw-pointer walks (no slice/
// std), exercised for real against a synthetic stack in hosted tests.

pub const AT_NULL: usize = 0;
pub const AT_PHDR: usize = 3;
pub const AT_PHENT: usize = 4;
pub const AT_PHNUM: usize = 5;
pub const AT_PAGESZ: usize = 6;
pub const AT_BASE: usize = 7;
pub const AT_ENTRY: usize = 9;
pub const AT_RANDOM: usize = 25;
pub const AT_EXECFN: usize = 31;

/// argc, read from the stack top.
/// # C: *(size_t*)sp
pub unsafe fn argc(sp: *const usize) -> usize {
    // SAFETY: sp is the kernel-provided initial stack pointer; its first
    // word is argc per the SysV process-startup ABI.
    unsafe { *sp }
}

/// Pointer to argv[0] (argv is NULL-terminated; envp follows).
/// # C: (char**)(sp + 1)
pub unsafe fn argv(sp: *const usize) -> *const *const u8 {
    // SAFETY: argv begins at sp+1 on the SysV initial stack.
    unsafe { sp.add(1) as *const *const u8 }
}

/// Pointer to envp[0] (after argv's NULL terminator).
/// # C: argv + argc + 1
pub unsafe fn envp(sp: *const usize) -> *const *const u8 {
    // SAFETY: envp follows the argc argv pointers and their NULL terminator.
    unsafe { (sp.add(1) as *const *const u8).add(*sp + 1) }
}

/// Walk the auxiliary vector for `at_type`; None if absent.
/// # C: scan (a_type,a_val) pairs after envp until AT_NULL
pub unsafe fn auxval(sp: *const usize, at_type: usize) -> Option<usize> {
    // SAFETY: the auxv begins after the NULL-terminated envp array and is a
    // sequence of (type,val) usize pairs ending at an AT_NULL type; we read
    // sequentially within that kernel-provided block.
    unsafe {
        // skip argc + argv + argv-NULL
        let mut p = sp.add(1 + *sp + 1);
        // skip envp until its NULL terminator
        while *p != 0 { p = p.add(1); }
        p = p.add(1); // past envp NULL → first auxv entry
        loop {
            let a_type = *p;
            let a_val = *p.add(1);
            if a_type == AT_NULL { return None; }
            if a_type == at_type { return Some(a_val); }
            p = p.add(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a synthetic initial stack: [argc, argv.., NULL, envp.., NULL,
    // (auxv pairs).., AT_NULL, 0]. Pointers are stored as usize.
    fn stack(argv: &[usize], envp_: &[usize], aux: &[(usize, usize)]) -> std::vec::Vec<usize> {
        let mut w = std::vec::Vec::new();
        w.push(argv.len()); // argc
        w.extend_from_slice(argv);
        w.push(0); // argv NULL
        w.extend_from_slice(envp_);
        w.push(0); // envp NULL
        for (t, v) in aux {
            w.push(*t);
            w.push(*v);
        }
        w.push(AT_NULL);
        w.push(0);
        w
    }

    #[test]
    fn parses_argc_argv_envp_auxv() {
        let w = stack(&[0x1111, 0x2222], &[0x3333], &[(AT_PHDR, 0x400040), (AT_ENTRY, 0xe), (AT_BASE, 0xb)]);
        let sp = w.as_ptr();
        // SAFETY: sp points at a live synthetic stack laid out per the ABI.
        unsafe {
            assert_eq!(argc(sp), 2);
            assert_eq!(*argv(sp), 0x1111 as *const u8);
            assert_eq!(*argv(sp).add(1), 0x2222 as *const u8);
            assert_eq!(*envp(sp), 0x3333 as *const u8);
            assert_eq!(*envp(sp).add(1), core::ptr::null()); // envp NULL
            assert_eq!(auxval(sp, AT_ENTRY), Some(0xe));
            assert_eq!(auxval(sp, AT_BASE), Some(0xb));
            assert_eq!(auxval(sp, AT_PAGESZ), None);
        }
    }

    #[test]
    fn empty_env() {
        let w = stack(&[0x10], &[], &[(AT_RANDOM, 0x77)]);
        let sp = w.as_ptr();
        // SAFETY: live synthetic stack with zero env entries.
        unsafe {
            assert_eq!(argc(sp), 1);
            assert_eq!(*envp(sp), core::ptr::null()); // immediate NULL
            assert_eq!(auxval(sp, AT_RANDOM), Some(0x77));
        }
    }
}
