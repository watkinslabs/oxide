// sys_execve split out of syscall_glue.rs to keep it under the
// 1000-line cap (docs/08§7). The dispatch in syscall_glue.rs
// forwards NR_EXECVE here.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::{USER_VA_END, TimerOps};

/// B46: reset caught signal handlers to SIG_DFL per execve(2) ABI.
/// "All signals that were being caught by the calling thread (set
/// to a value other than SIG_DFL and SIG_IGN) are reset to the
/// default disposition." Without this, a SIGCHLD handler installed
/// by busybox-init at e.g. 0x4925f9 leaks into every execve'd
/// child — when the child later forks its own grandchild and the
/// grandchild exits, SIGCHLD fires with handler=0x4925f9, but that
/// address is in busybox's text not the child's, so iretq lands
/// on an unmapped page and the child silently SIGSEGVs in its
/// waitpid path.
/// # SAFETY: running task on this CPU; preempt-off; sole writer
/// to sigactions slot per `13§5` single-mutator invariant.
/// # C: O(1) — 64-slot scan.
fn reset_caught_signals(cur: &sched::Task) {
    // SAFETY: running task on this CPU, preempt-off; sole writer to sigactions slot per `13§5` single-mutator invariant for the duration of this execve.
    unsafe {
        let table = &mut *cur.sigactions.get();
        for slot in table.iter_mut() {
            if slot.handler != 0 && slot.handler != 1 {
                slot.handler  = 0;
                slot.flags    = 0;
                slot.restorer = 0;
                slot.mask     = 0;
            }
        }
    }
}

/// F129: sweep all other per-task state Linux execve(2) resets:
///   * sigaltstack → SS_DISABLE (per sigaltstack(2): "The alternate
///     signal stack is reset on each call to execve(2)")
///   * robust futex list → null (per set_robust_list(2): "On exec
///     the head is set to NULL.")
///   * pdeath_sig → 0 (per prctl(PR_SET_PDEATHSIG): "is cleared upon
///     a call to execve")
///   * alarm / interval timer → 0 (per alarm(2): "All asynchronous
///     events ... are cleared by execve()")
///   * POSIX timers → all disarmed and cleared (per timer_create(2):
///     "Timers are not preserved across an execve(2)")
///   * RT signal queues → drained (per signal(7) sigqueue semantics:
///     queued info is task-private and dies with the program image)
/// Signal mask (sigprocmask) and pending bitmap are PRESERVED per
/// execve(2) "the set of signals pending is preserved across execve".
/// # SAFETY: running task on this CPU, preempt-off; sole writer to
/// every slot per `13§5` single-mutator invariant.
/// # C: O(N_timers) — bounded by `PosixTimer::SLOTS` (32).
fn reset_per_execve_state(cur: &sched::Task) {
    use core::sync::atomic::Ordering;
    // sigaltstack disabled.
    cur.sigaltstack_sp.store(0, Ordering::Release);
    cur.sigaltstack_size.store(0, Ordering::Release);
    cur.sigaltstack_flags.store(2 /* SS_DISABLE */, Ordering::Release);
    // robust futex list dropped — stale user-VA into the old AS.
    cur.robust_list_head.store(0, Ordering::Release);
    cur.robust_list_len.store(0, Ordering::Release);
    // parent-death signal cleared — handler would be in the old text.
    cur.pdeathsig.store(0, Ordering::Release);
    // ITIMER_REAL / alarm() armed against the dying image.
    cur.alarm_ns.store(0, Ordering::Release);
    cur.alarm_interval_ns.store(0, Ordering::Release);
    // POSIX timers — disarm + clear handler addresses (which point
    // into the old text).
    // SAFETY: running task on this CPU, preempt-off; sole writer to the per-task posix_timers slot per `13§5` single-mutator invariant for the duration of this execve.
    unsafe {
        let timers = &mut *cur.posix_timers.get();
        for t in timers.iter_mut() {
            *t = sched::PosixTimer::default();
        }
    }
    // RT signal queues — drain. The siginfos hold sigval_t.ptr values
    // that would point into the old AS. SAFETY: spinlock locks here,
    // single-CPU UP; the lock guards the per-task queue array.
    {
        let mut g = cur.rt_sigqueue.lock();
        for q in g.iter_mut() { q.clear(); }
    }
}


/// `execveat(dirfd, path, argv, envp, flags)` per Linux ABI. Honors
/// `AT_EMPTY_PATH` (flag 0x1000): when path is empty, exec the file
/// referenced by `dirfd`. This is the kernel side of `fexecve(3)`
/// (libc translates `fexecve(fd, ...)` to `execveat(fd, "", argv,
/// envp, AT_EMPTY_PATH)`). Non-empty paths route through execve.
/// dirfd is ignored for absolute paths.
/// # C: O(path + dentry depth) + execve_inner cost
pub fn sys_execveat(args: &SyscallArgs) -> i64 {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let dirfd = args.a0 as i32;
    let pathp = args.a1;
    let argv  = args.a2;
    let envp  = args.a3;
    let flags = args.a4;
    let path_is_empty = if pathp == 0 {
        true
    } else if pathp >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    } else {
        // SAFETY: pathp validated < USER_VA_END; one-byte probe.
        unsafe { core::ptr::read_volatile(pathp as *const u8) == 0 }
    };
    if path_is_empty && (flags & AT_EMPTY_PATH) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // SAFETY: running task; sole reader of fd_table slot per `13§5`.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let f = match fdt.get(dirfd) {
            Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
        };
        let kpath = f.dentry().absolute_path();
        if kpath.is_empty() { return -(Errno::Enoent.as_i32() as i64); }
        // Synthesise SyscallArgs where execve_inner sees argv/envp
        // in their familiar slots (a1, a2).
        let sa = SyscallArgs { a0: 0, a1: argv, a2: envp, a3: 0, a4: 0, a5: 0 };
        return execve_inner(&sa, kpath);
    }
    // Plain path-based execveat. dirfd ignored; sys_execve does the
    // user-pointer read + path resolution.
    let mut sa = *args;
    sa.a0 = pathp; sa.a1 = argv; sa.a2 = envp; sa.a3 = 0;
    sys_execve(&sa)
}

/// Read up to 64 bytes of a NUL-terminated path from a userspace
/// pointer into an owned Vec. Empty Vec ↔ NULL/empty user pointer.
/// Errors come back negated for the caller to forward.
/// # C: O(64)
fn read_user_exec_path(path_ptr: u64) -> Result<alloc::vec::Vec<u8>, i64> {
    if path_ptr == 0 { return Ok(alloc::vec::Vec::new()); }
    if path_ptr >= USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(64);
    for i in 0..64u64 {
        // SAFETY: bounded 64-byte read from validated user pointer < USER_VA_END; CPL=0 / EL1 reads through caller's AS pre-activate.
        let b = unsafe { core::ptr::read_volatile((path_ptr + i) as *const u8) };
        if b == 0 { break; }
        out.push(b);
    }
    Ok(out)
}

/// `sys_execve(path, argv, envp)` per `15§5` / `31§4`. Thin wrapper
/// that reads the user-space path then delegates to `execve_inner`.
/// # SAFETY: dispatch ctx, IRQs masked.
/// # C: O(64) + execve_inner cost
#[cfg(target_arch = "x86_64")]
pub fn sys_execve(args: &SyscallArgs) -> i64 {
    let path_owned = match read_user_exec_path(args.a0) {
        Ok(v) => v, Err(rc) => return rc,
    };
    execve_inner(args, path_owned)
}

/// execve body shared between `sys_execve` (path from user pointer)
/// and `sys_execveat` (path resolved from `dirfd` for AT_EMPTY_PATH).
/// `args.a1` = argv, `args.a2` = envp; `args.a0` is ignored — the
/// caller has already produced `path_owned` from whatever source.
/// # SAFETY: dispatch ctx, IRQs masked.
/// # C: O(phdrs) + O(N_vmas) + O(1)
#[cfg(target_arch = "x86_64")]
fn execve_inner(args: &SyscallArgs, path_owned: alloc::vec::Vec<u8>) -> i64 {
    use vmm::{AddressSpace, VmaBacking, VmaProt};
    use hal::UserVirtAddr;

    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    // Owned ext4 read storage; rooted in this fn frame so the blob's
    // lifetime extends across `load_static_blob` and drops at fn end.
    let mut ext4_blob: Option<alloc::vec::Vec<u8>> = None;
    let mut blob: &[u8] = if path_owned.is_empty() {
        crate::smoke::elf::EXEC_BLOB
    } else if let Some(v) = crate::syscalls::pathresolve::read_exec(&path_owned)
        .or_else(|| ext4::rootfs::read_file(&path_owned)) {
        ext4_blob = Some(v);
        // SAFETY: ext4_blob just-set; outlives the load_static_blob call below.
        ext4_blob.as_deref().expect("just set")
    } else {
        match crate::smoke::elf::lookup_blob(path_owned[0]) {
            Some(b) => b,
            None    => return -(Errno::Enoent.as_i32() as i64),
        }
    };

    // 1a. Snapshot argv + envp from the OLD user AS into kernel
    //     storage. After we activate the new AS, the old user
    //     pages are unmapped and the user-side argv/envp pointers
    //     would resolve to nothing. Linux ARG_MAX = 128 KiB total
    //     across both vectors; per-string limit is 32 pages. We
    //     enforce a generous total budget; per-string we cap at
    //     PATH_MAX-equivalent (4 KiB).
    const ARG_MAX_BYTES: usize  = 128 * 1024;   // Linux ARG_MAX
    const ARG_MAX_ENTRIES: usize = 1024;        // generous; Linux unlimited
    const ARG_MAX_STR: usize    = 4096;
    let mut argv_vec: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    let mut envp_vec: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    let mut total_bytes: usize = 0;
    let read_vec = |uva: u64,
                    out: &mut alloc::vec::Vec<alloc::vec::Vec<u8>>,
                    total: &mut usize| -> bool {
        if uva == 0 || uva >= USER_VA_END { return true; }
        for i in 0..ARG_MAX_ENTRIES {
            let p = uva + (i as u64) * 8;
            if p >= USER_VA_END { return false; }
            // SAFETY: argv/envp entries are 8-byte aligned per Linux ABI; bounded ARG_MAX_ENTRIES; CPL=0 reads through caller's active AS.
            let s = unsafe { core::ptr::read_volatile(p as *const u64) };
            if s == 0 { return true; }
            if s >= USER_VA_END { return false; }
            let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            for j in 0..ARG_MAX_STR {
                // SAFETY: bounded read up to ARG_MAX_STR from user pointer < USER_VA_END; CPL=0 reads through caller's AS.
                let b = unsafe { core::ptr::read_volatile((s + j as u64) as *const u8) };
                if b == 0 { break; }
                buf.push(b);
                *total += 1;
                if *total > ARG_MAX_BYTES { return false; }
            }
            out.push(buf);
        }
        true
    };
    if !read_vec(args.a1, &mut argv_vec, &mut total_bytes) {
        return -(Errno::E2big.as_i32() as i64);
    }
    if !read_vec(args.a2, &mut envp_vec, &mut total_bytes) {
        return -(Errno::E2big.as_i32() as i64);
    }

    // Shebang resolution. Only ext4-loaded files can be scripts —
    // the static `elf_smoke` blobs are all real ELFs. When the chain
    // fires, `argv_vec` is rewritten in place and `path_owned`/`blob`
    // are repointed at the final interpreter.
    let mut path_owned = path_owned;
    if ext4_blob.is_some() && blob.starts_with(b"#!") {
        let mut owned = ext4_blob.take().expect("ext4_blob.is_some()");
        if let Err(e) = resolve_shebang_chain(
            &mut owned, &mut path_owned, &mut argv_vec,
        ) {
            return -(e.as_i32() as i64);
        }
        ext4_blob = Some(owned);
        // SAFETY: ext4_blob just set; outlives the load_static_blob call.
        blob = ext4_blob.as_deref().expect("just set");
    }

    let argc = argv_vec.len();
    let envc = envp_vec.len();

    // 1. Allocate new PT root for the post-execve AS.
    // SAFETY: master PML4 captured at pmm::user_as::init; PMM up.
    let new_root = match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
        Some(r) => r,
        None    => return -(Errno::Enomem.as_i32() as i64),
    };

    // 2. Build the new AS shell + load the ELF + register stack.
    let new_as = match AddressSpace::new(new_root) {
        Ok(a)  => a,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };
    pmm::user_as::install_teardown(&new_as);
    let img = match elf_load::load_static_blob(blob, &new_as) {
        Ok(i)  => i,
        Err(_) => return -(Errno::Enoexec.as_i32() as i64),
    };
    // 64 KiB stack — busybox + glibc/musl static binaries routinely
    // use >4 KiB through SIGCHLD handlers, /proc parsers, and stdio
    // init. A single 4 KiB page underflows on the first wide musl
    // F230: real Linux layout. The stack reservation is RLIMIT_STACK
    // (default 8 MiB per `crate::rlimit::DEFAULT_RLIMITS`) at the
    // top of user VA. Full reservation up front mirrors Linux's
    // setup_arg_pages() — no auto-grow under RLIMIT_STACK.
    // mmap_base = stack_bottom - MMAP_BASE_GAP (128 MiB) per
    // `arch_pick_mmap_base`. Result: stack + mmap arena are
    // multi-gigabyte apart, matching real Linux.
    let rlim_stack: u64 = {
        // SAFETY: rlimits slot single-mutator per `13§5`; cur is the
        // running task on this CPU; we only read, no concurrent writer.
        let (rc, _) = unsafe { (*cur.rlimits.get())[sched::rlimit::rlim::STACK] };
        // Page-align; clamp at 1 GiB so a buggy setrlimit can't
        // reserve all of user VA.
        ((rc + 0xfff) & !0xfff).min(0x4000_0000)
    };
    let stack_top: u64 = hal::USER_VA_END - 0x10000;
    let exec_user_stack_va_u: u64  = stack_top - rlim_stack;
    let exec_user_stack_top_u: u64 = stack_top;
    let exec_user_stack_len_u: usize = rlim_stack as usize;
    // Local re-binds keep the rest of this fn (which references
    // the stack-region locals by name) unchanged.
    let exec_user_stack_va  = exec_user_stack_va_u;
    let exec_user_stack_top = exec_user_stack_top_u;
    let exec_user_stack_len = exec_user_stack_len_u;
    let stack_hint = UserVirtAddr::new(exec_user_stack_va)
        .expect("exec_user_stack_va in user range");
    // GROWSDOWN flag wires the stack VMA into the page-fault
    // auto-extend path: any write below the current `vma.start`
    // within 64 KiB extends the VMA downward (Linux's
    // STACK_GUARD_GAP), so a 64 KiB initial allocation
    // demand-grows up to RLIMIT_STACK per docs/31§5. F123:
    // dhcpcd-aarch64 overflowed the 64 KiB initial frame on its
    // first wide musl init pass and SIGSEGV'd because execve was
    // shipping PRIVATE|ANONYMOUS without GROWSDOWN, leaving
    // try_grow_stack with no VMA to extend.
    if new_as.mmap(
        Some(stack_hint), exec_user_stack_len,
        VmaProt::READ | VmaProt::WRITE,
        vmm::EXEC_STACK_VMA_FLAGS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    // Linux `arch_pick_mmap_base`: anon-mmap arena top sits
    // MMAP_BASE_GAP (128 MiB) below the stack reservation bottom.
    new_as.set_mmap_base(exec_user_stack_va.saturating_sub(vmm::MMAP_BASE_GAP));

    // 3. Replace `current.mm` with the new AS and activate it.
    //    Order: activate BEFORE replace_mm so CR3 doesn't dangle
    //    if drop runs concurrently — but on UP single-CPU the
    //    order is purely defensive.
    use hal::MmuOps;
    // SAFETY: new_root carries kernel-half cloned from master per P2-19; activate writes CR3 + flushes user TLB; preempt-off; single-CPU.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(new_root); }
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent reader of mm on another CPU (UP v1).
    unsafe { cur.replace_mm(Some(new_as)); }

    // F152-2: Linux execve resets FS_BASE = 0; user crt1 calls
    // arch_prctl(ARCH_SET_FS, tcb) once musl's __init_tls picks
    // a TCB VA. The previous code mmap'd a fixed kernel-side TLS
    // region at 0x600000 + wrote a self-pointer + set FS_BASE to
    // 0x601000 — a hack to support oxide_start.h-shimmed binaries
    // that bypassed musl's TLS init. With every userspace binary
    // now linked against full musl crt1 (F150-1 + F152-1), that
    // hack is dead weight; the user-side __init_tls path is the
    // canonical one.
    // SAFETY: zeroing FS_BASE is a wrmsr at CPL=0; subsequent
    // arch_prctl from user crt1 overwrites with the real TCB.
    unsafe {
        hal_x86_64::set_user_fs_base(0);
        let ctx_ptr: *mut hal_x86_64::ContextX86_64 = cur.arch_ctx_ptr();
        (*ctx_ptr).fs_base = 0;
    }

    // P3-61: drop FD_CLOEXEC fds before the new program runs.
    // SAFETY: same single-mutator invariant on fd_table as mm.
    if let Some(fdt) = unsafe { cur.fd_table_ref() } {
        fdt.close_on_exec();
    }
    reset_caught_signals(&cur);
    reset_per_execve_state(&cur);
    // F156: clear CLONE_VFORK rendezvous so the parent (suspended in
    // sys_clone) returns. Linux fires `mm_struct::vfork_done` at
    // exec time so the parent stops sharing the now-replaced mm.
    cur.vfork_pending.store(false, core::sync::atomic::Ordering::Release);

    // 4. Build the SysV initial stack (argc/argv/envp/auxv) per
    //    docs/31§4 step 5. v1 passes empty argv/envp; auxv carries
    //    AT_PHDR/PHENT/PHNUM/PAGESZ/ENTRY/RANDOM so static-PIE musl
    //    `_start` can locate its phdrs and seed its RNG.
    let random16 = {
        let ns = <hal_x86_64::X86TimerOps as TimerOps>::monotonic_ns().0;
        let mut r = [0u8; 16];
        for i in 0..16 { r[i] = (ns >> ((i % 8) * 8)) as u8 ^ (i as u8 * 0x9b); }
        r
    };
    // Materialise &[&[u8]] slices for the OLD-AS snapshot from the
    // heap-allocated argv/envp Vecs.
    let argv_slices: alloc::vec::Vec<&[u8]> = argv_vec.iter().map(|v| v.as_slice()).collect();
    let envp_slices: alloc::vec::Vec<&[u8]> = envp_vec.iter().map(|v| v.as_slice()).collect();
    // SAFETY: single-mutator per `13§5` for cmdline + environ + exe_path.
    let exec_path_for_caps = unsafe {
        *cur.cmdline.get() = Some(sched::argv_to_cmdline(&argv_slices[..argc]));
        *cur.environ.get() = Some(sched::argv_to_cmdline(&envp_slices[..envc]));
        let path_str = match core::str::from_utf8(&path_owned) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => alloc::string::String::new(),
        };
        if !path_str.is_empty() {
            *cur.exe_path.get() = Some(path_str.clone());
            // Linux semantics: /proc/<pid>/exe lives on the mm
            // (struct mm_struct::exe_file), shared by CLONE_VM
            // threads and fork-copied. Bind it to the new AS so
            // hardlinks to the same inode produce different
            // readlinks based on what the user actually invoked.
            if let Some(mm) = cur.mm_ref() {
                mm.set_exe_path(path_str.clone());
            }
            Some(path_str)
        } else { None }
    };
    // F103: file capabilities — apply security.capability xattr from the
    // exec path's inode to the calling task's cap_permitted / cap_effective.
    if let Some(p) = exec_path_for_caps {
        if let Some(inode) = crate::devfs::lookup(&p) {
            apply_file_caps_at_execve(&inode, cur);
        }
    }
    // 4b. Map the vDSO into the new AS so the SysV initial stack
    //     can publish AT_SYSINFO_EHDR. Failure is non-fatal — the
    //     auxv just gets 0 and userspace falls back to direct
    //     syscalls (same as kernels built without CONFIG_COMPAT_VDSO).
    let vdso_ehdr = crate::vdso::map_into_current().unwrap_or(0);

    // SAFETY: we activated new_root above, so user-VA writes from the kernel target the new AS; user_fault_handler will demand-fault the stack page.
    let new_sp = match unsafe {
        elf_load::stack::build_user_stack(
            exec_user_stack_top,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
            &path_owned,
            vdso_ehdr,
        )
    } {
        Some(sp) => sp,
        None     => return -(Errno::Enomem.as_i32() as i64),
    };

    // 5. Overwrite the per-task syscall stack's saved user-frame
    //    so the asm epilogue's `pop rcx; pop r11; pop rsp; sysretq`
    //    lands the user at the new program entry on the built stack.
    // SAFETY: we are running on cur's per-task syscall stack; current_user_frame() points at the live saved tail; the syscall asm pops from these same slots after we return.
    let frame = unsafe { &mut *hal_x86_64::current_user_frame() };
    frame[0] = img.user_ip();
    frame[1] = 0x202;                  // RFLAGS = IF=1 + reserved bit 1
    frame[2] = new_sp;

    debug_sched! {
        klog::write_raw(b"[INFO]  sys_execve: argc=");
        klog::write_dec_u64(argc as u64);
        klog::write_raw(b" envc=");
        klog::write_dec_u64(envc as u64);
        klog::write_raw(b" entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" sp=");
        klog::write_hex_u64(new_sp);
        klog::write_raw(b" new_root=");
        klog::write_hex_u64(new_root);
        klog::write_raw(b"\n");
    }

    // Return value irrelevant — sysretq goes to new program; rax
    // gets clobbered by the new program's first mov.
    0
}

/// aarch64 sys_execve — mirror of the x86 path. Differences vs x86:
///   1. Path lookup goes through `ext4::rootfs::read_file` (the ext4 root
///      mounted at boot) instead of x86's `elf_smoke` blob registry.
///   2. PT root allocator is `mmu_ops::new_user_l0` (aarch64 4-level
///      48-bit VA layout) instead of `new_user_pml4`.
///   3. AS activation calls `MmuOps::activate(root_pa)` which writes
///      TTBR0_EL1 + flushes user TLB.
///   4. Saved-eret-frame overwrite uses `hal_aarch64::current_svc_frame()`:
///      the SVC handler stashed sp at entry, we patch ELR_EL1 (entry),
///      SP_EL0 (new sp), SPSR_EL1 (=0 → EL0t with IRQs unmasked).
///   5. Stack VA reuses the same constant region as x86 (0x501000) for
///      v1 — separate per-arch consts not required since both are
///      below USER_VA_END on both arches.
///
/// # SAFETY: dispatch ctx, IRQs masked.
/// # C: O(phdrs) + O(N_vmas) + O(1)
#[cfg(target_arch = "aarch64")]
pub fn sys_execve(args: &SyscallArgs) -> i64 {
    let path_owned = match read_user_exec_path(args.a0) {
        Ok(v) => v, Err(rc) => return rc,
    };
    if path_owned.is_empty() {
        return -(Errno::Efault.as_i32() as i64);
    }
    execve_inner(args, path_owned)
}

/// aarch64 execve body. See x86_64 doc for the contract.
#[cfg(target_arch = "aarch64")]
fn execve_inner(args: &SyscallArgs, mut path_owned: alloc::vec::Vec<u8>) -> i64 {
    use core::sync::atomic::Ordering;
    use vmm::{AddressSpace, VmaBacking, VmaProt};
    use hal::{MmuOps, UserVirtAddr};

    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    let mut blob_vec = match crate::syscalls::pathresolve::read_exec(&path_owned)
        .or_else(|| ext4::rootfs::read_file(&path_owned)) {
        Some(v) => v,
        None    => return -(Errno::Enoent.as_i32() as i64),
    };

    // 1a. Snapshot argv / envp from the OLD AS (still active TTBR0).
    // Linux ARG_MAX = 128 KiB total; per-string PATH_MAX = 4 KiB.
    const ARG_MAX_BYTES: usize  = 128 * 1024;
    const ARG_MAX_ENTRIES: usize = 1024;
    const ARG_MAX_STR: usize    = 4096;
    let mut argv_vec: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    let mut envp_vec: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    let mut total_bytes: usize = 0;
    let read_vec = |uva: u64,
                    out: &mut alloc::vec::Vec<alloc::vec::Vec<u8>>,
                    total: &mut usize| -> bool {
        if uva == 0 || uva >= USER_VA_END { return true; }
        for i in 0..ARG_MAX_ENTRIES {
            let p = uva + (i as u64) * 8;
            if p >= USER_VA_END { return false; }
            // SAFETY: 8-byte aligned argv/envp entry per Linux ABI; bounded ARG_MAX_ENTRIES; EL1 read through caller's TTBR0 pre-activate.
            let s = unsafe { core::ptr::read_volatile(p as *const u64) };
            if s == 0 { return true; }
            if s >= USER_VA_END { return false; }
            let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            for j in 0..ARG_MAX_STR {
                // SAFETY: bounded read up to ARG_MAX_STR; user pointer < USER_VA_END; pre-activate TTBR0 resolves caller's user mapping.
                let b = unsafe { core::ptr::read_volatile((s + j as u64) as *const u8) };
                if b == 0 { break; }
                buf.push(b);
                *total += 1;
                if *total > ARG_MAX_BYTES { return false; }
            }
            out.push(buf);
        }
        true
    };
    if !read_vec(args.a1, &mut argv_vec, &mut total_bytes) {
        return -(Errno::E2big.as_i32() as i64);
    }
    if !read_vec(args.a2, &mut envp_vec, &mut total_bytes) {
        return -(Errno::E2big.as_i32() as i64);
    }

    // Shebang resolution per Linux fs/binfmt_script.c. Mirrors the
    // x86 path above; on success blob_vec/path_owned/argv_vec are
    // updated to the resolved interpreter chain.
    if blob_vec.starts_with(b"#!") {
        if let Err(e) = resolve_shebang_chain(
            &mut blob_vec, &mut path_owned, &mut argv_vec,
        ) {
            return -(e.as_i32() as i64);
        }
    }
    // Borrow the owned Vec for `load_static_blob` — no Box::leak.
    // The Vec drops at end of fn after place_image has copied the
    // segment bytes into AS-owned `staged_bytes` per B22.
    let blob: &[u8] = &blob_vec;
    let argc = argv_vec.len();
    let envc = envp_vec.len();

    // 2. Allocate new PT root + build the post-execve AS.
    // SAFETY: master L0 captured at pmm::user_as::init; PMM up; new_user_l0 returns a fresh frame zeroed and populated with the kernel half.
    let new_root = match unsafe { hal_aarch64::mmu_ops::new_user_l0() } {
        Some(r) => r,
        None    => return -(Errno::Enomem.as_i32() as i64),
    };
    let new_as = match AddressSpace::new(new_root) {
        Ok(a)  => a,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };
    pmm::user_as::install_teardown(&new_as);
    let img = match elf_load::load_static_blob(blob, &new_as) {
        Ok(i)  => i,
        Err(_) => return -(Errno::Enoexec.as_i32() as i64),
    };
    // 64 KiB stack — busybox + glibc/musl static binaries (Go later)
    // F230: real Linux layout (matches x86_64 path above). Stack
    // reservation = RLIMIT_STACK (8 MiB default), allocated up-front
    // per Linux's setup_arg_pages(); mmap_base = stack_bottom -
    // MMAP_BASE_GAP per arch_pick_mmap_base.
    let rlim_stack: u64 = {
        // SAFETY: rlimits slot single-mutator per `13§5`; cur is the
        // running task on this CPU; we only read, no concurrent writer.
        let (rc, _) = unsafe { (*cur.rlimits.get())[sched::rlimit::rlim::STACK] };
        ((rc + 0xfff) & !0xfff).min(0x4000_0000)
    };
    let stack_top: u64 = hal::USER_VA_END - 0x10000;
    let exec_user_stack_va:  u64   = stack_top - rlim_stack;
    let exec_user_stack_top: u64   = stack_top;
    let exec_user_stack_len: usize = rlim_stack as usize;
    let stack_hint = UserVirtAddr::new(exec_user_stack_va)
        .expect("exec_user_stack_va in user range");
    if new_as.mmap(
        Some(stack_hint), exec_user_stack_len,
        VmaProt::READ | VmaProt::WRITE,
        vmm::EXEC_STACK_VMA_FLAGS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    new_as.set_mmap_base(exec_user_stack_va.saturating_sub(vmm::MMAP_BASE_GAP));

    // 3. Replace cur.mm + activate the new AS.
    // SAFETY: new_root carries kernel-half cloned from master at new_user_l0; activate writes TTBR0_EL1 + flushes user TLB; preempt-off; single-CPU.
    unsafe { <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::activate(new_root); }
    // SAFETY: we are the running task; preempt-off; UP single-CPU so no concurrent reader of cur.mm.
    unsafe { cur.replace_mm(Some(new_as)); }

    // P3-61: drop FD_CLOEXEC fds before the new program runs.
    // SAFETY: same single-mutator invariant on fd_table as mm.
    if let Some(fdt) = unsafe { cur.fd_table_ref() } {
        fdt.close_on_exec();
    }
    reset_caught_signals(&cur);
    reset_per_execve_state(&cur);
    // F156: clear CLONE_VFORK rendezvous so the parent (suspended in
    // sys_clone) returns. Linux fires `mm_struct::vfork_done` at
    // exec time so the parent stops sharing the now-replaced mm.
    cur.vfork_pending.store(false, core::sync::atomic::Ordering::Release);

    // F152-2: Linux execve resets TPIDR_EL0 = 0; user crt1 calls
    // PR_SET_TLS / writes TPIDR_EL0 directly (EL0-writable on
    // aarch64) once musl's __init_tls picks a TCB VA. The previous
    // code mmap'd a fixed TLS region at 0x600000 + set TPIDR_EL0 to
    // 0x601000 — a hack to support the now-deleted oxide_start.h
    // shim. Real-musl-crt1 binaries (everything post-F152-1) install
    // their own TCB.
    // SAFETY: msr tpidr_el0 at EL1 is always legal; user crt1
    // overwrites with the real TCB.
    unsafe {
        core::arch::asm!(
            "msr tpidr_el0, xzr",
            options(nomem, nostack, preserves_flags),
        );
    }

    // 4. Build the SysV initial stack.
    let random16 = {
        let ns = <hal_aarch64::ArmTimerOps as TimerOps>::monotonic_ns().0;
        let mut r = [0u8; 16];
        for i in 0..16 { r[i] = (ns >> ((i % 8) * 8)) as u8 ^ (i as u8 * 0x9b); }
        r
    };
    let argv_slices: alloc::vec::Vec<&[u8]> = argv_vec.iter().map(|v| v.as_slice()).collect();
    let envp_slices: alloc::vec::Vec<&[u8]> = envp_vec.iter().map(|v| v.as_slice()).collect();
    // SAFETY: single-mutator per `13§5` for cmdline + environ + exe_path.
    let exec_path_for_caps = unsafe {
        *cur.cmdline.get() = Some(sched::argv_to_cmdline(&argv_slices[..argc]));
        *cur.environ.get() = Some(sched::argv_to_cmdline(&envp_slices[..envc]));
        let path_str = match core::str::from_utf8(&path_owned) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => alloc::string::String::new(),
        };
        if !path_str.is_empty() {
            *cur.exe_path.get() = Some(path_str.clone());
            if let Some(mm) = cur.mm_ref() {
                mm.set_exe_path(path_str.clone());
            }
            Some(path_str)
        } else { None }
    };
    if let Some(p) = exec_path_for_caps {
        if let Some(inode) = crate::devfs::lookup(&p) {
            apply_file_caps_at_execve(&inode, cur);
        }
    }
    let vdso_ehdr = crate::vdso::map_into_current().unwrap_or(0);
    // SAFETY: we activated new_root above, so user-VA writes from the kernel target the new AS; user_fault_handler will demand-fault the stack page.
    let new_sp = match unsafe {
        elf_load::stack::build_user_stack(
            exec_user_stack_top,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
            &path_owned,
            vdso_ehdr,
        )
    } {
        Some(sp) => sp,
        None     => return -(Errno::Enomem.as_i32() as i64),
    };

    // 5. Patch the saved SVC frame so the eret epilogue lands the
    //    new program at img.user_ip() with sp = new_sp. SPSR_EL1 = 0
    //    means EL0t + DAIF cleared (IRQs allowed). x0 = retval slot
    //    is loaded LAST by the asm; we leave it 0 since the new
    //    program's _start ignores x0.
    let _ = Ordering::Acquire; // silence unused import on this arch path
    // SAFETY: caller is `oxide_syscall_dispatch` running on cur's per-task kernel stack; current_svc_frame() points at the live saved tail; the SVC asm restores ELR_EL1 / SP_EL0 / x0 from these same slots after we return; preempt-off, single-CPU UP.
    let frame = unsafe { &mut *hal_aarch64::current_svc_frame() };
    frame.elr_el1  = img.user_ip();
    frame.sp_el0   = new_sp;
    frame.spsr_el1 = 0;          // EL0t, DAIF=0 (IRQs unmasked at EL0)
    frame.retval   = 0;

    debug_sched! {
        klog::write_raw(b"[INFO]  sys_execve(arm): argc=");
        klog::write_dec_u64(argc as u64);
        klog::write_raw(b" envc=");
        klog::write_dec_u64(envc as u64);
        klog::write_raw(b" entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" sp=");
        klog::write_hex_u64(new_sp);
        klog::write_raw(b" new_root=");
        klog::write_hex_u64(new_root);
        klog::write_raw(b"\n");
    }

    0
}

/// Decode the `security.capability` xattr on `inode` (Linux's
/// `struct vfs_cap_data` v2/v3 layout) and apply file capabilities
/// to `task.creds` per `capabilities(7)` semantics.
///
/// Layout (`linux/capability.h`):
///   magic_etc:  u32 (low 24 bits version, top 8 = flags;
///                    VFS_CAP_FLAGS_EFFECTIVE = 0x01)
///   permitted:  [u32; 2]
///   inheritable: [u32; 2]
///   v3 adds rootid: u32 at the tail (24 bytes total). v2 = 20 bytes.
///
/// Effect on the task post-execve (simplified Linux rule):
///   new_perm  = (file.perm  | (cap_inheritable & file.inh)) & cap_bounding
///   new_eff   = if VFS_CAP_FLAGS_EFFECTIVE then new_perm else 0
///   inh stays unchanged.
/// # C: O(1)
fn apply_file_caps_at_execve(inode: &vfs::InodeRef, cur: &sched::Task) {
    use core::sync::atomic::Ordering;
    const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x01;
    // First probe the value length via getxattr-len (buf=0).
    let s = "security.capability";
    let want = ::fs::xattr::query_len(inode, s);
    if want < 12 { return; }
    let mut buf = alloc::vec![0u8; want.min(24)];
    if !::fs::xattr::query_into(inode, s, &mut buf) { return; }
    if buf.len() < 12 { return; }
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
    };
    let magic_etc = read_u32(0);
    let perm = ((read_u32(4) as u64) | ((read_u32(8) as u64) << 32)) & ((1u64 << 40) - 1);
    let inh  = if buf.len() >= 20 {
        ((read_u32(12) as u64) | ((read_u32(16) as u64) << 32)) & ((1u64 << 40) - 1)
    } else { 0 };
    let task_inh = cur.creds.cap_inheritable.load(Ordering::Acquire);
    let bounding = cur.creds.cap_bounding.load(Ordering::Acquire);
    let new_perm = (perm | (task_inh & inh)) & bounding;
    let new_eff  = if magic_etc & VFS_CAP_FLAGS_EFFECTIVE != 0 { new_perm } else { 0 };
    cur.creds.cap_permitted.store(new_perm, Ordering::Release);
    cur.creds.cap_effective.store(new_eff,  Ordering::Release);
}

/// Resolve a `#!`-script chain per Linux `fs/binfmt_script.c`.
///
/// On entry:
///   * `blob_owned` holds the file content the user asked execve to load
///   * `path_owned` holds the path the user named
///   * `argv_vec` holds the original argv (argv[0] is the user's choice)
///
/// On every iteration where `blob_owned` begins with `#!`:
///   1. Parse `#!<interp>[ <opt-arg>]\n` from the first line (max 128 bytes).
///   2. Splice argv: new argv = [interp, opt-arg?, original_path] ++ argv[1..].
///      argv[0] of the original program is dropped, exactly as Linux does.
///   3. Update `path_owned` to `interp`, re-read it from ext4 into
///      `blob_owned`, and loop. Bail with ENOENT if interp missing.
///
/// Recursion cap = 4 (matches Linux `BINPRM_MAX_RECURSION`).
/// Returns `Ok(())` when the chain terminates on a non-script blob.
/// # C: O(N_chain × file_size)
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn resolve_shebang_chain(
    blob_owned: &mut alloc::vec::Vec<u8>,
    path_owned: &mut alloc::vec::Vec<u8>,
    argv_vec: &mut alloc::vec::Vec<alloc::vec::Vec<u8>>,
) -> Result<(), Errno> {
    for _ in 0..4 {
        if blob_owned.len() < 2 || &blob_owned[..2] != b"#!" {
            return Ok(());
        }
        let head_end = blob_owned.iter().take(128).position(|&b| b == b'\n')
            .unwrap_or_else(|| blob_owned.len().min(128));
        let line = &blob_owned[2..head_end];
        let mut i = 0usize;
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') { i += 1; }
        let interp_start = i;
        while i < line.len() && line[i] != b' ' && line[i] != b'\t' { i += 1; }
        let interp_end = i;
        if interp_end == interp_start { return Err(Errno::Enoexec); }
        let interp: alloc::vec::Vec<u8> = line[interp_start..interp_end].to_vec();
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') { i += 1; }
        let mut j = line.len();
        while j > i && (line[j-1] == b' ' || line[j-1] == b'\t' || line[j-1] == b'\r') { j -= 1; }
        let opt_arg: Option<alloc::vec::Vec<u8>> =
            if j > i { Some(line[i..j].to_vec()) } else { None };
        let cur_path: alloc::vec::Vec<u8> = path_owned.clone();
        // Splice argv per Linux: drop original argv[0] (if any), prepend
        // [interp, opt-arg?, original_path] in front of argv[1..].
        let original_tail: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            if argv_vec.is_empty() {
                alloc::vec::Vec::new()
            } else {
                argv_vec.drain(..).skip(1).collect()
            };
        argv_vec.push(interp.clone());
        if let Some(a) = opt_arg { argv_vec.push(a); }
        argv_vec.push(cur_path);
        argv_vec.extend(original_tail);
        // Update path → interp, refresh blob from ext4.
        *path_owned = interp.clone();
        match crate::syscalls::pathresolve::read_exec(&interp)
            .or_else(|| ext4::rootfs::read_file(&interp)) {
            Some(v) => *blob_owned = v,
            None    => return Err(Errno::Enoent),
        }
    }
    // Recursion cap exceeded: Linux returns ELOOP; we lack ELOOP in
    // our errno table so map to ENOEXEC (closest valid v1 code).
    Err(Errno::Enoexec)
}
