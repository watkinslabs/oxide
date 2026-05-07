// sys_execve split out of syscall_glue.rs to keep it under the
// 1000-line cap (docs/08§7). The dispatch in syscall_glue.rs
// forwards NR_EXECVE here.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::{USER_VA_END, TimerOps};

/// `sys_execve(path, argv, envp)` per `15§5` / `31§4`.
/// # SAFETY: dispatch ctx, IRQs masked.
/// # C: O(phdrs) + O(N_vmas) + O(1)
#[cfg(target_arch = "x86_64")]
pub fn kernel_sys_execve(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};
    use hal::UserVirtAddr;

    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };

    // Read the first byte of the path argument as a kernel-static
    // ELF selector (v1 stand-in for VFS path lookup per docs/16).
    // `path = NULL` falls back to the default blob — preserves the
    // P2-21 legacy behavior. CPL=0 reads through user pages
    // directly per `15§3` (kernel can read user memory while
    // running on its kernel stack with CR3 = user AS).
    let path_ptr = args.a0;
    let blob = if path_ptr == 0 {
        crate::elf_smoke::EXEC_BLOB
    } else {
        if path_ptr >= USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        // Read up to 64 bytes of the user path, NUL-terminated.
        let mut path_buf = [0u8; 64];
        let mut path_len = 0;
        for i in 0..64 {
            // SAFETY: bounded read up to 64 bytes from a user pointer < USER_VA_END; CPL=0 reads through user mapping pre-activate.
            let b = unsafe { core::ptr::read_volatile((path_ptr + i) as *const u8) };
            if b == 0 { break; }
            path_buf[i as usize] = b;
            path_len = (i + 1) as usize;
        }
        let path = &path_buf[..path_len];
        // Path-string lookup first; fall back to first-byte
        // selector form (init blob's iter_block uses non-NUL-
        // terminated single-byte selectors at known VAs).
        if let Some(b) = crate::elf_smoke::lookup_blob_by_path(path) {
            b
        } else if path_len >= 1 {
            match crate::elf_smoke::lookup_blob(path[0]) {
                Some(b) => b,
                None    => return -(Errno::Enoent.as_i32() as i64),
            }
        } else {
            return -(Errno::Enoent.as_i32() as i64);
        }
    };

    // 1a. Snapshot argv + envp from the OLD user AS into kernel
    //     storage. After we activate the new AS, the old user
    //     pages are unmapped and the user-side argv/envp pointers
    //     would resolve to nothing. v1 caps: 8 entries each, 64
    //     bytes per string.
    const MAX_VEC: usize = 8;
    const MAX_STR: usize = 64;
    let mut argv_buf = [[0u8; MAX_STR]; MAX_VEC];
    let mut argv_len = [0usize; MAX_VEC];
    let mut argc: usize = 0;
    let mut envp_buf = [[0u8; MAX_STR]; MAX_VEC];
    let mut envp_len = [0usize; MAX_VEC];
    let mut envc: usize = 0;
    if args.a1 != 0 && args.a1 < USER_VA_END {
        let argv_uva = args.a1;
        for i in 0..MAX_VEC {
            let p = argv_uva + (i as u64) * 8;
            if p >= USER_VA_END { break; }
            // SAFETY: argv array entries are 8-byte aligned per Linux ABI; we bound at MAX_VEC; CPL=0 reads through user mapping pre-activate.
            let s = unsafe { core::ptr::read_volatile(p as *const u64) };
            if s == 0 { break; }
            if s >= USER_VA_END { break; }
            for j in 0..MAX_STR {
                // SAFETY: bounded read of user string up to MAX_STR; CPL=0 reads through caller's AS.
                let b = unsafe { core::ptr::read_volatile((s + j as u64) as *const u8) };
                if b == 0 { argv_len[i] = j; break; }
                argv_buf[i][j] = b;
                argv_len[i] = j + 1;
            }
            argc += 1;
        }
    }
    if args.a2 != 0 && args.a2 < USER_VA_END {
        let envp_uva = args.a2;
        for i in 0..MAX_VEC {
            let p = envp_uva + (i as u64) * 8;
            if p >= USER_VA_END { break; }
            // SAFETY: envp array entries 8-byte aligned per Linux ABI; bounded MAX_VEC; CPL=0 reads through user mapping pre-activate.
            let s = unsafe { core::ptr::read_volatile(p as *const u64) };
            if s == 0 { break; }
            if s >= USER_VA_END { break; }
            for j in 0..MAX_STR {
                // SAFETY: bounded read of user string up to MAX_STR; CPL=0 reads through caller's AS.
                let b = unsafe { core::ptr::read_volatile((s + j as u64) as *const u8) };
                if b == 0 { envp_len[i] = j; break; }
                envp_buf[i][j] = b;
                envp_len[i] = j + 1;
            }
            envc += 1;
        }
    }

    // 1. Allocate new PT root for the post-execve AS.
    // SAFETY: master PML4 captured at user_as::init; PMM up.
    let new_root = match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
        Some(r) => r,
        None    => return -(Errno::Enomem.as_i32() as i64),
    };

    // 2. Build the new AS shell + load the ELF + register stack.
    let new_as = match AddressSpace::new(new_root) {
        Ok(a)  => a,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };
    let img = match crate::elf_load::load_static_blob(blob, &new_as) {
        Ok(i)  => i,
        Err(_) => return -(Errno::Enoexec.as_i32() as i64),
    };
    let stack_hint = UserVirtAddr::new(crate::elf_smoke::EXEC_USER_STACK_VA)
        .expect("EXEC_USER_STACK_VA in user range");
    if new_as.mmap(
        Some(stack_hint), 0x1000,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }

    // 3. Replace `current.mm` with the new AS and activate it.
    //    Order: activate BEFORE replace_mm so CR3 doesn't dangle
    //    if drop runs concurrently — but on UP single-CPU the
    //    order is purely defensive.
    use hal::MmuOps;
    // SAFETY: new_root carries kernel-half cloned from master per P2-19; activate writes CR3 + flushes user TLB; preempt-off; single-CPU.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(new_root); }
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent reader of mm on another CPU (UP v1).
    unsafe { cur.replace_mm(Some(new_as)); }

    // P3-61: drop FD_CLOEXEC fds before the new program runs.
    // SAFETY: same single-mutator invariant on fd_table as mm.
    if let Some(fdt) = unsafe { cur.fd_table_ref() } {
        fdt.close_on_exec();
    }

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
    // Materialise stack-allocated &[&[u8]] slices for the OLD-AS snapshot.
    let mut argv_slices: [&[u8]; MAX_VEC] = [b""; MAX_VEC];
    for i in 0..argc { argv_slices[i] = &argv_buf[i][..argv_len[i]]; }
    let mut envp_slices: [&[u8]; MAX_VEC] = [b""; MAX_VEC];
    for i in 0..envc { envp_slices[i] = &envp_buf[i][..envp_len[i]]; }
    // SAFETY: single-mutator per `13§5` for both cmdline + environ slots.
    unsafe {
        *cur.cmdline.get() = Some(sched::argv_to_cmdline(&argv_slices[..argc]));
        *cur.environ.get() = Some(sched::argv_to_cmdline(&envp_slices[..envc]));
    }
    // SAFETY: we activated new_root above, so user-VA writes from the kernel target the new AS; user_fault_handler will demand-fault the stack page.
    let new_sp = match unsafe {
        crate::exec_stack::build_user_stack(
            crate::elf_smoke::EXEC_USER_STACK_TOP,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
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
///   1. Path lookup goes through `dev_ext4::read_file` (the ext4 root
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
pub fn kernel_sys_execve(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};
    use hal::{MmuOps, UserVirtAddr};

    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };

    // 1. Read the path argument and look it up via dev_ext4. v1
    //    cap: 64-byte path, NUL-terminated, single absolute path.
    let path_ptr = args.a0;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mut path_buf = [0u8; 64];
    let mut path_len = 0;
    for i in 0..64 {
        // SAFETY: bounded read up to 64 bytes from a user pointer < USER_VA_END; CPL=0 reads through user mapping pre-activate (still on caller's TTBR0).
        let b = unsafe { core::ptr::read_volatile((path_ptr + i) as *const u8) };
        if b == 0 { break; }
        path_buf[i as usize] = b;
        path_len = (i + 1) as usize;
    }
    let path = &path_buf[..path_len];
    let blob_vec = match crate::dev_ext4::read_file(path) {
        Some(v) => v,
        None    => return -(Errno::Enoent.as_i32() as i64),
    };
    // Leak to 'static so the load_static_blob lifetime contract is satisfied
    // (the blob must outlive the address space). Per-execve leak is bounded
    // by the lifetime of the new program's text VMAs.
    let blob: &'static [u8] = alloc::boxed::Box::leak(blob_vec.into_boxed_slice());

    // 1a. Snapshot argv / envp from the OLD AS (still active TTBR0).
    const MAX_VEC: usize = 8;
    const MAX_STR: usize = 64;
    let mut argv_buf = [[0u8; MAX_STR]; MAX_VEC];
    let mut argv_len = [0usize; MAX_VEC];
    let mut argc: usize = 0;
    let mut envp_buf = [[0u8; MAX_STR]; MAX_VEC];
    let mut envp_len = [0usize; MAX_VEC];
    let mut envc: usize = 0;
    if args.a1 != 0 && args.a1 < USER_VA_END {
        let argv_uva = args.a1;
        for i in 0..MAX_VEC {
            let p = argv_uva + (i as u64) * 8;
            if p >= USER_VA_END { break; }
            // SAFETY: 8-byte aligned argv array entry per Linux ABI; bound at MAX_VEC; CPL=EL1 read through caller's TTBR0 pre-activate.
            let s = unsafe { core::ptr::read_volatile(p as *const u64) };
            if s == 0 || s >= USER_VA_END { break; }
            for j in 0..MAX_STR {
                // SAFETY: bounded read up to MAX_STR bytes of user string; same CR3/TTBR0 precondition as the array read above.
                let b = unsafe { core::ptr::read_volatile((s + j as u64) as *const u8) };
                if b == 0 { argv_len[i] = j; break; }
                argv_buf[i][j] = b;
                argv_len[i] = j + 1;
            }
            argc += 1;
        }
    }
    if args.a2 != 0 && args.a2 < USER_VA_END {
        let envp_uva = args.a2;
        for i in 0..MAX_VEC {
            let p = envp_uva + (i as u64) * 8;
            if p >= USER_VA_END { break; }
            // SAFETY: 8-byte aligned envp array entry; bounded MAX_VEC; same TTBR0 precondition.
            let s = unsafe { core::ptr::read_volatile(p as *const u64) };
            if s == 0 || s >= USER_VA_END { break; }
            for j in 0..MAX_STR {
                // SAFETY: bounded read up to MAX_STR bytes; pre-activate so caller's user mapping resolves.
                let b = unsafe { core::ptr::read_volatile((s + j as u64) as *const u8) };
                if b == 0 { envp_len[i] = j; break; }
                envp_buf[i][j] = b;
                envp_len[i] = j + 1;
            }
            envc += 1;
        }
    }

    // 2. Allocate new PT root + build the post-execve AS.
    // SAFETY: master L0 captured at user_as::init; PMM up; new_user_l0 returns a fresh frame zeroed and populated with the kernel half.
    let new_root = match unsafe { hal_aarch64::mmu_ops::new_user_l0() } {
        Some(r) => r,
        None    => return -(Errno::Enomem.as_i32() as i64),
    };
    let new_as = match AddressSpace::new(new_root) {
        Ok(a)  => a,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };
    let img = match crate::elf_load::load_static_blob(blob, &new_as) {
        Ok(i)  => i,
        Err(_) => return -(Errno::Enoexec.as_i32() as i64),
    };
    const EXEC_USER_STACK_VA:  u64 = 0x501_000;
    const EXEC_USER_STACK_TOP: u64 = EXEC_USER_STACK_VA + 0x1000;
    const USER_TLS_BASE: u64       = 0x600_000;
    const USER_TLS_LEN:  usize     = 0x2000;
    const USER_TPIDR_VA: u64       = USER_TLS_BASE + 0x1000;
    let stack_hint = UserVirtAddr::new(EXEC_USER_STACK_VA)
        .expect("EXEC_USER_STACK_VA in user range");
    if new_as.mmap(
        Some(stack_hint), 0x1000,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    // TLS scratch — same layout as elf_smoke_arm spawn_init so musl's
    // pthread_self() lookups resolve in the new AS too.
    let tls_hint = UserVirtAddr::new(USER_TLS_BASE)
        .expect("USER_TLS_BASE in user range");
    if new_as.mmap(
        Some(tls_hint), USER_TLS_LEN,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }

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

    // Update TPIDR_EL0 for the new program's TLS scratch.
    // SAFETY: msr tpidr_el0 at EL1 is always legal; eret carries the value into EL0; USER_TPIDR_VA points into the freshly mmap'd TLS region of `new_as` (active TTBR0).
    unsafe {
        core::arch::asm!(
            "msr tpidr_el0, {v}",
            v = in(reg) USER_TPIDR_VA,
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
    let mut argv_slices: [&[u8]; MAX_VEC] = [b""; MAX_VEC];
    for i in 0..argc { argv_slices[i] = &argv_buf[i][..argv_len[i]]; }
    let mut envp_slices: [&[u8]; MAX_VEC] = [b""; MAX_VEC];
    for i in 0..envc { envp_slices[i] = &envp_buf[i][..envp_len[i]]; }
    // SAFETY: single-mutator per `13§5` for both cmdline + environ slots.
    unsafe {
        *cur.cmdline.get() = Some(sched::argv_to_cmdline(&argv_slices[..argc]));
        *cur.environ.get() = Some(sched::argv_to_cmdline(&envp_slices[..envc]));
    }
    // SAFETY: we activated new_root above, so user-VA writes from the kernel target the new AS; user_fault_handler will demand-fault the stack page.
    let new_sp = match unsafe {
        crate::exec_stack::build_user_stack(
            EXEC_USER_STACK_TOP,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
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
