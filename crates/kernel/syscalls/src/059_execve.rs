// sys_execve (NR_EXECVE=59) per docs/53§0 — per-syscall-file module.
// Both arch-cfg'd variants of sys_execve + execve_inner live here;
// shared helpers (signal reset, path read, file caps, shebang)
// live in execve_common.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::{USER_VA_END, TimerOps};

use crate::execve_common::{
    apply_file_caps_at_execve, regain_root_caps_at_execve, read_user_exec_path,
    reset_caught_signals, reset_per_execve_state, resolve_shebang_chain,
};

fn unshare_fd_table_and_close_on_exec(cur: &sched::Task) {
    let shared = unsafe {
        cur.fd_table_ref()
            .map(|fdt| alloc::sync::Arc::strong_count(fdt) > 1)
            .unwrap_or(false)
    };
    if shared {
        let new_fdt = unsafe {
            cur.fd_table_ref()
                .map(|fdt| alloc::sync::Arc::new(fdt.fork_clone()))
        };
        if let Some(fdt) = new_fdt {
            // SAFETY: execve is the sole fd-table mutator for this task.
            unsafe { cur.replace_fd_table(Some(fdt)); }
        }
    }
    // SAFETY: execve is the sole fd-table mutator for this task.
    if let Some(fdt) = unsafe { cur.fd_table_ref() } {
        fdt.close_on_exec();
    }
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
pub(crate) fn execve_inner(args: &SyscallArgs, path_owned: alloc::vec::Vec<u8>) -> i64 {
    use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};
    use hal::UserVirtAddr;

    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    // Owned ext4 read storage; rooted in this fn frame so the blob's
    // lifetime extends across `load_static_blob` and drops at fn end.
    let mut ext4_blob: Option<alloc::vec::Vec<u8>> = None;
    if path_owned.is_empty() {
        return -(Errno::Enoent.as_i32() as i64);
    }
    let v = match crate::pathresolve::read_exec(&path_owned)
        .or_else(|| ext4::rootfs::read_file(&path_owned)) {
        Some(v) => v,
        None    => {
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(b"[execve ENOENT] path=");
                klog::write_raw(&path_owned);
                klog::write_raw(b"\n");
            }
            return -(Errno::Enoent.as_i32() as i64);
        }
    };
    ext4_blob = Some(v);
    // SAFETY: ext4_blob just-set; outlives the load_static_blob call below.
    let mut blob: &[u8] = ext4_blob.as_deref().expect("just set");

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

    // B288 diagnostic: dump LISTEN_FDS / LISTEN_FDNAMES (socket-activation
    // fd handoff) for the failing early services so the n_fds vs n_names
    // mismatch behind udevd's "Failed to listen on fds: EINVAL" is visible.
    #[cfg(feature = "debug-boot")]
    {
        let is_target = path_owned.windows(5).any(|w| w == b"udevd")
            || path_owned.windows(8).any(|w| w == b"journald");
        if is_target {
            for e in &envp_vec {
                if e.starts_with(b"LISTEN_") {
                    klog::write_raw(b"[B288 env ");
                    klog::write_raw(&path_owned);
                    klog::write_raw(b"] ");
                    klog::write_raw(e);
                    klog::write_raw(b"\n");
                }
            }
        }
    }

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
    // 64 KiB stack — glibc/musl static binaries routinely
    // use >4 KiB through SIGCHLD handlers, /proc parsers, and stdio
    // init. A single 4 KiB page underflows on the first wide musl
    // F230: real Linux layout. The stack reservation is RLIMIT_STACK
    // (default 8 MiB per `sched::rlimit::DEFAULT_RLIMITS`) at the
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
    // EXEC_USER_STACK_* by name) unchanged.
    let EXEC_USER_STACK_VA  = exec_user_stack_va_u;
    let EXEC_USER_STACK_TOP = exec_user_stack_top_u;
    let EXEC_USER_STACK_LEN = exec_user_stack_len_u;
    let stack_hint = UserVirtAddr::new(EXEC_USER_STACK_VA)
        .expect("EXEC_USER_STACK_VA in user range");
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
        Some(stack_hint), EXEC_USER_STACK_LEN,
        VmaProt::READ | VmaProt::WRITE,
        vmm::EXEC_STACK_VMA_FLAGS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    // Linux `arch_pick_mmap_base`: anon-mmap arena top sits
    // MMAP_BASE_GAP (128 MiB) below the stack reservation bottom.
    new_as.set_mmap_base(EXEC_USER_STACK_VA.saturating_sub(vmm::MMAP_BASE_GAP));

    // 3. Replace `current.mm` with the new AS and activate it.
    //    Order: activate BEFORE replace_mm so CR3 doesn't dangle
    //    if drop runs concurrently — but on UP single-CPU the
    //    order is purely defensive.
    use hal::MmuOps;
    // mm_cpumask (Linux): execve swaps the mm on the running CPU via a
    // DIRECT activate (bypassing the scheduler), so it must do its own
    // set/clear. Mark THIS CPU on the new AS BEFORE the CR3 reload so a peer
    // shootdown can't skip us; clear the OLD mm's bit AFTER the reload (which
    // flushed our old user TLB) and before replace_mm drops it.
    let me = { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) };
    new_as.mark_cpu(me);
    // SAFETY: new_root carries kernel-half cloned from master per P2-19; activate writes CR3 + flushes user TLB; preempt-off; single-CPU.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(new_root); }
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent execve writer; reading the still-current old mm before replace.
    if let Some(old) = unsafe { cur.mm_ref() } { old.clear_cpu(me); }
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

    // P3-61: Linux execve unshares CLONE_FILES, then drops FD_CLOEXEC fds.
    unshare_fd_table_and_close_on_exec(&cur);
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
    // Cap transition: root regains the full set on exec (unconditional —
    // Linux applies this even with no file-caps; the pathresolve below reads
    // file-cap xattrs from the resolved inode, devfs node or ext4 binary).
    regain_root_caps_at_execve(cur);
    // F103: file capabilities — apply security.capability xattr from the
    // exec path's inode to the calling task's cap_permitted / cap_effective.
    if let Some(p) = exec_path_for_caps {
        if let Some(inode) = crate::pathresolve::resolve(&p, true) {
            apply_file_caps_at_execve(&inode, cur);
            // FAN_OPEN_EXEC notification (Linux fsnotify_open with FMODE_EXEC).
            ::fs::inotify::fire_open_exec(&inode);
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
            EXEC_USER_STACK_TOP,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
            &path_owned,
            vdso_ehdr,
            <hal_x86_64::X86CpuOps as hal::CpuOps>::cpu_hwcap(),
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
    // Linux ABI (`fs/binfmt_elf.c` start_thread / ELF_PLAT_INIT): every GP
    // register is 0 at process entry except RSP. Our syscall epilogue restores
    // rax/rdi/rsi/rdx/r10/r8/r9 from the saved frame (the 7 slots immediately
    // below this RIP/RFLAGS/RSP triple) — left un-zeroed, the new program (and
    // ld.so) inherit stale register garbage. RDX especially is the
    // `rtld_fini`/atexit pointer glibc's _start forwards to __libc_start_main
    // and registers via __cxa_atexit — a garbage value there poisons the
    // exit-handler list (the same .bss the boot wedge corrupts).
    // SAFETY: current_user_frame() points at base+0x38 (RIP); base+0x00..0x30
    // are the 7 GP-arg slots the epilogue pops. Same per-task syscall stack,
    // single mutator, IRQs/preempt-off in the syscall body.
    unsafe {
        let base = (frame as *mut [u64; 3] as *mut u64).sub(7);
        for i in 0..7 { core::ptr::write_volatile(base.add(i), 0); }
    }

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
/// # C: O(argv+envp+ELF segments)
pub(crate) fn execve_inner(args: &SyscallArgs, mut path_owned: alloc::vec::Vec<u8>) -> i64 {
    use core::sync::atomic::Ordering;
    use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};
    use hal::{MmuOps, UserVirtAddr};

    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    let mut blob_vec = match crate::pathresolve::read_exec(&path_owned)
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
    // 64 KiB stack — glibc/musl static binaries (Go later)
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
    let EXEC_USER_STACK_VA:  u64   = stack_top - rlim_stack;
    let EXEC_USER_STACK_TOP: u64   = stack_top;
    let EXEC_USER_STACK_LEN: usize = rlim_stack as usize;
    let stack_hint = UserVirtAddr::new(EXEC_USER_STACK_VA)
        .expect("EXEC_USER_STACK_VA in user range");
    if new_as.mmap(
        Some(stack_hint), EXEC_USER_STACK_LEN,
        VmaProt::READ | VmaProt::WRITE,
        vmm::EXEC_STACK_VMA_FLAGS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    new_as.set_mmap_base(EXEC_USER_STACK_VA.saturating_sub(vmm::MMAP_BASE_GAP));

    // 3. Replace cur.mm + activate the new AS.
    // mm_cpumask (Linux): execve's direct activate bypasses the scheduler, so
    // it sets/clears the cpumask itself. Mark THIS CPU on the new AS before
    // the TTBR0 reload; clear the old mm's bit after it (TLB flushed) and
    // before replace_mm drops it.
    let me = { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) };
    new_as.mark_cpu(me);
    // SAFETY: new_root carries kernel-half cloned from master at new_user_l0; activate writes TTBR0_EL1 + flushes user TLB; preempt-off; single-CPU.
    unsafe { <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::activate(new_root); }
    // SAFETY: running task on this CPU; preempt-off; no concurrent execve writer; reading the still-current old mm before replace.
    if let Some(old) = unsafe { cur.mm_ref() } { old.clear_cpu(me); }
    // SAFETY: we are the running task; preempt-off; UP single-CPU so no concurrent reader of cur.mm.
    unsafe { cur.replace_mm(Some(new_as)); }

    // P3-61: Linux execve unshares CLONE_FILES, then drops FD_CLOEXEC fds.
    unshare_fd_table_and_close_on_exec(&cur);
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
    regain_root_caps_at_execve(cur);
    if let Some(p) = exec_path_for_caps {
        if let Some(inode) = crate::pathresolve::resolve(&p, true) {
            apply_file_caps_at_execve(&inode, cur);
            // FAN_OPEN_EXEC notification (Linux fsnotify_open with FMODE_EXEC).
            ::fs::inotify::fire_open_exec(&inode);
        }
    }
    let vdso_ehdr = crate::vdso::map_into_current().unwrap_or(0);
    // SAFETY: we activated new_root above, so user-VA writes from the kernel target the new AS; user_fault_handler will demand-fault the stack page.
    let new_sp = match unsafe {
        elf_load::stack::build_user_stack(
            EXEC_USER_STACK_TOP,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
            &path_owned,
            vdso_ehdr,
            <hal_aarch64::ArmCpuOps as hal::CpuOps>::cpu_hwcap(),
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
