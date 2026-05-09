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
    // Owned ext4 read storage; rooted in this fn frame so the blob's
    // lifetime extends across `load_static_blob` and drops at fn end
    // — no per-exec Box::leak (replaces the prior `Box::leak` pattern;
    // B22 made `load_static_blob` accept a non-'static slice).
    let mut ext4_blob: Option<alloc::vec::Vec<u8>> = None;
    // F62: hoist path_buf/path_len so we can record the exec path
    // for /proc/self/exe even when path_ptr != 0.
    let mut path_buf = [0u8; 64];
    let mut path_len = 0usize;
    let blob: &[u8] = if path_ptr == 0 {
        crate::elf_smoke::EXEC_BLOB
    } else {
        if path_ptr >= USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        for i in 0..64 {
            // SAFETY: bounded read up to 64 bytes from a user pointer < USER_VA_END; CPL=0 reads through user mapping pre-activate.
            let b = unsafe { core::ptr::read_volatile((path_ptr + i) as *const u8) };
            if b == 0 { break; }
            path_buf[i as usize] = b;
            path_len = (i + 1) as usize;
        }
        let path = &path_buf[..path_len];
        // Read from ext4 directly into an owned Vec — no per-exec
        // Box::leak (B23-followup: the blob only lives for the
        // duration of `load_static_blob`; segment bytes get copied
        // into AS-owned staging via `stash_bytes` per B22).
        if let Some(v) = crate::dev_ext4::read_file(path) {
            ext4_blob = Some(v);
            // SAFETY: ext4_blob is rooted in this stack frame and
            // outlives the load_static_blob call below.
            ext4_blob.as_deref().expect("just set")
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
    let argc = argv_vec.len();
    let envc = envp_vec.len();

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
    crate::user_as::install_teardown(&new_as);
    let img = match crate::elf_load::load_static_blob(blob, &new_as) {
        Ok(i)  => i,
        Err(_) => return -(Errno::Enoexec.as_i32() as i64),
    };
    // 64 KiB stack — busybox + glibc/musl static binaries routinely
    // use >4 KiB through SIGCHLD handlers, /proc parsers, and stdio
    // init. A single 4 KiB page underflows on the first wide musl
    // libc init frame. Matches the aarch64 execve path below.
    const EXEC_USER_STACK_LEN: usize = 0x10000;
    // F152-3: stack near the top of the user-half VA range, Linux-style.
    // The previous fixed VA of 0x4F1_000 collided with the text
    // segment of any ELF whose .text extended past 0xF1000 bytes —
    // busybox-ash's text PT_LOAD ends at 0x50e000, so its 0x500012
    // function pointer landed in the stack VMA (R+W, NX) and faulted
    // on the first call into that page. Place stack at
    // USER_VA_END - 0x20000 so the [start, end) range stays
    // strictly below USER_VA_END (`UserVirtAddr::new` rejects ==).
    const EXEC_USER_STACK_VA:  u64   = hal::USER_VA_END - 0x20000;
    const EXEC_USER_STACK_TOP: u64   = EXEC_USER_STACK_VA + EXEC_USER_STACK_LEN as u64;
    let stack_hint = UserVirtAddr::new(EXEC_USER_STACK_VA)
        .expect("EXEC_USER_STACK_VA in user range");
    if new_as.mmap(
        Some(stack_hint), EXEC_USER_STACK_LEN,
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
        let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
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
    // SAFETY: we activated new_root above, so user-VA writes from the kernel target the new AS; user_fault_handler will demand-fault the stack page.
    let new_sp = match unsafe {
        crate::exec_stack::build_user_stack(
            EXEC_USER_STACK_TOP,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
            &path_buf[..path_len],
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
    // Borrow the owned Vec for `load_static_blob` — no Box::leak.
    // The Vec drops at end of fn after place_image has copied the
    // segment bytes into AS-owned `staged_bytes` per B22.
    let blob: &[u8] = &blob_vec;

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
    let argc = argv_vec.len();
    let envc = envp_vec.len();

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
    crate::user_as::install_teardown(&new_as);
    let img = match crate::elf_load::load_static_blob(blob, &new_as) {
        Ok(i)  => i,
        Err(_) => return -(Errno::Enoexec.as_i32() as i64),
    };
    // 64 KiB stack — busybox + glibc/musl static binaries (Go later)
    // routinely use >4 KiB, especially through SIGCHLD handlers and
    // /proc parsers. A single 4 KiB page overflows on the first
    // wide stack frame (e.g. busybox sh's parser locals); 64 KiB is
    // the same shape Linux's sysctl-default rlim_cur hands out for
    // small static binaries.
    const EXEC_USER_STACK_LEN:  usize = 0x10000;
    const EXEC_USER_STACK_VA:   u64   = 0x4F1_000;
    const EXEC_USER_STACK_TOP:  u64   = EXEC_USER_STACK_VA + EXEC_USER_STACK_LEN as u64;
    let stack_hint = UserVirtAddr::new(EXEC_USER_STACK_VA)
        .expect("EXEC_USER_STACK_VA in user range");
    if new_as.mmap(
        Some(stack_hint), EXEC_USER_STACK_LEN,
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
        let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
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
    if let Some(p) = exec_path_for_caps {
        if let Some(inode) = crate::devfs::lookup(&p) {
            apply_file_caps_at_execve(&inode, cur);
        }
    }
    // SAFETY: we activated new_root above, so user-VA writes from the kernel target the new AS; user_fault_handler will demand-fault the stack page.
    let new_sp = match unsafe {
        crate::exec_stack::build_user_stack(
            EXEC_USER_STACK_TOP,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
            &path_buf[..path_len],
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
    let want = crate::xattr_overlay::query_len(inode, s);
    if want < 12 { return; }
    let mut buf = alloc::vec![0u8; want.min(24)];
    if !crate::xattr_overlay::query_into(inode, s, &mut buf) { return; }
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
