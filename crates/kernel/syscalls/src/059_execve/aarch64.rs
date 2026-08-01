#![cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]

use hal::USER_VA_END;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::execve_common::{
    open_exec_image, read_user_exec_path, reset_caught_signals, reset_per_execve_state,
    resolve_shebang_chain,
};

use super::fd_table::unshare_fd_table_and_close_on_exec;

/// aarch64 sys_execve — mirror of the x86 path.
/// # SAFETY: dispatch ctx, IRQs masked.
/// # C: O(phdrs) + O(N_vmas) + O(1)
pub fn sys_execve(args: &SyscallArgs) -> i64 {
    let path_owned = match read_user_exec_path(args.a0) {
        Ok(v) => v,
        Err(rc) => return rc,
    };
    #[cfg(feature = "debug-swap")]
    trace_swap_exec(&path_owned);
    if path_owned.is_empty() { return -(Errno::Efault.as_i32() as i64); }
    execve_inner(args, path_owned)
}

/// Retained, feature-gated trace for the userspace half of swap activation.
/// # C: O(path length)
#[cfg(feature = "debug-swap")]
fn trace_swap_exec(path: &[u8]) {
    if matches!(path, b"/sbin/swapon" | b"/usr/sbin/swapon" | b"/usr/bin/swapon") {
        klog::write_raw(b"[SWAPON] exec ");
        klog::write_raw(path);
        klog::write_raw(b"\n");
    }
}

/// Retained feature-gated marker after AArch64 exec has installed sshd's path.
/// # C: O(1)
#[cfg(feature = "debug-sshd")]
fn trace_sshd_exec_success(tid: u32, path: &[u8]) {
    if path != b"/usr/sbin/sshd" { return; }
    klog::write_raw(b"[SSHD-EXEC] tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" path=/usr/sbin/sshd\n");
}

/// aarch64 execve body. See x86_64 doc for the contract.
/// # C: O(argv+envp+ELF segments)
pub fn execve_inner(args: &SyscallArgs, mut path_owned: alloc::vec::Vec<u8>) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::{MmuOps, UserVirtAddr};
    use vmm::{AddressSpace, VmaBacking, VmaProt};

    let cur = match sched::live::current() {
        Some(c) => c,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    // Linux runs this before `alloc_bprm`, so a refused exec touches nothing.
    if let Some(rc) = crate::execve_common::nproc_admits(&cur) { return rc; }
    // Linux `do_open_execat`: the MAY_EXEC / noexec / file-type gate runs HERE,
    // before anything is committed, and `exec_vp` carries the very inode+mount
    // it ran against into the credential transition below.
    let (mut blob_vec, mut exec_vp) = match open_exec_image(&path_owned) {
        Ok(v) => v,
        Err(rc) => return rc,
    };
    const ARG_MAX_BYTES: usize = 128 * 1024;
    const ARG_MAX_ENTRIES: usize = 1024;
    const ARG_MAX_STR: usize = 4096;
    let mut argv_vec: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    let mut envp_vec: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    let mut total_bytes: usize = 0;
    let read_vec = |uva: u64, out: &mut alloc::vec::Vec<alloc::vec::Vec<u8>>, total: &mut usize| -> bool {
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
    if !read_vec(args.a1, &mut argv_vec, &mut total_bytes) { return -(Errno::E2big.as_i32() as i64); }
    if !read_vec(args.a2, &mut envp_vec, &mut total_bytes) { return -(Errno::E2big.as_i32() as i64); }
    #[cfg(feature = "debug-desktop")]
    if path_owned.windows(b"gnome-shell".len()).any(|part| part == b"gnome-shell") {
        for entry in &envp_vec {
            if entry.starts_with(b"CLUTTER_DEBUG=") || entry.starts_with(b"MUTTER_DEBUG=") {
                klog::write_raw(b"[GNOME_EXEC_ENV ");
                klog::write_raw(entry);
                klog::write_raw(b"]\n");
            }
        }
    }
    if blob_vec.starts_with(b"#!") {
        if let Err(rc) = resolve_shebang_chain(&mut blob_vec, &mut path_owned, &mut argv_vec, &mut exec_vp) {
            return rc;
        }
    }
    // Linux `bprm_creds_from_file` — computed on the FINAL image (the
    // interpreter for a `#!` chain, which is why a setuid script confers
    // nothing) and BEFORE the point of no return, so EPERM is still returnable.
    let creds = match crate::exec_transition::decide(cur, exec_vp.as_ref()) {
        Ok(t) => t,
        Err(e) => return -(e.as_i32() as i64),
    };
    let blob: &[u8] = &blob_vec;
    let argc = argv_vec.len();
    let envc = envp_vec.len();
    if ::fs::inotify::perm_marks_present() {
        if let Ok(p) = core::str::from_utf8(&path_owned) {
            if let Ok(vp) = crate::pathresolve::resolve_path_raw(p, true) {
                let inode = vp.inode;
                if let Err(e) = ::fs::inotify::check_open_exec_perm(&inode) {
                    return -(e.as_i32() as i64);
                }
            }
        }
    }
    // SAFETY: exec is the sole writer of this task's mm slot. Pin the old mm
    // so MDWE inheritance is applied before any new stack/ELF VMA is created.
    let old_as = unsafe { cur.mm_ref() }.cloned();
    // SAFETY: the architecture allocator returns a new inactive user root
    // whose TTBR0 hierarchy is ready for the new process mappings.
    let new_root = match unsafe { hal_aarch64::mmu_ops::new_user_l0() } {
        Some(r) => r,
        None => return -(Errno::Enomem.as_i32() as i64),
    };
    let new_as = match old_as.as_ref() {
        Some(parent) => AddressSpace::new_for_exec(new_root, parent),
        None => AddressSpace::new(new_root),
    };
    let new_as = match new_as {
        Ok(a) => a,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };
    pmm::user_as::install_teardown(&new_as);
    // Same ordering as the x86_64 path and as Linux: arena + stack first, so
    // the interpreter's `get_unmapped_area` placement has a `mmap_base`.
    let rnd = crate::exec_transition::exec_rnd(&cur, creds.per_clear);
    // The RAW soft limit is kept alongside the mapped one: `RLIM_INFINITY` is
    // an input to `arch_pick_mmap_layout` that the map-size clamp erases.
    let raw_stack_rlim: u64 = {
        let (rc, _) = cur.rlimit(sched::rlimit::rlim::STACK);
        crate::exec_transition::secure_stack_limit(rc, creds.secure_exec)
    };
    let rlim_stack: u64 =
        ((raw_stack_rlim.saturating_add(0xfff)) & !0xfff).min(aslr::limits::RLIM_STACK_MAP_CAP);
    let stack_top: u64 = rnd.stack_top();
    let exec_user_stack_va = stack_top - rlim_stack;
    let exec_user_stack_top = stack_top;
    let exec_user_stack_len = rlim_stack as usize;
    let stack_hint = UserVirtAddr::new(exec_user_stack_va).expect("EXEC_USER_STACK_VA in user range");
    if new_as.mmap(
        Some(stack_hint),
        exec_user_stack_len,
        VmaProt::READ | VmaProt::WRITE,
        vmm::EXEC_STACK_VMA_FLAGS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    let layout = crate::exec_transition::exec_mmap_layout(
        &cur, creds.per_clear, &rnd, rlim_stack, raw_stack_rlim);
    new_as.set_mmap_layout(layout.base, layout.top_down);
    let exec_image = elf_load::Image {
        blob,
        file: exec_vp.as_ref().map(crate::execve_common::image_backing),
    };
    let img = match elf_load::load_image(
        exec_image, Some(&crate::execve_common::open_interp), &new_as, &rnd) {
        Ok(i) => i,
        Err(_) => return -(Errno::Enoexec.as_i32() as i64),
    };
    // Linux `load_elf_binary` tail: SVr4 `MMAP_PAGE_ZERO` emulation, mapped
    // after every PT_LOAD so a segment can never be displaced by it.
    crate::exec_persona::map_page_zero(&cur, &new_as, creds.per_clear);
    sched::live::zap_other_threads();
    let me = { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) };
    new_as.mark_cpu(me);
    // SAFETY: new_root carries kernel-half cloned from master at new_user_l0; activate writes TTBR0_EL1 + flushes user TLB; preempt-off; single-CPU.
    unsafe { <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::activate(new_root); }
    // SAFETY: running task on this CPU; preempt-off; no concurrent execve writer; reading the still-current old mm before replace.
    if let Some(old) = unsafe { cur.mm_ref() } { old.clear_cpu(me); }
    // SAFETY: we are the running task; preempt-off; UP single-CPU so no concurrent reader of cur.mm.
    unsafe { cur.replace_mm(Some(new_as)); }
    unshare_fd_table_and_close_on_exec(&cur);
    reset_caught_signals(&cur);
    reset_per_execve_state(&cur);
    // Linux clears the TLS register across exec; the new image installs its own.
    // SAFETY: TPIDR_EL0 is the per-thread user TLS register, written at EL1 for
    // the task currently on this CPU, whose old image is already gone.
    unsafe {
        core::arch::asm!("msr tpidr_el0, xzr", options(nomem, nostack, preserves_flags));
    }
    // Linux `fs/binfmt_elf.c:226` `create_elf_tables()`: AT_RANDOM is 16
    // `get_random_bytes()` bytes drawn per exec.
    let random16 = crate::auxrandom::at_random_bytes();
    let argv_slices: alloc::vec::Vec<&[u8]> = argv_vec.iter().map(|v| v.as_slice()).collect();
    let envp_slices: alloc::vec::Vec<&[u8]> = envp_vec.iter().map(|v| v.as_slice()).collect();
    cur.set_cmdline(Some(sched::argv_to_cmdline(&argv_slices[..argc])));
    cur.set_environ(Some(sched::argv_to_cmdline(&envp_slices[..envc])));
    // SAFETY: the block borrows only `path_owned`, a kernel-side copy of the
    // exec path already read out of user memory, and the file-capability lookup
    // it performs runs in this task's own execve.
    let exec_path_for_caps = unsafe {
        let path_str = match core::str::from_utf8(&path_owned) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => alloc::string::String::new(),
        };
        if !path_str.is_empty() {
            cur.set_exe_path(Some(path_str.clone()));
            if let Some(mm) = cur.mm_ref() { mm.set_exe_path(path_str.clone()); }
            // Linux `exe_file_deny_write_access` on the new image, released on
            // the old one (`kernel/fork.c` `replace_mm_exe_file`). Modern Linux
            // dropped `VM_DENYWRITE` and hangs `ETXTBSY` off the exe_file, so
            // this retention is what stops a running binary's text being
            // rewritten under it. The image was already opened for exec above,
            // so a failure here means someone opened it for write in between —
            // rare, and non-fatal: the exec has already committed, so we keep
            // the old deny rather than unwind a live image.
            if let Some(vp) = exec_vp.as_ref() { let _ = cur.set_exe_inode(Some(vp.inode.clone())); }
            // Linux `load_elf_binary`/`set_task_comm`: execve always resets
            // comm to the basename of the newly-exec'd file, overriding any
            // prior prctl(PR_SET_NAME) rename — a fresh program image gets a
            // fresh name.
            let base = path_str.rsplit('/').next().unwrap_or(path_str.as_str());
            if !base.is_empty() { cur.set_comm(base); }
            Some(path_str)
        } else {
            None
        }
    };
    #[cfg(feature = "debug-sshd")]
    trace_sshd_exec_success(cur.tid, &path_owned);
    let _ = exec_path_for_caps;
    // Past the point of no return: install the credentials decided above
    // (Linux `commit_creds(bprm->cred)` inside `begin_new_exec`).
    crate::exec_transition::commit(cur, &creds);
    if let Some(vp) = exec_vp.as_ref() { ::fs::inotify::fire_open_exec(&vp.inode); }
    if let Err(e) = crate::exec_time::promote_time_namespace_at_exec(cur) {
        return -(e.as_i32() as i64);
    }
    let vdso_ehdr = match crate::vdso::map_into_current() {
        Some(v) => v,
        None => return -(Errno::Enomem.as_i32() as i64),
    };
    let vdso_rt_sigreturn = match crate::vdso::rt_sigreturn_addr(vdso_ehdr) {
        Some(v) => v,
        None => return -(Errno::Enoexec.as_i32() as i64),
    };
    // SAFETY: this task owns the freshly installed mm throughout execve.
    if let Some(mm) = unsafe { cur.mm_ref() } {
        mm.set_vdso_rt_sigreturn(vdso_rt_sigreturn);
    }
    // SAFETY: `build_user_stack` writes through the mm this task just installed
    // and activated on this CPU, into the freshly mapped stack VMA whose top and
    // length are passed here; no other task can reach that address space yet.
    let layout = match unsafe {
        elf_load::stack::build_user_stack(
            exec_user_stack_top,
            exec_user_stack_len as u64,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
            &path_owned,
            vdso_ehdr,
            <hal_aarch64::ArmCpuOps as hal::CpuOps>::cpu_hwcap(),
            elf_load::stack::AuxCreds {
                uid: creds.new.ruid, euid: creds.new.euid,
                gid: creds.new.rgid, egid: creds.new.egid,
                secure: creds.secure_exec,
            },
            <hal_aarch64::ArmCpuOps as hal::CpuOps>::cpu_min_sigstksz(),
            &rnd,
        )
    } {
        Some(l) => l,
        None => return -(Errno::Enomem.as_i32() as i64),
    };
    let new_sp = layout.sp;
    // Publish code/data/brk and argv/env/stack through the same commit point
    // the kernel's PID 1 bootstrap uses.
    // SAFETY: running task on this CPU; preempt-off; no concurrent execve.
    if let Some(mm) = unsafe { cur.mm_ref() } {
        elf_load::commit_mm_layout(mm, &img, &layout);
    }
    let _ = Ordering::Acquire;
    // SAFETY: the task-owned pointer remains tied to this exec even if loading
    // blocked and another task entered SVC on the same CPU.
    let frame = unsafe { &mut *crate::arch_frame::current_svc_frame() };
    frame.elr_el1 = img.user_ip();
    frame.sp_el0 = new_sp;
    frame.spsr_el1 = 0;
    frame.retval = 0;
    // A vfork parent shares this mm and user stack until exec completes.
    // Publish completion only after the child has its final user return
    // frame, so the parent cannot resume and alter that shared stack while
    // this task is still constructing its new image.
    sched::live::vfork_done(cur);
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
    #[cfg(feature = "debug-heappoison")]
    if let Some(bad) = kalloc::validate_global() {
        klog::write_raw(b"[KALLOC-BISECT] free list broke by tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" bad_node=0x");
        klog::write_hex_u64(bad as u64);
        klog::write_raw(b"\n");
    }
    #[cfg(feature = "debug-heappoison")]
    if let Some((dentry, bad_op)) = vfs::dcache::debug_scan_d_op_sanity() {
        klog::write_raw(b"[DENTRY-BISECT] d_op corrupted by tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" dentry=0x");
        klog::write_hex_u64(dentry);
        klog::write_raw(b" bad_d_op=0x");
        klog::write_hex_u64(bad_op);
        klog::write_raw(b"\n");
    }
    crate::execve_common::ptrace_exec_event(cur);
    0
}
