#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use hal::{TimerOps, USER_VA_END};
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::execve_common::{
    apply_file_caps_at_execve, regain_root_caps_at_execve, read_user_exec_path,
    reset_caught_signals, reset_per_execve_state, resolve_shebang_chain,
};

use super::fd_table::unshare_fd_table_and_close_on_exec;

/// `sys_execve(path, argv, envp)` per `15§5` / `31§4`. Thin wrapper
/// that reads the user-space path then delegates to `execve_inner`.
/// # SAFETY: dispatch ctx, IRQs masked.
/// # C: O(64) + execve_inner cost
pub fn sys_execve(args: &SyscallArgs) -> i64 {
    let path_owned = match read_user_exec_path(args.a0) {
        Ok(v) => v,
        Err(rc) => return rc,
    };
    #[cfg(feature = "debug-swap")]
    trace_swap_exec(&path_owned);
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

/// Retained, feature-gated `execve` stage trace for the swap activator.
/// # C: O(path length)
#[cfg(feature = "debug-swap")]
fn trace_swap_exec_stage(path: &[u8], stage: &[u8]) {
    if matches!(path, b"/sbin/swapon" | b"/usr/sbin/swapon" | b"/usr/bin/swapon") {
        klog::write_raw(b"[SWAPON] exec-stage ");
        klog::write_raw(stage);
        klog::write_raw(b"\n");
    }
}

/// execve body shared between `sys_execve` (path from user pointer)
/// and `sys_execveat` (path resolved from `dirfd` for AT_EMPTY_PATH).
/// `args.a1` = argv, `args.a2` = envp; `args.a0` is ignored — the
/// caller has already produced `path_owned` from whatever source.
/// # SAFETY: dispatch ctx, IRQs masked.
/// # C: O(phdrs) + O(N_vmas) + O(1)
pub fn execve_inner(args: &SyscallArgs, path_owned: alloc::vec::Vec<u8>) -> i64 {
    use hal::UserVirtAddr;
    use vmm::{AddressSpace, VmaBacking, VmaProt};

    let cur = match sched::live::current() {
        Some(c) => c,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    let mut ext4_blob: Option<alloc::vec::Vec<u8>> = None;
    if path_owned.is_empty() { return -(Errno::Enoent.as_i32() as i64); }
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[EXECLOAD begin tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" path=");
        klog::write_raw(&path_owned);
        klog::write_raw(b"]\n");
    }
    let v = match crate::pathresolve::read_exec(&path_owned).or_else(|| ext4::rootfs::read_file(&path_owned)) {
        Some(v) => v,
        None => {
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(b"[execve ENOENT] path=");
                klog::write_raw(&path_owned);
                klog::write_raw(b"\n");
            }
            // Y3 execve-ENOENT capture (gated): the EXACT binary path systemd
            // --user tried to exec that resolved to -2, with the caller vpid so
            // it can be tied to the uid-979 user@979.service cascade.
            #[cfg(feature = "debug-syscall")]
            {
                use core::sync::atomic::Ordering;
                let v = cur.vtgid.load(Ordering::Acquire);
                let vpid = if v != 0 { v } else { cur.tgid.load(Ordering::Acquire) };
                klog::write_raw(b"[EXECNOENT] vpid=");
                klog::write_dec_u64(vpid as u64);
                klog::write_raw(b" path=");
                klog::write_raw(&path_owned);
                klog::write_raw(b"\n");
            }
            return -(Errno::Enoent.as_i32() as i64);
        }
    };
    ext4_blob = Some(v);
    let mut blob: &[u8] = ext4_blob.as_deref().expect("just set");
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
    if !read_vec(args.a1, &mut argv_vec, &mut total_bytes) { return -(Errno::E2big.as_i32() as i64); }
    if !read_vec(args.a2, &mut envp_vec, &mut total_bytes) { return -(Errno::E2big.as_i32() as i64); }
    #[cfg(feature = "debug-boot")]
    if path_owned.windows(b"gnome-shell".len()).any(|part| part == b"gnome-shell") {
        for entry in &envp_vec {
            if entry.starts_with(b"CLUTTER_DEBUG=") || entry.starts_with(b"MUTTER_DEBUG=") {
                klog::write_raw(b"[GNOME_EXEC_ENV ");
                klog::write_raw(entry);
                klog::write_raw(b"]\n");
            }
        }
    }
    let mut path_owned = path_owned;
    if ext4_blob.is_some() && blob.starts_with(b"#!") {
        let mut owned = ext4_blob.take().expect("ext4_blob.is_some()");
        if let Err(e) = resolve_shebang_chain(&mut owned, &mut path_owned, &mut argv_vec) {
            return -(e.as_i32() as i64);
        }
        ext4_blob = Some(owned);
        blob = ext4_blob.as_deref().expect("just set");
    }
    #[cfg(feature = "debug-atexit")]
    {
        let is_target = path_owned.windows(9).any(|w| w == b"generator")
            || path_owned.windows(7).any(|w| w == b"udevadm");
        if is_target {
            envp_vec.push(b"LD_DEBUG=versions,scopes,files".to_vec());
            envp_vec.push(b"LD_WARN=1".to_vec());
        }
    }
    let argc = argv_vec.len();
    let envc = envp_vec.len();
    // [X5 xdg] Ground-truth probe: does `systemd --user` (uid 979) receive
    // XDG_RUNTIME_DIR in its execve envp? Answers set-but-dropped vs never-set.
    // Gated behind debug-syscall; matches any execve whose path contains
    // "systemd" run as a non-root uid (the per-user manager), and dumps the
    // ruid plus whether/what XDG_RUNTIME_DIR is present in envp.
    #[cfg(feature = "debug-syscall")]
    {
        use core::sync::atomic::Ordering;
        let ruid = cur.creds.ruid.load(Ordering::Acquire);
        let is_systemd = path_owned.windows(7).any(|w| w == b"systemd");
        if is_systemd && ruid != 0 {
            let mut xdg: Option<&[u8]> = None;
            for e in &envp_vec {
                if e.starts_with(b"XDG_RUNTIME_DIR=") {
                    xdg = Some(&e[b"XDG_RUNTIME_DIR=".len()..]);
                    break;
                }
            }
            klog::write_raw(b"[X5 xdg] exec path=");
            klog::write_raw(&path_owned);
            klog::write_raw(b" ruid=");
            klog::write_dec_u64(ruid as u64);
            klog::write_raw(b" envc=");
            klog::write_dec_u64(envc as u64);
            match xdg {
                Some(v) => {
                    klog::write_raw(b" XDG_RT=SET val=");
                    klog::write_raw(v);
                }
                None => klog::write_raw(b" XDG_RT=UNSET"),
            }
            klog::write_raw(b"\n");
        }
    }
    if ::fs::inotify::perm_marks_present() {
        if let Ok(p) = core::str::from_utf8(&path_owned) {
            if let Ok(vp) = crate::pathresolve::resolve_path_raw(p, true) {
                let inode = vp.inode;
                if !::fs::inotify::check_open_exec_perm(&inode) {
                    return -(Errno::Eacces.as_i32() as i64);
                }
            }
        }
    }
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
    let new_root = match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
        Some(r) => r,
        None => return -(Errno::Enomem.as_i32() as i64),
    };
    let new_as = match AddressSpace::new(new_root) {
        Ok(a) => a,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };
    pmm::user_as::install_teardown(&new_as);
    #[cfg(feature = "debug-swap")]
    trace_swap_exec_stage(&path_owned, b"before-elf-load");
    let img = match elf_load::load_static_blob(blob, &new_as) {
        Ok(i) => i,
        Err(_) => return -(Errno::Enoexec.as_i32() as i64),
    };
    #[cfg(feature = "debug-swap")]
    trace_swap_exec_stage(&path_owned, b"after-elf-load");
    // Record the ELF code/data bounds + initial brk (Linux mm->start_code..
    // end_data + start_brk) so /proc/<pid>/stat + PR_SET_MM validation see
    // real values. arg/env/stack land after the stack is built below.
    new_as.set_code_data(img.start_code, img.end_code, img.start_data, img.end_data);
    new_as.set_start_brk(img.brk.as_u64());
    let rlim_stack: u64 = {
        // SAFETY: rlimits slot single-mutator per `13§5`; cur is the running task on this CPU; we only read, no concurrent writer.
        let (rc, _) = unsafe { (*cur.rlimits.get())[sched::rlimit::rlim::STACK] };
        ((rc + 0xfff) & !0xfff).min(0x4000_0000)
    };
    let stack_top: u64 = hal::USER_VA_END - 0x10000;
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
    #[cfg(feature = "debug-swap")]
    trace_swap_exec_stage(&path_owned, b"after-stack-map");
    new_as.set_mmap_base(exec_user_stack_va.saturating_sub(vmm::MMAP_BASE_GAP));
    sched::live::zap_other_threads();
    use hal::MmuOps;
    let me = { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) };
    new_as.mark_cpu(me);
    // SAFETY: new_root carries kernel-half cloned from master per P2-19; activate writes CR3 + flushes user TLB; preempt-off; single-CPU.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(new_root); }
    #[cfg(feature = "debug-swap")]
    trace_swap_exec_stage(&path_owned, b"after-activate-mm");
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent execve writer; reading the still-current old mm before replace.
    if let Some(old) = unsafe { cur.mm_ref() } { old.clear_cpu(me); }
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent reader of mm on another CPU (UP v1).
    unsafe { cur.replace_mm(Some(new_as)); }
    #[cfg(feature = "debug-swap")]
    trace_swap_exec_stage(&path_owned, b"after-replace-mm");
    unsafe {
        hal_x86_64::set_user_fs_base(0);
        let ctx_ptr: *mut hal_x86_64::ContextX86_64 = cur.arch_ctx_ptr();
        (*ctx_ptr).fs_base = 0;
    }
    unshare_fd_table_and_close_on_exec(&cur);
    reset_caught_signals(&cur);
    reset_per_execve_state(&cur);
    let random16 = {
        let ns = <hal_x86_64::X86TimerOps as TimerOps>::monotonic_ns().0;
        let mut r = [0u8; 16];
        for i in 0..16 { r[i] = (ns >> ((i % 8) * 8)) as u8 ^ (i as u8 * 0x9b); }
        r
    };
    let argv_slices: alloc::vec::Vec<&[u8]> = argv_vec.iter().map(|v| v.as_slice()).collect();
    let envp_slices: alloc::vec::Vec<&[u8]> = envp_vec.iter().map(|v| v.as_slice()).collect();
    let exec_path_for_caps = unsafe {
        *cur.cmdline.get() = Some(sched::argv_to_cmdline(&argv_slices[..argc]));
        *cur.environ.get() = Some(sched::argv_to_cmdline(&envp_slices[..envc]));
        let path_str = match core::str::from_utf8(&path_owned) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => alloc::string::String::new(),
        };
        if !path_str.is_empty() {
            *cur.exe_path.get() = Some(path_str.clone());
            if let Some(mm) = cur.mm_ref() { mm.set_exe_path(path_str.clone()); }
            Some(path_str)
        } else {
            None
        }
    };
    regain_root_caps_at_execve(cur);
    if let Some(p) = exec_path_for_caps {
        if let Ok(vp) = crate::pathresolve::resolve_path_raw(&p, true) {
            apply_file_caps_at_execve(&vp.inode, cur);
            ::fs::inotify::fire_open_exec(&vp.inode);
        }
    }
    if let Err(e) = crate::exec_time::promote_time_namespace_at_exec(cur) {
        return -(e.as_i32() as i64);
    }
    let vdso_ehdr = crate::vdso::map_into_current().unwrap_or(0);
    #[cfg(feature = "debug-swap")]
    trace_swap_exec_stage(&path_owned, b"after-vdso-map");
    let layout = match unsafe {
        elf_load::stack::build_user_stack(
            exec_user_stack_top,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
            &path_owned,
            vdso_ehdr,
            <hal_x86_64::X86CpuOps as hal::CpuOps>::cpu_hwcap(),
        )
    } {
        Some(l) => l,
        None => return -(Errno::Enomem.as_i32() as i64),
    };
    let new_sp = layout.sp;
    #[cfg(feature = "debug-swap")]
    trace_swap_exec_stage(&path_owned, b"after-stack-build");
    // Record argv/env string-block bounds + initial rsp (Linux
    // mm->arg_start..env_end + start_stack); the source for
    // /proc/<pid>/{cmdline,environ,stat} and the PR_SET_MM baseline.
    // SAFETY: running task on this CPU; preempt-off; no concurrent execve.
    if let Some(mm) = unsafe { cur.mm_ref() } {
        mm.set_arg_env_stack(layout.arg_start, layout.arg_end, layout.env_start, layout.env_end, new_sp);
    }
    let frame = unsafe { &mut *hal_x86_64::current_user_frame() };
    frame[0] = img.user_ip();
    frame[1] = 0x202;
    frame[2] = new_sp;
    unsafe {
        let base = (frame as *mut [u64; 3] as *mut u64).sub(7);
        for i in 0..7 { core::ptr::write_volatile(base.add(i), 0); }
    }
    // A vfork parent shares this mm and user stack until exec completes.
    // Publish completion only after the child has its final user return
    // frame, so the parent cannot resume and alter that shared stack while
    // this task is still constructing its new image.
    sched::live::vfork_done(cur);
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
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[EXECLOAD ready tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b"]\n");
    }
    0
}
