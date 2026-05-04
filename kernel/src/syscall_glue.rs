// Glue between the per-arch syscall asm stub and the architecture-
// neutral `syscall::dispatch` table per `15§4`.
//
// Both arches' asm stubs reference `oxide_syscall_dispatch` by symbol;
// `extern "C"` + `#[no_mangle]` here makes the linker resolve it to
// the kernel-side wrapper that:
//   1. packs the asm-shuffled regs into `SyscallArgs`,
//   2. calls `syscall::dispatch(nr, &args) -> i64`,
//   3. returns the result as `u64` placed in rax (x86) / x0 (arm)
//      per `15§1.3` so a libc-style `rv > -4096UL` failure check
//      works userspace-side.
//
// arch-specific interceptions (e.g., x86 `sys_arch_prctl`) live
// here behind cfg gates because they need to call into `hal-<arch>`.

#![cfg(target_os = "oxide-kernel")]

use syscall::{dispatch, SyscallArgs};
use syscall::errno::Errno;
use hal::{TimerOps, USER_VA_END};

#[cfg(target_arch = "x86_64")]
const SYSCALL_NR_ARCH_PRCTL: u64 = 158;
#[cfg(target_arch = "x86_64")]
const ARCH_SET_FS: u64 = 0x1002;
#[cfg(target_arch = "x86_64")]
const ARCH_GET_FS: u64 = 0x1003;

const SYSCALL_NR_CLOCK_GETTIME: u64 = 228;
const SYSCALL_NR_UNAME: u64          = 63;
const SYSCALL_NR_MMAP: u64           = 9;
const SYSCALL_NR_MUNMAP: u64         = 11;
const SYSCALL_NR_EXIT: u64           = 60;
const SYSCALL_NR_FORK: u64           = 57;
const SYSCALL_NR_EXECVE: u64         = 59;
const SYSCALL_NR_WAIT4: u64          = 61;
const SYSCALL_NR_GETPID: u64         = 39;
const SYSCALL_NR_GETPPID: u64        = 110;
const SYSCALL_NR_READ: u64           = 0;

const NS_PER_SEC: u64 = 1_000_000_000;

/// `struct utsname` field width per Linux. Six fixed-length C
/// strings, NUL-terminated, total 6 × 65 = 390 bytes.
const UTSNAME_FIELD_LEN: usize = 65;
const UTSNAME_TOTAL_LEN: usize = UTSNAME_FIELD_LEN * 6;

/// Per-arch machine identifier returned by `uname.machine`.
#[cfg(target_arch = "x86_64")]
const UNAME_MACHINE: &[u8] = b"x86_64";
#[cfg(target_arch = "aarch64")]
const UNAME_MACHINE: &[u8] = b"aarch64";

/// Write the 6 utsname fields at consecutive 65-byte slots starting
/// at `tp`. Each field is the source bytes followed by NUL padding
/// out to 65 B. Caller validates `tp` range.
unsafe fn write_utsname_field(tp: u64, off: usize, src: &[u8]) {
    let n = src.len().min(UTSNAME_FIELD_LEN - 1);
    for i in 0..n {
        // SAFETY: caller validated [tp, tp + UTSNAME_TOTAL_LEN) lies entirely below USER_VA_END and is mapped writable; CPL=0 ignores the leaf U bit so direct writes land in the user page.
        unsafe { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, src[i]); }
    }
    for i in n..UTSNAME_FIELD_LEN {
        // SAFETY: same range as above; pads out the field with NUL.
        unsafe { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, 0u8); }
    }
}

/// `sys_mmap(addr, len, prot, flags, fd, off)` — slot 9. Routes to
/// the real `vmm::AddressSpace::mmap` per `11§3`/`11§6` via the
/// `crate::user_as` integration. v1 supports only
/// `MAP_ANONYMOUS | MAP_PRIVATE` with `addr=NULL` / `fd=-1`; pages
/// are demand-faulted in by `user_as::user_fault_handler` per
/// `11§5`. No upfront frame allocation — first user access faults.
fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd = args.a4 as i64;
    match crate::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd) {
        Ok(va)  => va as i64,
        Err(rv) => rv,
    }
}

/// `sys_munmap(addr, len)` — slot 11. Routes to
/// `vmm::AddressSpace::munmap` + per-page PT unmap + frame free per
/// `11§6` via the `crate::user_as` integration. Replaces the no-op
/// stub in `crates/syscall::dispatch::sys_munmap` (the in-table
/// stub still exists as a fallback when glue isn't routing — but
/// glue now intercepts nr=11 first so it's dead-path).
fn kernel_munmap(args: &SyscallArgs) -> i64 {
    crate::user_as::glue_munmap(args.a0, args.a1)
}

/// Poll the COM1 UART (I/O port 0x3F8) for one byte. Returns
/// `Some(byte)` if RX data is ready, `None` otherwise. v1 stand-
/// in for full TTY input plumbing per docs/28: a real UART RX
/// IRQ + ringbuffer + WaitQueue lands with the interactive shell
/// PR (P2-23). This polling form is enough to demonstrate the
/// syscall path; userspace reads `0` until input arrives.
///
/// # SAFETY: privileged port I/O legal at CPL=0; reads two bytes
/// at most from the COM1 device range.
#[cfg(target_arch = "x86_64")]
unsafe fn uart_poll_read() -> Option<u8> {
    // SAFETY: port I/O at CPL=0; LSR + RBR are read-only; no memory effect.
    unsafe {
        let lsr: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") lsr,
            in("dx") 0x3FDu16,
            options(nomem, nostack, preserves_flags),
        );
        if lsr & 0x01 == 0 {
            return None;
        }
        let b: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") b,
            in("dx") 0x3F8u16,
            options(nomem, nostack, preserves_flags),
        );
        Some(b)
    }
}

/// `sys_read(fd, buf, count)` — slot 0. v1 stand-in: only fd=0
/// (stdin) is wired, polling COM1 RX. Other fds fall through to
/// the arch-neutral table's `-EBADF` stub.
///
/// Polling, non-blocking: if RX data is ready returns the byte
/// count read (currently always 1 on a hit, 0 on no data). A real
/// blocking implementation rides the WaitQueue work for P2-23.
#[cfg(target_arch = "x86_64")]
fn kernel_sys_read(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2;
    if fd != 0 {
        // Not stdin — defer to in-table stub via -EBADF.
        return -(Errno::Ebadf.as_i32() as i64);
    }
    if cnt == 0 {
        return 0;
    }
    if buf == 0 || buf >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: port I/O at CPL=0; non-blocking poll.
    let byte = match unsafe { uart_poll_read() } {
        Some(b) => b,
        None    => return 0, // EAGAIN-equivalent: caller polls again.
    };
    // SAFETY: caller validated buf < USER_VA_END; user page mapped (caller's task already executed from this AS); CPL=0 writes through user mapping.
    unsafe { core::ptr::write_volatile(buf as *mut u8, byte); }
    1
}

/// `sys_getpid()` — slot 39 per docs/15§5. Returns the current
/// task's `tid` per `13§5`. Replaces the in-table stub that
/// returns a fixed `1`.
fn kernel_sys_getpid(_args: &SyscallArgs) -> i64 {
    crate::sched::current().map(|c| c.tid as i64).unwrap_or(1)
}

/// `sys_getppid()` — slot 110 per docs/15§5. Returns the current
/// task's `parent_tid`; `0` for tasks with no parent (boot's
/// init-like task, kthreads).
fn kernel_sys_getppid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    crate::sched::current()
        .map(|c| c.parent_tid.load(Ordering::Acquire) as i64)
        .unwrap_or(0)
}

/// `sys_fork()` — slot 57 per docs/15§5 (Linux x86_64 fork). v0
/// per docs/11§7: clone the parent's `AddressSpace` (VMA tree
/// copy; mapped pages NOT copied — child re-demand-pages from
/// KernelBytes / fresh-zero for Anonymous), spawn a new user
/// `Task` with `mm = child_as`, return the child's TID to parent.
///
/// Child's iretq frame is built by `spawn_user_thread` with rax=0
/// (the synthesised IRQ frame's scratch slots default to zero, and
/// the rax slot is consumed by the IRQ epilogue's pop sequence
/// just before iretq) — so when the child is scheduled in, it
/// resumes at `user_rip` with rax=0 (the canonical fork return
/// distinguisher) and `rsp = user_rsp`.
///
/// Reads `user_rip`/`user_rsp` from globals captured by the
/// `oxide_syscall_entry` asm stub.
///
/// # C: O(N_vmas) clone + O(log N) enqueue
#[cfg(target_arch = "x86_64")]
fn kernel_sys_fork(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: we are the running task on this CPU; no concurrent writer to our mm; preempt-off through the syscall handler.
    let parent_mm = match unsafe { cur.mm_ref() } {
        Some(m) => m,
        None    => return -(Errno::Einval.as_i32() as i64),
    };

    // Allocate new PT root for the child.
    // SAFETY: capture_kernel_master ran at user_as::init; PMM up.
    let new_root = match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
        Some(r) => r,
        None    => return -(Errno::Enomem.as_i32() as i64),
    };

    // Clone the AS — VMA tree only per P2-15a.
    let child_mm = match parent_mm.fork(new_root) {
        Ok(m) => m,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };

    // SAFETY: we are running on the parent's per-task syscall stack; current_user_frame() points at the saved tail; we read but do not write.
    let frame = unsafe { &*hal_x86_64::current_user_frame() };
    let user_rip = frame[0];
    let user_rsp = frame[2];
    // user_rip points at the instruction RIGHT AFTER the syscall
    // (rcx is post-syscall in x86_64) — the child resumes there
    // with rax=0.

    let child_tid = crate::sched::next_tid();
    // SAFETY: runqueue installed by elf_smoke; child_mm is freshly forked from the parent's AS with kernel-half cloned from master per P2-19; user_rip/user_rsp captured from the parent's syscall frame.
    let spawn = unsafe {
        crate::sched::spawn_user_thread(
            child_tid, "fork-child", user_rip, user_rsp, child_mm,
        )
    };
    let child = match spawn {
        Ok(t)  => t,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };

    // Record parent_tid for `wait4` (P2-22).
    child.parent_tid.store(cur.tid, Ordering::Release);

    debug_sched! {
        klog::write_raw(b"[INFO]  sys_fork: parent_tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" child_tid=");
        klog::write_dec_u64(child_tid as u64);
        klog::write_raw(b" child_root=");
        klog::write_hex_u64(new_root);
        klog::write_raw(b"\n");
    }

    // Drop our local Arc; the runqueue's enqueue clone keeps the
    // child alive until it Zombies + parks to the zombie registry.
    drop(child);

    child_tid as i64
}

/// `sys_wait4(pid, wstatus, options, rusage)` — slot 61 per
/// docs/15§5. Reaps a Zombie child of the current task and
/// optionally writes the exit status to user memory at `wstatus`.
/// `pid == -1` matches any child; `pid > 0` matches that
/// specific TID. `options` (WNOHANG etc.) ignored for v1.
/// `rusage` ignored.
///
/// If no Zombie child is currently queued, the parent yields via
/// `schedule()` and re-checks. With UP single-CPU + non-preempt
/// schedule, the child is guaranteed to run + Zombie before the
/// parent's loop terminates (unless the child is itself blocked).
///
/// Returns the reaped child's TID, or -ECHILD if the caller has
/// no eligible children at all.
///
/// # C: O(N_zombies × N_yield_iters) — bounded by child runtime
#[cfg(target_arch = "x86_64")]
fn kernel_sys_wait4(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid     = args.a0 as i32;
    let wstatus = args.a1;
    let _options = args.a2;
    let _rusage  = args.a3;

    let parent_tid = match crate::sched::current() {
        Some(c) => c.tid,
        None    => return -(Errno::Einval.as_i32() as i64),
    };

    // Loop: try to reap; if no match, yield + retry. Bounded
    // because schedule() picks runnable children which eventually
    // exit + park.
    loop {
        if let Some((tid, code)) = crate::sched::reap_one(parent_tid, pid) {
            // POSIX wstatus encoding: low 7 bits = signal (0 for
            // normal exit), bit 7 = core flag, bits 8..16 =
            // exit code. v1 only handles normal exits.
            let wstat: i32 = (code & 0xff) << 8;
            if wstatus != 0 && wstatus < USER_VA_END {
                // SAFETY: wstatus validated < USER_VA_END; user page mapped (caller's user code already executed from this AS); CPL=0 reads/writes through the user mapping.
                unsafe { core::ptr::write_volatile(wstatus as *mut i32, wstat); }
            }
            debug_sched! {
                klog::write_raw(b"[INFO]  sys_wait4: parent=");
                klog::write_dec_u64(parent_tid as u64);
                klog::write_raw(b" reaped tid=");
                klog::write_dec_u64(tid as u64);
                klog::write_raw(b" code=");
                klog::write_dec_u64(code as u64);
                klog::write_raw(b"\n");
            }
            return tid as i64;
        }
        // No zombie ready — yield and retry. schedule() saves
        // our state into current.arch_ctx + switches; we resume
        // here when a child eventually exits + reschedule picks
        // us back.
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { crate::sched::tick_yield(); }
        // After resume, ZOMBIES likely contains a new entry.
        // Loop body re-tries.
        let _ = Ordering::Acquire; // touch to keep ordering import live
    }
}

/// `sys_execve(path, argv, envp)` — slot 59 per docs/15§5. v0
/// per docs/31§4: ignores the path argument, always loads the
/// kernel-static `EXEC_BLOB`. Replaces `current.mm` atomically,
/// activates the new AS, and updates `oxide_user_rip`/`rsp` so
/// the syscall epilogue's `sysretq` lands at the new program's
/// `e_entry` instead of returning to the caller.
///
/// argv/envp/auxv build is skipped for v1 (the test program
/// doesn't read them); P2-21b adds the auxv table per docs/31§5.
///
/// On error returns -ENOMEM / -ENOEXEC and the caller resumes
/// at the post-execve instruction. On success doesn't return —
/// the new program runs from `e_entry`.
///
/// # SAFETY: caller is `oxide_syscall_dispatch` running on the
/// user task's kernel stack with IRQs masked.
/// # C: O(phdrs) parse + O(N_vmas) AS build + O(1) activate
#[cfg(target_arch = "x86_64")]
fn kernel_sys_execve(args: &SyscallArgs) -> i64 {
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
        // SAFETY: path_ptr < USER_VA_END validated above; the user page is mapped (user code already executed from this AS); we read a single byte.
        let sel = unsafe { core::ptr::read_volatile(path_ptr as *const u8) };
        match crate::elf_smoke::lookup_blob(sel) {
            Some(b) => b,
            None    => return -(Errno::Enoent.as_i32() as i64),
        }
    };

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

    // 4. Overwrite the per-task syscall stack's saved user-frame
    //    so the asm epilogue's `pop rcx; pop r11; pop rsp; sysretq`
    //    lands the user at the new program entry instead of
    //    returning to the execve caller.
    // SAFETY: we are running on cur's per-task syscall stack; current_user_frame() points at the live saved tail; the syscall asm pops from these same slots after we return.
    let frame = unsafe { &mut *hal_x86_64::current_user_frame() };
    frame[0] = img.entry.as_u64();
    frame[1] = 0x002;
    frame[2] = crate::elf_smoke::EXEC_USER_STACK_TOP;

    debug_sched! {
        klog::write_raw(b"[INFO]  sys_execve: new entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" sp=");
        klog::write_hex_u64(crate::elf_smoke::EXEC_USER_STACK_TOP);
        klog::write_raw(b" new_root=");
        klog::write_hex_u64(new_root);
        klog::write_raw(b"\n");
    }

    // Return value irrelevant — sysretq goes to new program; rax
    // gets clobbered by the new program's first mov.
    0
}

/// `sys_exit(code)` — slot 60 per docs/15§2. The arch-neutral
/// dispatch table has a stub that returns 0; this wrapper
/// upgrades the behaviour to a real lifecycle exit per docs/13§5:
/// mark the running task Zombie + reschedule. With state=Zombie
/// the picker won't re-enqueue us, so `schedule()` falls through
/// to idle (the boot anchor) — boot resumes at its prior
/// `schedule()` callsite (in `elf_smoke::run_as_task`).
///
/// Stores the exit code in `Task.exit_status` per docs/13§5 so a
/// future `wait4` / `waitid` can read it.
///
/// # SAFETY: caller is `oxide_syscall_dispatch` running on the
/// user task's kernel stack with IRQs masked.
/// # C: O(log N) CFS pick + O(1) ctxsw
fn kernel_sys_exit(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use alloc::sync::Arc;
    if let Some(rq) = crate::sched::global() {
        // Snapshot exit code + state before parking — the
        // current task's strong ref needs to live in the zombie
        // registry until wait4 reaps it.
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current was installed via Arc::into_raw in `Runqueue::new` / `swap_current`; bumping the strong count is sound because we then matching `from_raw` to materialise an owned Arc.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: matching from_raw consumes the bumped count.
            let arc = unsafe { Arc::from_raw(raw) };
            arc.exit_status.store(args.a0 as i32, Ordering::Release);
            crate::sched::mark_done(&arc);
            debug_sched! {
                klog::write_raw(b"[INFO]  sys_exit: tid=");
                klog::write_dec_u64(arc.tid as u64);
                klog::write_raw(b" code=");
                klog::write_dec_u64(args.a0);
                klog::write_raw(b"\n");
            }
            crate::sched::park_zombie(arc);
        }
    }
    // Schedule away. State=Zombie ⇒ no re-enqueue; picker returns
    // idle (boot anchor) ⇒ Context::switch loads boot's saved regs
    // ⇒ control resumes in `elf_smoke::run_as_task` past its
    // `schedule()` call. We never come back to this task.
    // SAFETY: process / kthread context (we're on the user task's kernel stack); preempt-off; runqueue installed.
    unsafe { crate::sched::schedule(); }
    // Unreachable — Zombie task isn't re-scheduled.
    loop { core::hint::spin_loop(); }
}

fn kernel_uname(args: &SyscallArgs) -> i64 {
    let tp = args.a0;
    if let Err(rv) = validate_user_buf(tp, UTSNAME_TOTAL_LEN as u64, 1) { return rv; }
    // SAFETY: range validated above; user-half VA is mapped writable
    // by the userspace-smoke setup. Each field write iterates byte-
    // by-byte so no alignment requirement.
    unsafe {
        write_utsname_field(tp, 0 * UTSNAME_FIELD_LEN, b"oxide");
        write_utsname_field(tp, 1 * UTSNAME_FIELD_LEN, b"oxide");                  // nodename
        write_utsname_field(tp, 2 * UTSNAME_FIELD_LEN, b"0.1.0-pre");              // release
        write_utsname_field(tp, 3 * UTSNAME_FIELD_LEN, b"oxide #1 SMP PREEMPT");  // version
        write_utsname_field(tp, 4 * UTSNAME_FIELD_LEN, UNAME_MACHINE);             // machine
        write_utsname_field(tp, 5 * UTSNAME_FIELD_LEN, b"(none)");                 // domainname
    }
    0
}

/// Validate that a user buffer `[ptr, ptr + len)` lies entirely
/// below `USER_VA_END` and is `align`-byte aligned at `ptr`.
/// Returns Ok(()) or Err(-EFAULT-as-i64) ready to return from a
/// glue handler.
fn validate_user_buf(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    if ptr == 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    if align > 1 && (ptr & (align - 1)) != 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let end = ptr.checked_add(len).ok_or(-(Errno::Efault.as_i32() as i64))?;
    if end > USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    Ok(())
}

/// Read the per-arch monotonic clock and write `{tv_sec, tv_nsec}`
/// to the user `timespec*`. Both arches' `TimerOps::monotonic_ns`
/// returns 0 until calibrated, so a CLOCK_MONOTONIC reading at
/// boot-time may legitimately be 0.
///
/// v1: ignore clk_id; CLOCK_REALTIME and CLOCK_MONOTONIC alike use
/// the kernel monotonic counter (no wall-time RTC source yet).
fn kernel_clock_gettime(args: &SyscallArgs) -> i64 {
    let _clk_id = args.a0;
    let tp = args.a1;
    if let Err(rv) = validate_user_buf(tp, 16, 8) { return rv; }

    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;

    let tv_sec  = ns / NS_PER_SEC;
    let tv_nsec = ns % NS_PER_SEC;
    // SAFETY: `tp` validated 16-byte range below USER_VA_END + 8-byte
    // aligned. CPL=0 ignores the leaf U bit so the kernel can write
    // the user mapping directly.
    unsafe {
        core::ptr::write_volatile(tp as *mut u64,         tv_sec);
        core::ptr::write_volatile((tp + 8) as *mut u64,   tv_nsec);
    }
    0
}

/// x86-specific syscall handled in the kernel-side glue (since
/// `crates/syscall` is arch-neutral and can't call `hal-x86_64`).
/// Only `ARCH_SET_FS` and `ARCH_GET_FS` are implemented; other
/// codes return -EINVAL. v1 single-thread → ARCH_GET_FS reads
/// IA32_FS_BASE via rdmsr (added if needed); v1 just returns 0.
#[cfg(target_arch = "x86_64")]
fn kernel_arch_prctl(args: &SyscallArgs) -> i64 {
    let code = args.a0;
    let val  = args.a1;
    match code {
        ARCH_SET_FS => {
            // Reject non-canonical / kernel-VA addresses.
            if val >= USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: val is a user-canonical address per the check
            // above; wrmsr IA32_FS_BASE = val updates the per-CPU
            // segment base used by user-mode `fs:` accesses.
            unsafe { hal_x86_64::set_user_fs_base(val); }
            0
        }
        ARCH_GET_FS => {
            // v1: report 0; once we read FS_BASE back, return that.
            0
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// SysV-ABI hook invoked by `oxide_syscall_entry`. Stack-switched +
/// arg-shuffled by the asm stub before this is called.
///
/// # SAFETY: caller is the syscall asm stub; runs single-CPU with
/// IF=0 (FMASK cleared). Returns a u64 placed in rax for sysretq.
/// # C: O(1) + dispatch fn cost
#[no_mangle]
pub unsafe extern "C" fn oxide_syscall_dispatch(
    nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64,
) -> u64 {
    let args = SyscallArgs { a0, a1, a2, a3, a4, a5: 0 };
    // Arch-specific + per-arch-time syscalls handled here (kernel can
    // call hal); others fall through to the arch-neutral dispatch.
    let rv = match nr {
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_ARCH_PRCTL    => kernel_arch_prctl(&args),
        SYSCALL_NR_CLOCK_GETTIME => kernel_clock_gettime(&args),
        SYSCALL_NR_UNAME         => kernel_uname(&args),
        SYSCALL_NR_MMAP          => kernel_mmap(&args),
        SYSCALL_NR_MUNMAP        => kernel_munmap(&args),
        SYSCALL_NR_EXIT          => kernel_sys_exit(&args),
        SYSCALL_NR_GETPID        => kernel_sys_getpid(&args),
        SYSCALL_NR_GETPPID       => kernel_sys_getppid(&args),
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_READ          => kernel_sys_read(&args),
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_FORK          => kernel_sys_fork(&args),
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_EXECVE        => kernel_sys_execve(&args),
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_WAIT4         => kernel_sys_wait4(&args),
        _                        => dispatch(nr as u32, &args),
    };
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    rv as u64
}
