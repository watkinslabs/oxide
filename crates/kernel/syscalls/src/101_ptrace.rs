// ptrace(2) — slot 101. Extracted from signal.rs to keep that file
// under the 1000-line cap per `08§7`. Dispatch in `mod.rs` calls
// `ptrace::sys_ptrace` by name. FPU/user-area helpers live in the
// sibling `ptrace_fpu` module; foreign-AS access via `pmm::user_as`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_ptrace(request, pid, addr, data)` — slot 101. Admits the
/// request set tracer-class libraries probe (sandbox-detection,
/// sentry-style runtime checks); real cross-AS memory access and
/// signal-stop integration are wired against `traced_by` +
/// foreign-mm read/write + the sched stop-state registry.
///
/// PTRACE_TRACEME — sets caller's traced_by to its parent.
/// PTRACE_ATTACH/SEIZE — sets target's traced_by to caller.
/// PTRACE_DETACH clears the tracer; CONT/SYSCALL/SINGLESTEP wake
/// the target via the stop-state registry; SETOPTIONS stores the
/// option bit-set on the target; KILL posts SIGKILL; LISTEN is
/// silent 0 (full ptrace-stop machinery rides a follow-up).
/// PTRACE_PEEKTEXT/PEEKDATA — real foreign-mm read of an 8-byte
/// word from the target's user AS via `read_foreign_user`.
/// PTRACE_PEEKUSER — returns 0 word (no per-arch user-area
/// materializer; honest stub for probes that need the call to
/// succeed but don't depend on register values).
/// PTRACE_POKETEXT/POKEDATA — real foreign-mm write via
/// `write_foreign_user` (refuses non-writable leaves).
/// PTRACE_POKEUSER — EOPNOTSUPP (no per-arch user-area materializer yet).
/// PTRACE_GETREGS/SETREGS/GETREGSET/SETREGSET — real read/write of
/// the target's saved syscall frame at kstack_top - 0x80 (x86) /
/// -0xD0 (aarch64). PTRACE_GETSIGINFO/SETSIGINFO — silent 0.
/// Anything else → -EINVAL (per Linux for unknown ptrace request).
/// # C: O(N_tasks) on PTRACE_ATTACH lookup; O(1) otherwise.
pub fn sys_ptrace(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    use sched::Signum;
    const PTRACE_TRACEME:    u64 = 0;
    const PTRACE_PEEKTEXT:   u64 = 1;
    const PTRACE_PEEKDATA:   u64 = 2;
    const PTRACE_PEEKUSER:   u64 = 3;
    const PTRACE_POKETEXT:   u64 = 4;
    const PTRACE_POKEDATA:   u64 = 5;
    const PTRACE_POKEUSER:   u64 = 6;
    const PTRACE_CONT:       u64 = 7;
    const PTRACE_KILL:       u64 = 8;
    const PTRACE_SINGLESTEP: u64 = 9;
    const PTRACE_GETREGS:    u64 = 12;
    const PTRACE_SETREGS:    u64 = 13;
    const PTRACE_GETFPREGS:  u64 = 14;
    const PTRACE_SETFPREGS:  u64 = 15;
    const PTRACE_ATTACH:     u64 = 16;
    const PTRACE_DETACH:     u64 = 17;
    const PTRACE_SYSCALL:    u64 = 24;
    const PTRACE_GETREGSET:  u64 = 0x4204;
    const PTRACE_SETREGSET:  u64 = 0x4205;
    const PTRACE_SEIZE:      u64 = 0x4206;
    const PTRACE_INTERRUPT:  u64 = 0x4207;
    const PTRACE_LISTEN:     u64 = 0x4208;
    const PTRACE_SETOPTIONS: u64 = 0x4200;
    const PTRACE_GETEVENTMSG:u64 = 0x4201;
    const PTRACE_GETSIGINFO: u64 = 0x4202;
    const PTRACE_SETSIGINFO: u64 = 0x4203;

    let request = args.a0;
    let pid     = args.a1 as u32;

    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    match request {
        PTRACE_TRACEME => {
            let parent = cur.parent_tid.load(Ordering::Acquire);
            cur.traced_by.store(parent, Ordering::Release);
            0
        }
        PTRACE_ATTACH | PTRACE_SEIZE => {
            match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => {
                    t.traced_by.store(cur.tid, Ordering::Release);
                    // F104: ATTACH posts SIGSTOP so the target stops at
                    // its next signal-delivery point. SEIZE attaches
                    // without the implicit stop (Linux semantics —
                    // tracer must use PTRACE_INTERRUPT to stop the
                    // target later).
                    if request == PTRACE_ATTACH {
                        t.sigpending.fetch_or(Signum::Sigstop.bit(), Ordering::Release);
                        sched::live::signal_wake_up(&t);
                    }
                    0
                }
                None    => -(Errno::Esrch.as_i32() as i64),
            }
        }
        PTRACE_DETACH => {
            if let Some(t) = sched::live::registry::resolve_user_pid(pid) {
                t.traced_by.store(0, Ordering::Release);
                // F104: clear any pending SIGSTOP from a prior ATTACH
                // and wake the target if it parked in stop_until_cont.
                t.sigpending.fetch_and(!Signum::Sigstop.bit(), Ordering::Release);
                sched::live::registry::wake_if_stopped(&t);
            }
            0
        }
        PTRACE_KILL => {
            // Set SIGKILL pending on target.
            if let Some(t) = sched::live::registry::resolve_user_pid(pid) {
                t.sigpending.fetch_or(Signum::Sigkill.bit(), Ordering::Release);
                sched::live::signal_wake_up(&t);
            }
            0
        }
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
            // Real foreign-mm read of 8 bytes from `addr` in
            // the target's user AS.
            //
            // ABI quirk: glibc/musl's ptrace() PEEK wrapper
            // passes `&result` as `data` and expects the kernel
            // to write the word INTO `*data`, returning 0 on
            // success (matches what real Linux does despite the
            // man page implying the word comes back as the rv).
            // We do both: write to `*data` if non-NULL, and
            // return the word as the syscall rv for raw callers.
            // -EFAULT on unmapped target page.
            let addr = args.a2;
            let data = args.a3;
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            // target is a foreign task: clone_mm pins against a concurrent
            // exit/execve mm replacement on another CPU.
            let mm = match target.clone_mm() {
                Some(m) => m, None => return -(Errno::Esrch.as_i32() as i64),
            };
            let root_pa = mm.root_pa();
            let mut buf = [0u8; 8];
            // SAFETY: mm Arc keeps root_pa alive; HHDM init done before any user task runs; target page tables are stable while mm Arc is held.
            let n = unsafe { pmm::user_as::read_foreign_user(root_pa, addr, &mut buf[..]) };
            if n != 8 { return -(Errno::Efault.as_i32() as i64); }
            let word = i64::from_le_bytes(buf);
            if data != 0 && data < ::hal::USER_VA_END {
                // SAFETY: data validated < USER_VA_END; user page mapped (caller's AS active during syscall); CPL=0 writes through caller's mapping.
                unsafe { core::ptr::write_volatile(data as *mut i64, word); }
            }
            word
        }
        PTRACE_PEEKUSER => crate::ptrace_fpu::peek_user(pid, args.a2, args.a3),
        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            // Real foreign-mm write of 8 bytes. Refuses if leaf
            // is not user-writable (no silent W^X bypass; CoW
            // path follows when the kernel grows one).
            let addr = args.a2;
            let data = args.a3;
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            // target is a foreign task: clone_mm pins against a concurrent
            // exit/execve mm replacement on another CPU.
            let mm = match target.clone_mm() {
                Some(m) => m, None => return -(Errno::Esrch.as_i32() as i64),
            };
            let root_pa = mm.root_pa();
            let buf = data.to_le_bytes();
            // SAFETY: mm Arc keeps root_pa alive; write_foreign_user verifies leaf writability per chunk before writing.
            let n = unsafe { pmm::user_as::write_foreign_user(root_pa, addr, &buf[..]) };
            if n != 8 { return -(Errno::Efault.as_i32() as i64); }
            0
        }
        PTRACE_POKEUSER => crate::ptrace_fpu::poke_user(pid, args.a2, args.a3),
        PTRACE_CONT | PTRACE_SYSCALL | PTRACE_SINGLESTEP => {
            // Real wake: target was Stopped (via SIGSTOP/TSTP/etc. or
            // ATTACH-induced stop in a future PTRACE_INTERRUPT path).
            // Flip Stopped → Runnable + re-enqueue. Optionally inject
            // a signal from `data` (caller's `data` arg = a3) — Linux
            // semantic: 0 = continue without signal; non-zero = post
            // that signal pending so syscall-return delivers it.
            //
            // SINGLESTEP additionally arms target.singlestep so the
            // kernel-to-user resume path (per-arch follow-ups) sets
            // RFLAGS.TF / MDSCR_EL1.SS on the next entry. Until those
            // arches land, behaviour matches CONT — flag is set but
            // no trap fires; first-cut wake semantics preserved.
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            let sig = args.a3 as i32;
            if sig > 0 && (sig as u32) <= sched::signum::RT_SIGNAL_MAX {
                target.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
                sched::live::signal_wake_up(&target);
            }
            if request == PTRACE_SINGLESTEP {
                target.singlestep.store(1, Ordering::Release);
            }
            if request == PTRACE_SYSCALL {
                // F108: arm the tracee to self-stop at the next syscall
                // entry + return. Cleared at the stop.
                target.ptrace_syscall_armed.store(true, Ordering::Release);
            } else {
                target.ptrace_syscall_armed.store(false, Ordering::Release);
            }
            sched::live::registry::wake_if_stopped(&target);
            0
        }
        PTRACE_GETREGS | PTRACE_GETREGSET => {
            // F115: real reg snapshot from target's saved syscall frame.
            // Target must be stopped or attached; we read its
            // kernel_stack top and copy the 15-u64 user-reg block at
            // offset -0x80 (x86) / SVC frame (aarch64) into `data`.
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            let top = target.kernel_stack.load(Ordering::Acquire);
            if top.is_null() { return -(Errno::Esrch.as_i32() as i64); }
            let data = args.a3;
            if data == 0 || data >= hal::USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: top is the target task's per-task kernel stack
            // top installed at spawn; saved syscall frame lies in the
            // 0x80 bytes immediately below it per the syscall-entry
            // asm prologue. Target is stopped (caller arranged
            // PTRACE_ATTACH SIGSTOP) so the frame is stable.
            #[cfg(target_arch = "x86_64")]
            {
                let frame = (top as u64 - 0x80) as *const u64;
                // SAFETY: data validated < USER_VA_END; CPL=0 writes 27*8 bytes (struct user_regs_struct shape, partially populated) through caller's AS.
                unsafe {
                    for i in 0..15 {
                        let v = core::ptr::read_volatile(frame.add(i));
                        core::ptr::write_volatile((data + (i as u64) * 8) as *mut u64, v);
                    }
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                // aarch64 SVC frame layout: 18 u64s at the same offset.
                let frame = (top as u64 - 0xD0) as *const u64;
                // SAFETY: data validated < USER_VA_END; CPL=0 writes 18*8 bytes through caller's AS; frame layout matches `hal_aarch64::SvcFrame.gp[..]`.
                unsafe {
                    for i in 0..18 {
                        let v = core::ptr::read_volatile(frame.add(i));
                        core::ptr::write_volatile((data + (i as u64) * 8) as *mut u64, v);
                    }
                }
            }
            0
        }
        PTRACE_SETREGS | PTRACE_SETREGSET => {
            // F116: real reg writeback into target's saved syscall
            // frame, symmetric with F115 GETREGS. Target must be
            // stopped; the frame at kstack_top - 0x80 (x86) /
            // -0xD0 (aarch64) is stable while the tracee is parked.
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            let top = target.kernel_stack.load(Ordering::Acquire);
            if top.is_null() { return -(Errno::Esrch.as_i32() as i64); }
            let data = args.a3;
            if data == 0 || data >= hal::USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            #[cfg(target_arch = "x86_64")]
            {
                let frame = (top as u64 - 0x80) as *mut u64;
                // SAFETY: data validated < USER_VA_END; CPL=0 reads 15*8 bytes from caller AS into the target task's saved syscall frame; the SyscallFrame layout is stable while the target is parked (caller's responsibility).
                unsafe {
                    for i in 0..15 {
                        let v = core::ptr::read_volatile((data + (i as u64) * 8) as *const u64);
                        core::ptr::write_volatile(frame.add(i), v);
                    }
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                let frame = (top as u64 - 0xD0) as *mut u64;
                // SAFETY: same — data validated; SVC frame layout stable while target parked.
                unsafe {
                    for i in 0..18 {
                        let v = core::ptr::read_volatile((data + (i as u64) * 8) as *const u64);
                        core::ptr::write_volatile(frame.add(i), v);
                    }
                }
            }
            0
        }
        PTRACE_SETOPTIONS => {
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            target.ptrace_options.store(args.a3 as u32, Ordering::Release);
            0
        }
        PTRACE_GETEVENTMSG => {
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            let data = args.a3;
            if data == 0 || data >= hal::USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            let msg = target.ptrace_eventmsg.load(Ordering::Acquire);
            // SAFETY: data validated < USER_VA_END; aligned u64 store of last ptrace event msg into caller's AS.
            unsafe { core::ptr::write_volatile(data as *mut u64, msg); }
            0
        }
        PTRACE_GETSIGINFO => {
            // Return the last stop's siginfo_t (or a SIGTRAP-shaped
            // default if no stop has snapshotted). Tracer reads
            // 128 bytes; we fill the first 32 with the SigInfo
            // record and leave the rest zero.
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            let data = args.a3;
            if data == 0 || data >= hal::USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            let snap = target.ptrace_siginfo.lock().clone()
                .unwrap_or(sched::SigInfo { signo: 5, code: 0, pid: 0, uid: 0, value: 0 });
            // SAFETY: data validated < USER_VA_END; 128-byte siginfo_t slot in caller's AS; we write the leading 32 bytes (signo/errno/code/pid/uid/value) and zero the rest.
            unsafe {
                for i in 0..128usize {
                    core::ptr::write_volatile((data + i as u64) as *mut u8, 0);
                }
                core::ptr::write_volatile(data as *mut i32, snap.signo as i32);
                core::ptr::write_volatile((data +  8) as *mut i32, snap.code);
                core::ptr::write_volatile((data + 16) as *mut u32, snap.pid);
                core::ptr::write_volatile((data + 20) as *mut u32, snap.uid);
                core::ptr::write_volatile((data + 24) as *mut u64, snap.value);
            }
            0
        }
        PTRACE_SETSIGINFO => {
            // Replace target's stop siginfo from a user-supplied
            // siginfo_t (first 32 bytes). On the next ptrace-CONT
            // with a non-zero signal arg, the kernel would normally
            // deliver this siginfo (full delivery integration rides
            // a follow-up; the write itself is now real).
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            let data = args.a3;
            if data == 0 || data >= hal::USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: data validated < USER_VA_END; siginfo_t leading 32B layout per Linux x86_64; CPL=0 reads through caller's AS.
            let info = unsafe {
                sched::SigInfo {
                    signo: core::ptr::read_volatile(data as *const i32) as u32,
                    code:  core::ptr::read_volatile((data +  8) as *const i32),
                    pid:   core::ptr::read_volatile((data + 16) as *const u32),
                    uid:   core::ptr::read_volatile((data + 20) as *const u32),
                    value: core::ptr::read_volatile((data + 24) as *const u64),
                }
            };
            *target.ptrace_siginfo.lock() = Some(info);
            0
        }
        PTRACE_GETFPREGS => crate::ptrace_fpu::get_fpregs(pid, args.a3),
        PTRACE_SETFPREGS => crate::ptrace_fpu::set_fpregs(pid, args.a3),
        PTRACE_INTERRUPT => {
            // Force the tracee to enter group-stop at the next safe point.
            // Real Linux semantics: a SEIZE'd tracee not yet stopped gets a
            // synthetic SIGSTOP, on delivery a PTRACE_EVENT_STOP fires and
            // wait4 reports the stop. v1 substrate: mark stop_pending +
            // raise SIGSTOP. The pending bit drives wait4(WUNTRACED).
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            target.stop_signal.store(Signum::Sigstop as u8, Ordering::Release);
            target.stop_pending.store(true, Ordering::Release);
            target.sigpending.fetch_or(Signum::Sigstop.bit(), Ordering::Release);
            sched::live::signal_wake_up(&target);
            0
        }
        PTRACE_LISTEN => {
            // Re-enter listen state without resuming: keep target Stopped,
            // clear cont_pending so wait4(WCONTINUED) won't fire spuriously.
            let target = match sched::live::registry::resolve_user_pid(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            target.cont_pending.store(false, Ordering::Release);
            0
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
