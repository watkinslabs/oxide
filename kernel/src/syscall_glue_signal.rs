// Signal/namespace/ptrace/kill family extracted from
// syscall_glue_proc.rs to keep that file under the 1000-line cap
// per `08§7`. The dispatch in `syscall_glue.rs` calls into this
// module by name; everything here is single-mutator-per-active-CPU.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

const CLONE_NEWNS:    u64 = 0x00020000;
const CLONE_NEWCGROUP:u64 = 0x02000000;
const CLONE_NEWUTS:   u64 = 0x04000000;
const CLONE_NEWIPC:   u64 = 0x08000000;
const CLONE_NEWUSER:  u64 = 0x10000000;
const CLONE_NEWPID:   u64 = 0x20000000;
const CLONE_NEWNET:   u64 = 0x40000000;

#[inline]
fn ns_bit_for_clone(clone_flag: u64) -> Option<u32> {
    Some(match clone_flag {
        CLONE_NEWNS      => 0,
        CLONE_NEWUTS     => 1,
        CLONE_NEWIPC     => 2,
        CLONE_NEWUSER    => 3,
        CLONE_NEWPID     => 4,
        CLONE_NEWNET     => 5,
        CLONE_NEWCGROUP  => 6,
        _ => return None,
    })
}

/// `sys_unshare(flags)` — slot 272. Detach the calling task from
/// the named namespaces. v1 honors CLONE_NEWUTS by snapshotting the
/// current global hostname into a per-task UTS slot. Other CLONE_NEW*
/// bits set the membership bit but per-NS isolation isn't enforced.
/// # C: O(1)
pub fn kernel_sys_unshare(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let flags = args.a0;
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    let mut bits: u64 = 0;
    for clone_flag in [
        CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER,
        CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP,
    ] {
        if (flags & clone_flag) != 0 {
            if let Some(b) = ns_bit_for_clone(clone_flag) {
                bits |= 1u64 << b;
            }
        }
    }
    if bits == 0 { return 0; }
    cur.ns_membership.fetch_or(bits, Ordering::Release);
    if (bits & (1u64 << 1)) != 0 {
        let snap_bytes = crate::hostname::snapshot();
        let snap = alloc::string::String::from_utf8(snap_bytes).unwrap_or_default();
        // SAFETY: per-task slot single-mutator per `13§5`; running task on this CPU is the sole writer of uts_hostname.
        unsafe { *cur.uts_hostname.get() = snap; }
    }
    if (bits & (1u64 << 2)) != 0 {
        // CLONE_NEWIPC — fresh ipc_ns id (F100).
        static NEXT_IPC_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_IPC_NS.fetch_add(1, Ordering::AcqRel);
        cur.ipc_ns.store(id, Ordering::Release);
    }
    if (bits & (1u64 << 5)) != 0 {
        // CLONE_NEWNET — fresh net_ns id (F101). Subsequent
        // IfaceRegistry lookups from this task match only entries
        // registered in the new NS (initially empty — userspace must
        // create veth/lo for the new NS).
        static NEXT_NET_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_NET_NS.fetch_add(1, Ordering::AcqRel);
        cur.net_ns.store(id, Ordering::Release);
    }
    0
}

/// `sys_setns(fd, nstype)` — slot 308. v1 honors the syscall as a
/// clear-the-membership-bit op so callers can re-attach to the init
/// namespace. fd argument is currently ignored.
/// # C: O(1)
pub fn kernel_sys_setns(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let _fd  = args.a0;
    let nstype = args.a1;
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    let mut clear: u64 = 0;
    for clone_flag in [
        CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER,
        CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP,
    ] {
        if (nstype & clone_flag) != 0 {
            if let Some(b) = ns_bit_for_clone(clone_flag) {
                clear |= 1u64 << b;
            }
        }
    }
    if clear == 0 { return 0; }
    cur.ns_membership.fetch_and(!clear, Ordering::Release);
    if (clear & (1u64 << 1)) != 0 {
        // SAFETY: per-task slot single-mutator per `13§5`; running task on this CPU is the sole writer of uts_hostname.
        unsafe { (*cur.uts_hostname.get()).clear(); }
    }
    0
}

/// `sys_ptrace(request, pid, addr, data)` — slot 101. v2 P22b
/// extension: admits the request set most tracer-class libraries
/// probe (sandbox-detection, sentry-style runtime checks) so they
/// pass beyond the ptrace gate. Real cross-AS memory access +
/// signal-stop integration ride P22c (needs a foreign-mm read/
/// write helper + sched-side ptrace stop-state).
///
/// PTRACE_TRACEME — sets caller's traced_by to its parent.
/// PTRACE_ATTACH/SEIZE — sets target's traced_by to caller.
/// PTRACE_DETACH/CONT/SYSCALL/SINGLESTEP/SETOPTIONS/KILL/LISTEN —
///   silent 0 (no scheduler-stop machinery yet).
/// PTRACE_PEEKTEXT/PEEKDATA/PEEKUSER — returns 0 word (does NOT
///   read the target's actual memory; honest stub for tracer-
///   present probes that only need the call to succeed).
/// PTRACE_POKETEXT/POKEDATA — real foreign-mm write via write_foreign_user
/// (refuses non-writable leaves; no silent W^X bypass).
/// PTRACE_POKEUSER — EOPNOTSUPP (no per-arch user-area materializer yet).
/// PTRACE_GETREGS/SETREGS/GETREGSET/SETREGSET/GETSIGINFO — silent 0.
/// Anything else → -EINVAL (per Linux for unknown ptrace request).
/// # C: O(N_tasks) on PTRACE_ATTACH lookup; O(1) otherwise.
pub fn kernel_sys_ptrace(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
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

    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    match request {
        PTRACE_TRACEME => {
            let parent = cur.parent_tid.load(Ordering::Acquire);
            cur.traced_by.store(parent, Ordering::Release);
            0
        }
        PTRACE_ATTACH | PTRACE_SEIZE => {
            match crate::sched::registry::lookup(pid) {
                Some(t) => { t.traced_by.store(cur.tid, Ordering::Release); 0 }
                None    => -(Errno::Esrch.as_i32() as i64),
            }
        }
        PTRACE_DETACH => {
            if let Some(t) = crate::sched::registry::lookup(pid) {
                t.traced_by.store(0, Ordering::Release);
            }
            0
        }
        PTRACE_KILL => {
            // Set SIGKILL pending on target.
            if let Some(t) = crate::sched::registry::lookup(pid) {
                t.sigpending.fetch_or(1u64 << 8, Ordering::Release); // SIGKILL = 9 → bit 8
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
            let target = match crate::sched::registry::lookup(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            // SAFETY: target task; we hold an Arc<Task> from the registry; mm slot is single-mutator per `13§5` and target is either running or parked — fork/exec don't mutate the slot under us.
            let mm = match unsafe { target.mm_ref() } {
                Some(m) => m.clone(), None => return -(Errno::Esrch.as_i32() as i64),
            };
            let root_pa = mm.root_pa();
            let mut buf = [0u8; 8];
            // SAFETY: mm Arc keeps root_pa alive; HHDM init done before any user task runs; target page tables are stable while mm Arc is held.
            let n = unsafe { crate::user_as::read_foreign_user(root_pa, addr, &mut buf[..]) };
            if n != 8 { return -(Errno::Efault.as_i32() as i64); }
            let word = i64::from_le_bytes(buf);
            if data != 0 && data < ::hal::USER_VA_END {
                // SAFETY: data validated < USER_VA_END; user page mapped (caller's AS active during syscall); CPL=0 writes through caller's mapping.
                unsafe { core::ptr::write_volatile(data as *mut i64, word); }
            }
            word
        }
        PTRACE_PEEKUSER => {
            // Reads from the target's struct user (registers +
            // tls offsets). Needs a per-arch user-area materializer
            // we don't have. Honest -EOPNOTSUPP rather than a 0 lie.
            -(Errno::Eopnotsupp.as_i32() as i64)
        }
        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            // Real foreign-mm write of 8 bytes. Refuses if leaf
            // is not user-writable (no silent W^X bypass; CoW
            // path follows when the kernel grows one).
            let addr = args.a2;
            let data = args.a3;
            let target = match crate::sched::registry::lookup(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            // SAFETY: same as PEEKTEXT — we hold Arc<Task>; mm slot stable per `13§5`.
            let mm = match unsafe { target.mm_ref() } {
                Some(m) => m.clone(), None => return -(Errno::Esrch.as_i32() as i64),
            };
            let root_pa = mm.root_pa();
            let buf = data.to_le_bytes();
            // SAFETY: mm Arc keeps root_pa alive; write_foreign_user verifies leaf writability per chunk before writing.
            let n = unsafe { crate::user_as::write_foreign_user(root_pa, addr, &buf[..]) };
            if n != 8 { return -(Errno::Efault.as_i32() as i64); }
            0
        }
        PTRACE_POKEUSER => -(Errno::Eopnotsupp.as_i32() as i64),
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
            let target = match crate::sched::registry::lookup(pid) {
                Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
            };
            let sig = args.a3 as i32;
            if sig > 0 && sig <= 64 {
                target.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
            }
            if request == PTRACE_SINGLESTEP {
                target.singlestep.store(1, Ordering::Release);
            }
            crate::sched::registry::wake_if_stopped(&target);
            0
        }
        PTRACE_GETREGS | PTRACE_SETREGS
            | PTRACE_GETFPREGS | PTRACE_SETFPREGS
            | PTRACE_GETREGSET | PTRACE_SETREGSET
            | PTRACE_INTERRUPT | PTRACE_LISTEN
            | PTRACE_SETOPTIONS | PTRACE_GETEVENTMSG
            | PTRACE_GETSIGINFO | PTRACE_SETSIGINFO => 0,
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// `sys_kill(pid, sig)` — slot 62. pgrp-aware per `28§4`:
///   pid > 0 — signal that tid via the registry.
///   pid == 0 — fan to caller's pgrp.
///   pid == -1 — not implemented; -EPERM.
///   pid <  -1 — fan to pgrp `(-pid)`.
/// `sig == 0` is a permission probe.
/// # C: O(N_tasks) on pgrp fan; O(N_tasks) lookup for non-self pid
pub fn kernel_sys_kill(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid = args.a0 as i32;
    let sig = args.a1 as i32;
    if !(0..=64).contains(&sig) { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    let bit = if sig == 0 { 0 } else { 1u64 << (sig - 1) };
    if pid > 0 {
        if pid as u32 == cur.tid {
            if sig != 0 { cur.sigpending.fetch_or(bit, Ordering::Release); }
            return 0;
        }
        match crate::sched::registry::lookup(pid as u32) {
            Some(t) => {
                if !sig_perm_check(cur, &t, sig) {
                    return -(syscall::errno::Errno::Eperm.as_i32() as i64);
                }
                if sig != 0 {
                    t.sigpending.fetch_or(bit, Ordering::Release);
                    if sig == 18 { crate::sched::registry::wake_if_stopped(&t); }
                }
                0
            }
            None => -(syscall::errno::Errno::Esrch.as_i32() as i64),
        }
    } else if pid == 0 {
        let pgid = cur.pgid.load(Ordering::Acquire);
        let n = post_pgrp(pgid, bit, sig);
        if n == 0 { -(syscall::errno::Errno::Esrch.as_i32() as i64) } else { 0 }
    } else if pid == -1 {
        -(syscall::errno::Errno::Eperm.as_i32() as i64)
    } else {
        let n = post_pgrp((-pid) as u32, bit, sig);
        if n == 0 { -(syscall::errno::Errno::Esrch.as_i32() as i64) } else { 0 }
    }
}

fn post_pgrp(pgid: u32, bit: u64, sig: i32) -> usize {
    use core::sync::atomic::Ordering;
    let tasks = crate::sched::registry::tasks_in_pgrp(pgid);
    let mut n = 0usize;
    let cur = crate::sched::current();
    for t in &tasks {
        let allowed = match cur {
            Some(c) => sig_perm_check(c, t, sig),
            None    => true,
        };
        if !allowed { continue; }
        if sig != 0 {
            t.sigpending.fetch_or(bit, Ordering::Release);
            if sig == 18 { crate::sched::registry::wake_if_stopped(t); }
        }
        n += 1;
    }
    n
}

/// Linux signal-permission check per `kill(2)`: sender may signal
/// receiver if sender holds CAP_KILL OR sender's real/effective uid
/// matches receiver's real or saved-set uid. SIGCONT is additionally
/// allowed within the same session (so `kill -CONT 0` from a parent
/// shell works even after setuid drops).
/// # C: O(1)
pub fn sig_perm_check(cur: &sched::Task, target: &sched::Task, sig: i32) -> bool {
    use core::sync::atomic::Ordering;
    if cur.tid == target.tid { return true; }
    if cur.has_cap(sched::cap::KILL) { return true; }
    let ce = cur.creds.euid.load(Ordering::Acquire);
    let cr = cur.creds.ruid.load(Ordering::Acquire);
    let tr = target.creds.ruid.load(Ordering::Acquire);
    let ts = target.creds.suid.load(Ordering::Acquire);
    if ce == tr || ce == ts || cr == tr || cr == ts { return true; }
    // SIGCONT (18) — same session bypass.
    if sig == 18 && cur.sid.load(Ordering::Acquire) == target.sid.load(Ordering::Acquire) {
        return true;
    }
    false
}

/// `sys_rt_sigaction(sig, act, oldact, sz)` — slot 13. Reads + stores
/// the user-supplied `struct sigaction` into the per-task `sigactions`
/// array; writes the prior to `oldact` if non-NULL. Layout:
///   { sa_handler: u64, sa_flags: u64, sa_restorer: u64, sa_mask: u64 }
/// # C: O(1)
pub fn kernel_sys_rt_sigaction(args: &SyscallArgs) -> i64 {
    use sched::SaHandler;
    use syscall::errno::Errno;
    let sig = args.a0 as usize;
    let act    = args.a1;
    let oldact = args.a2;
    let _sz    = args.a3;
    if sig == 0 || sig > 64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return 0,
    };
    let idx = sig - 1;
    // SAFETY: running task on this CPU; preempt-off; sole writer to sigactions slot per single-mutator invariant.
    let table = unsafe { &mut *cur.sigactions.get() };
    let prior = table[idx];
    if oldact != 0 && oldact < hal::USER_VA_END {
        // SAFETY: oldact validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( oldact         as *mut u64, prior.handler);
            core::ptr::write_volatile((oldact +   8)  as *mut u64, prior.flags);
            core::ptr::write_volatile((oldact +  16)  as *mut u64, prior.restorer);
            core::ptr::write_volatile((oldact +  24)  as *mut u64, prior.mask);
        }
    }
    if act != 0 {
        if act >= hal::USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: act validated < USER_VA_END; user page mapped via active CR3 (caller's AS); CPL=0 reads through user mapping per `15§3`; 8-byte aligned per Linux ABI.
        let (h, f, r, m) = unsafe { (
            core::ptr::read_volatile( act         as *const u64),
            core::ptr::read_volatile((act +   8)  as *const u64),
            core::ptr::read_volatile((act +  16)  as *const u64),
            core::ptr::read_volatile((act +  24)  as *const u64),
        ) };
        table[idx] = SaHandler { handler: h, flags: f, restorer: r, mask: m };
    }
    0
}

/// `sys_rt_sigprocmask(how, set, oldset, sz)` — slot 14.
/// # C: O(1)
pub fn kernel_sys_rt_sigprocmask(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    const SIG_BLOCK:   u64 = 0;
    const SIG_UNBLOCK: u64 = 1;
    const SIG_SETMASK: u64 = 2;
    let how    = args.a0;
    let set    = args.a1;
    let oldset = args.a2;
    let sz     = args.a3;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return 0,
    };
    let prior = cur.sigmask.load(Ordering::Acquire);
    if oldset != 0 && oldset < hal::USER_VA_END {
        // SAFETY: oldset validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe { core::ptr::write_volatile(oldset as *mut u64, prior); }
    }
    if set == 0 { return 0; }
    if set >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: set validated < USER_VA_END; CPL=0 reads through caller's AS.
    let new_set = unsafe { core::ptr::read_volatile(set as *const u64) };
    let new_mask = match how {
        SIG_BLOCK   => prior | new_set,
        SIG_UNBLOCK => prior & !new_set,
        SIG_SETMASK => new_set,
        _           => return -(Errno::Einval.as_i32() as i64),
    };
    let new_mask = new_mask & !(1u64 << 8) & !(1u64 << 18);
    cur.sigmask.store(new_mask, Ordering::Release);
    0
}

/// `sys_sigaltstack(ss, oldss)` — slot 131.
/// # C: O(1)
pub fn kernel_sys_sigaltstack(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let ss    = args.a0;
    let oldss = args.a1;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Eperm.as_i32() as i64),
    };
    if oldss != 0 {
        if oldss >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let sp    = cur.sigaltstack_sp.load(Ordering::Acquire);
        let size  = cur.sigaltstack_size.load(Ordering::Acquire);
        let flags = cur.sigaltstack_flags.load(Ordering::Acquire);
        // SAFETY: oldss validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile(oldss        as *mut u64, sp);
            core::ptr::write_volatile((oldss + 8)  as *mut i32, flags as i32);
            core::ptr::write_volatile((oldss + 16) as *mut u64, size);
        }
    }
    if ss != 0 {
        if ss >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: ss validated < USER_VA_END; struct sigaltstack layout {sp, flags, size}; CPL=0 reads through caller's AS.
        let sp:    u64 = unsafe { core::ptr::read_volatile(ss as *const u64) };
        // SAFETY: ss+8 still inside 24-byte struct sigaltstack; aligned i32 read.
        let flags: i32 = unsafe { core::ptr::read_volatile((ss + 8) as *const i32) };
        // SAFETY: ss+16 still inside 24-byte struct sigaltstack; aligned u64 read.
        let size:  u64 = unsafe { core::ptr::read_volatile((ss + 16) as *const u64) };
        cur.sigaltstack_sp.store(sp, Ordering::Release);
        cur.sigaltstack_size.store(size, Ordering::Release);
        cur.sigaltstack_flags.store(flags as u32, Ordering::Release);
    }
    0
}

/// `sys_rt_sigpending(set, sz)` — slot 127.
/// # C: O(1)
pub fn kernel_sys_rt_sigpending(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let set = args.a0;
    let sz  = args.a1;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if set == 0 || set >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    let p = cur.sigpending.load(Ordering::Acquire);
    // SAFETY: set validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe { core::ptr::write_volatile(set as *mut u64, p); }
    0
}

/// `sys_rt_sigsuspend(mask, sz)` — slot 130.
/// # C: O(yields until signal)
pub fn kernel_sys_rt_sigsuspend(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let mask = args.a0;
    let sz   = args.a1;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if mask == 0 || mask >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    // SAFETY: mask validated < USER_VA_END; CPL=0 reads through caller's AS.
    let m = unsafe { core::ptr::read_volatile(mask as *const u64) };
    let new_mask = m & !(1u64 << 8) & !(1u64 << 18);
    let old_mask = cur.sigmask.swap(new_mask, Ordering::AcqRel);
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        if (pending & !cur.sigmask.load(Ordering::Acquire)) != 0 { break; }
        // SAFETY: brief IRQ-on window so timer + IPI signal-raise can land; preempt-off through tick_yield.
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("sti; pause; cli", options(nomem, nostack, preserves_flags)); }
        // SAFETY: process ctx; runqueue installed; preempt-off until tick_yield's Context::switch.
        unsafe { crate::sched::tick_yield(); }
    }
    cur.sigmask.store(old_mask, Ordering::Release);
    -(Errno::Eintr.as_i32() as i64)
}

/// `sys_rt_sigtimedwait(set, info, timeout, sz)` — slot 128.
/// # C: O(yields until signal or timeout)
pub fn kernel_sys_rt_sigtimedwait(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    use syscall::errno::Errno;
    let set     = args.a0;
    let info    = args.a1;
    let timeout = args.a2;
    let sz      = args.a3;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if set == 0 || set >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: set validated < USER_VA_END; CPL=0 reads via active CR3.
    let wanted = unsafe { core::ptr::read_volatile(set as *const u64) };
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    let deadline = if timeout != 0 && timeout < hal::USER_VA_END {
        // SAFETY: timeout validated < USER_VA_END; struct timespec layout {tv_sec, tv_nsec}; CPL=0 reads.
        let secs = unsafe { core::ptr::read_volatile(timeout as *const i64) };
        // SAFETY: timeout+8 inside the 16-byte timespec; aligned i64 read.
        let nsec = unsafe { core::ptr::read_volatile((timeout + 8) as *const i64) };
        if secs < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return -(Errno::Einval.as_i32() as i64);
        }
        let total = (secs as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        Some(now.saturating_add(total))
    } else { None };
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        let arrived = pending & wanted;
        if arrived != 0 {
            let sig = arrived.trailing_zeros() + 1;
            cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
            if info != 0 && info < hal::USER_VA_END {
                // SAFETY: info validated < USER_VA_END; siginfo_t is 128 bytes; CPL=0 writes through caller's AS.
                unsafe {
                    for i in 0..128usize {
                        core::ptr::write_volatile((info + i as u64) as *mut u8, 0);
                    }
                    core::ptr::write_volatile(info as *mut i32, sig as i32);
                }
            }
            return sig as i64;
        }
        if let Some(dl) = deadline {
            #[cfg(target_arch = "x86_64")]
            let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
            #[cfg(target_arch = "aarch64")]
            let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
            if now >= dl { return -(Errno::Eagain.as_i32() as i64); }
        }
        // SAFETY: brief IRQ-on window so timer + IPI signal-raise can land; preempt-off through tick_yield.
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("sti; pause; cli", options(nomem, nostack, preserves_flags)); }
        // SAFETY: process ctx; runqueue installed; preempt-off until tick_yield's Context::switch.
        unsafe { crate::sched::tick_yield(); }
    }
}

/// `sys_rt_sigqueueinfo(pid, sig, info)` — slot 129.
/// # C: O(N_tasks)
pub fn kernel_sys_rt_sigqueueinfo(args: &SyscallArgs) -> i64 {
    let kill_args = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: 0, a3: 0, a4: 0, a5: 0,
    };
    kernel_sys_kill(&kill_args)
}

/// `sys_rt_tgsigqueueinfo(tgid, tid, sig, info)` — slot 297.
/// # C: O(1)
pub fn kernel_sys_rt_tgsigqueueinfo(args: &SyscallArgs) -> i64 {
    let tgkill_args = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: args.a2, a3: 0, a4: 0, a5: 0,
    };
    kernel_sys_tgkill(&tgkill_args)
}

/// One signal ready for delivery.
#[derive(Copy, Clone, Debug)]
pub struct PendingSignal {
    pub sig:      u32,
    pub handler:  u64,
    pub flags:    u64,
    pub restorer: u64,
}

/// Inspect `current.sigpending & !current.sigmask`; if non-zero,
/// clear the lowest bit and return the `PendingSignal`.
/// # C: O(1)
pub fn take_lowest_pending() -> Option<PendingSignal> {
    use core::sync::atomic::Ordering;
    let cur = crate::sched::current()?;
    let pending = cur.sigpending.load(Ordering::Acquire);
    let masked  = cur.sigmask.load(Ordering::Acquire);
    let deliver = pending & !masked;
    if deliver == 0 { return None; }
    let sig = deliver.trailing_zeros() + 1;
    cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
    // SAFETY: running task on this CPU; preempt-off; sole reader of sigactions slot per single-mutator invariant in `13§5`.
    let table = unsafe { &*cur.sigactions.get() };
    let h = table[(sig - 1) as usize];
    Some(PendingSignal { sig, handler: h.handler, flags: h.flags, restorer: h.restorer })
}

/// `sys_tgkill(tgid, tid, sig)` — slot 234. Validates that the
/// target tid belongs to the named tgid before delivering.
/// # C: O(N_tasks) lookup
pub fn kernel_sys_tgkill(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let tgid = args.a0 as i32;
    let tid  = args.a1 as i32;
    let sig  = args.a2 as i32;
    if tgid <= 0 || tid <= 0 { return -(Errno::Esrch.as_i32() as i64); }
    if !(0..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
    match crate::sched::registry::lookup(tid as u32) {
        Some(t) => {
            if t.tgid.load(Ordering::Acquire) != tgid as u32 {
                return -(Errno::Esrch.as_i32() as i64);
            }
            let cur = match crate::sched::current() {
                Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
            };
            if !sig_perm_check(cur, &t, sig) {
                return -(Errno::Eperm.as_i32() as i64);
            }
            if sig != 0 {
                t.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
                if sig == 18 { crate::sched::registry::wake_if_stopped(&t); }
            }
            0
        }
        None => -(Errno::Esrch.as_i32() as i64),
    }
}
