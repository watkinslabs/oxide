// `sys_prctl` (slot 157) real impl. Split out of
// `syscall_glue_proc.rs` to keep that file under the 1000-line cap.


use syscall::SyscallArgs;
use syscall::errno::Errno;
use core::sync::atomic::Ordering;

const PR_SET_PDEATHSIG:       u64 = 1;
const PR_GET_PDEATHSIG:       u64 = 2;
const PR_GET_DUMPABLE:        u64 = 3;
const PR_SET_DUMPABLE:        u64 = 4;
pub(crate) const PR_SET_KEEPCAPS: u64 = 8;
const PR_GET_KEEPCAPS:        u64 = 7;
const PR_SET_NAME:            u64 = 15;
const PR_GET_NAME:            u64 = 16;
const PR_SET_SECCOMP:         u64 = 22;
const PR_GET_SECCOMP:         u64 = 21;
const PR_CAPBSET_READ:        u64 = 23;
const PR_CAPBSET_DROP:        u64 = 24;
const PR_GET_TSC:             u64 = 25;
const PR_SET_TSC:             u64 = 26;
const PR_SET_MM:              u64 = 35;
const PR_SET_VMA:             u64 = 0x5356_4d41;
const PR_SET_NO_NEW_PRIVS:    u64 = 38;
const PR_GET_NO_NEW_PRIVS:    u64 = 39;
const PR_SET_THP_DISABLE:     u64 = 41;
const PR_GET_THP_DISABLE:     u64 = 42;
const PR_SET_CHILD_SUBREAPER: u64 = 36;
const PR_GET_CHILD_SUBREAPER: u64 = 37;
const PR_GET_SECUREBITS:      u64 = 27;
pub(crate) const PR_SET_SECUREBITS: u64 = 28;
const PR_SET_TIMERSLACK:      u64 = 29;
const PR_GET_TIMERSLACK:      u64 = 30;
pub(crate) const PR_CAP_AMBIENT: u64 = 47;
// PR_CAP_AMBIENT sub-commands (arg2).
pub(crate) const PR_CAP_AMBIENT_IS_SET: u64 = 1;
const PR_CAP_AMBIENT_RAISE:     u64 = 2;
const PR_CAP_AMBIENT_LOWER:     u64 = 3;
const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;

/// `sys_personality(persona)` — slot 135. Returns previous personality
/// and (when `persona != 0xFFFFFFFF`) sets the new one. Per-task slot
/// added in F78. Stored opaquely; v1 doesn't act on the bits.
/// # C: O(1)
pub fn sys_personality(args: &SyscallArgs) -> i64 {
    let new = args.a0 as u32;
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let prev = cur.personality.load(Ordering::Acquire);
    if new != u32::MAX { cur.personality.store(new, Ordering::Release); }
    prev as i64
}

/// `sys_prctl(option, arg2, arg3, arg4, arg5)` — slot 157.
///
/// Real per-task storage for PR_SET_NO_NEW_PRIVS, PR_SET_KEEPCAPS,
/// PR_SET_PDEATHSIG, PR_SET_CHILD_SUBREAPER, plus reads via the
/// matching PR_GET_*. PR_CAPBSET_READ / PR_CAPBSET_DROP read from
/// the cap_bounding mask added in F66.
/// # C: O(1)
pub fn sys_prctl(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    match args.a0 {
        PR_SET_NAME | PR_SET_DUMPABLE | PR_SET_TSC | PR_SET_THP_DISABLE => 0,
        PR_GET_DUMPABLE => 1,
        PR_GET_TSC      => 1,
        PR_GET_THP_DISABLE => 0,
        PR_SET_TIMERSLACK => {
            // Linux: zero does not mean zero slack; it restores the task's
            // default 50us value. Sleep-deadline coalescing is a separate
            // scheduler consumer of this canonical per-task state.
            let slack_ns = if args.a1 == 0 { 50_000 } else { args.a1 };
            cur.timer_slack_ns.store(slack_ns, Ordering::Release);
            0
        }
        PR_GET_TIMERSLACK => cur.timer_slack_ns.load(Ordering::Acquire) as i64,
        PR_GET_NAME => {
            let p = args.a1;
            if p != 0 && p < hal::USER_VA_END {
                let name = cur.name;
                let n = name.len().min(15);
                // SAFETY: p validated < USER_VA_END; n bytes from a 'static str fit in the user 16-byte name buf.
                unsafe {
                    for i in 0..n {
                        core::ptr::write_volatile((p + i as u64) as *mut u8, name.as_bytes()[i]);
                    }
                    core::ptr::write_volatile((p + n as u64) as *mut u8, 0);
                }
            }
            0
        }
        PR_SET_NO_NEW_PRIVS => {
            if args.a1 != 1 { return -(Errno::Einval.as_i32() as i64); }
            cur.no_new_privs.store(true, Ordering::Release);
            0
        }
        PR_GET_NO_NEW_PRIVS => cur.no_new_privs.load(Ordering::Acquire) as i64,
        PR_SET_KEEPCAPS => {
            if args.a1 > 1 { return -(Errno::Einval.as_i32() as i64); }
            let old = cur.creds.securebits.load(Ordering::Acquire);
            if (old & crate::task::creds::securebits::SECBIT_KEEP_CAPS_LOCKED) != 0 {
                return -(Errno::Eperm.as_i32() as i64);
            }
            let new = if args.a1 != 0 {
                old | crate::task::creds::securebits::SECBIT_KEEP_CAPS
            } else {
                old & !crate::task::creds::securebits::SECBIT_KEEP_CAPS
            };
            cur.creds.securebits.store(new, Ordering::Release);
            0
        }
        PR_GET_KEEPCAPS => ((cur.creds.securebits.load(Ordering::Acquire)
            & crate::task::creds::securebits::SECBIT_KEEP_CAPS) != 0) as i64,
        PR_SET_PDEATHSIG => {
            let sig = args.a1 as u32;
            if sig > 64 { return -(Errno::Einval.as_i32() as i64); }
            cur.pdeathsig.store(sig, Ordering::Release);
            0
        }
        PR_GET_PDEATHSIG => {
            let p = args.a1;
            let v = cur.pdeathsig.load(Ordering::Acquire);
            if p != 0 && p < hal::USER_VA_END {
                // SAFETY: p validated < USER_VA_END; CPL=0 i32 write through caller's AS at the prctl-ABI specified pointer.
                unsafe { core::ptr::write_volatile(p as *mut i32, v as i32); }
            }
            0
        }
        PR_SET_CHILD_SUBREAPER => {
            cur.child_subreaper.store(args.a1 != 0, Ordering::Release);
            0
        }
        PR_GET_CHILD_SUBREAPER => {
            let p = args.a1;
            let v = cur.child_subreaper.load(Ordering::Acquire);
            if p != 0 && p < hal::USER_VA_END {
                // SAFETY: p validated < USER_VA_END; CPL=0 i32 write through caller's AS at the prctl-ABI specified pointer.
                unsafe { core::ptr::write_volatile(p as *mut i32, v as i32); }
            }
            0
        }
        PR_CAPBSET_READ => {
            let cap = args.a1;
            if cap >= 64 { return -(Errno::Einval.as_i32() as i64); }
            ((cur.creds.cap_bounding.load(Ordering::Acquire) >> cap) & 1) as i64
        }
        PR_CAPBSET_DROP => {
            let cap = args.a1;
            if cap >= 64 { return -(Errno::Einval.as_i32() as i64); }
            if !cur.has_cap(crate::cap::SETPCAP) { return -(Errno::Eperm.as_i32() as i64); }
            let mask = !(1u64 << cap);
            cur.creds.cap_bounding.fetch_and(mask, Ordering::AcqRel);
            0
        }
        PR_GET_SECCOMP => {
            // SAFETY: running task on this CPU; preempt-off; sole reader/writer of seccomp_filters per `13§5`.
            let n = unsafe { (*cur.seccomp_filters.get()).len() };
            if n == 0 { 0 } else { 2 } // 0 = SECCOMP_MODE_DISABLED, 2 = SECCOMP_MODE_FILTER
        }
        PR_SET_SECCOMP => {
            // Modern programs use the seccomp(2) syscall directly; this
            // legacy entry stays EINVAL for now.
            -(Errno::Einval.as_i32() as i64)
        }
        // securebits round-trip. systemd applies per-service securebits in
        // its exec child; an EINVAL here aborts the spawn at step SECUREBITS.
        PR_SET_SECUREBITS => {
            if args.a1 > u32::MAX as u64 {
                return -(Errno::Eperm.as_i32() as i64);
            }
            let requested = args.a1 as u32;
            let old = cur.creds.securebits.load(Ordering::Acquire);
            if !crate::task::creds::securebits::replacement_is_allowed(old, requested) {
                return -(Errno::Eperm.as_i32() as i64);
            }
            if !cur.has_cap(crate::cap::SETPCAP) {
                return -(Errno::Eperm.as_i32() as i64);
            }
            cur.creds.securebits.store(requested, Ordering::Release);
            0
        }
        PR_GET_SECUREBITS => cur.creds.securebits.load(Ordering::Acquire) as i64,
        // PR_CAP_AMBIENT(arg2=sub, arg3=cap): manage the per-task ambient
        // capability set. systemd's exec path always calls CLEAR_ALL when
        // applying a service's ambient set — an EINVAL here aborts every
        // service spawn ("Failed to apply the starting ambient set").
        PR_CAP_AMBIENT => {
            match args.a1 {
                PR_CAP_AMBIENT_CLEAR_ALL => {
                    if args.a2 != 0 || args.a3 != 0 || args.a4 != 0 {
                        return -(Errno::Einval.as_i32() as i64);
                    }
                    cur.creds.cap_ambient.store(0, Ordering::Release);
                    0
                }
                PR_CAP_AMBIENT_IS_SET | PR_CAP_AMBIENT_RAISE | PR_CAP_AMBIENT_LOWER => {
                    let cap = args.a2;
                    if cap >= 64 || args.a3 != 0 || args.a4 != 0 {
                        return -(Errno::Einval.as_i32() as i64);
                    }
                    let bit = 1u64 << cap;
                    match args.a1 {
                        PR_CAP_AMBIENT_IS_SET =>
                            ((cur.creds.cap_ambient.load(Ordering::Acquire) >> cap) & 1) as i64,
                        PR_CAP_AMBIENT_RAISE => {
                            // Linux: the cap must be in BOTH permitted and
                            // inheritable, and SECBIT_NO_CAP_AMBIENT_RAISE
                            // must be clear, else EPERM.
                            let perm = cur.creds.cap_permitted.load(Ordering::Acquire);
                            let inh  = cur.creds.cap_inheritable.load(Ordering::Acquire);
                            let securebits = cur.creds.securebits.load(Ordering::Acquire);
                            if (perm & bit) == 0 || (inh & bit) == 0
                                || (securebits & crate::task::creds::securebits::SECBIT_NO_CAP_AMBIENT_RAISE) != 0 {
                                return -(Errno::Eperm.as_i32() as i64);
                            }
                            cur.creds.cap_ambient.fetch_or(bit, Ordering::AcqRel);
                            0
                        }
                        _ /* LOWER */ => {
                            cur.creds.cap_ambient.fetch_and(!bit, Ordering::AcqRel);
                            0
                        }
                    }
                }
                _ => -(Errno::Einval.as_i32() as i64),
            }
        }
        // PR_SET_MM(arg2=opt, arg3=addr, arg4=len): rewrite this mm's
        // argv/env/stack/code/data/brk layout under CAP_SYS_RESOURCE.
        // systemd sets ARG_START/ARG_END (or PR_SET_MM_MAP) so
        // /proc/self/{cmdline,environ,stat} reflect its relabeled layout.
        PR_SET_MM => crate::prctl_set_mm::sys_set_mm(cur, args),
        PR_SET_VMA => crate::prctl_vma::sys_set_vma_name(cur, args),
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
