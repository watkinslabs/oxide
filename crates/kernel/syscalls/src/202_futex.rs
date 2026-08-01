// 202 futex — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
use syscall::SyscallArgs;

/// `sys_futex(uaddr, op, val, ts, uaddr2, val3)` — slot 202.
/// Delegates to `::ipc::live::futex` which keeps a per-(mm_root_pa, va)
/// in-kernel wait queue. Supported ops: FUTEX_WAIT/FUTEX_WAIT_BITSET (park
/// until FUTEX_WAKE or the timeout), FUTEX_WAKE/FUTEX_WAKE_BITSET.
///
/// `ts` (a3) is the timeout: RELATIVE for FUTEX_WAIT, ABSOLUTE for
/// FUTEX_WAIT_BITSET. Honored here as a monotonic deadline so timeout-only
/// waits (pthread_cond_timedwait, sem_timedwait) wake on expiry with
/// ETIMEDOUT instead of hanging forever — the bug that wedged early systemd
/// services. `FUTEX_PRIVATE_FLAG`/`FUTEX_CLOCK_REALTIME` masks are accepted
/// (v1 process-private + monotonic clock).
/// # C: O(W) waiters per WAKE, O(1) WAIT
pub fn sys_futex(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use syscall::errno::Errno;
    const FUTEX_WAIT: u32 = 0;
    const FUTEX_WAIT_BITSET: u32 = 9;
    const FUTEX_WAKE_BITSET: u32 = 10;
    const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
    const FUTEX_LOCK_PI2: u32 = 13;
    use ::ipc::live::futex::{FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK, FUTEX_BITSET_MATCH_ANY};
    let op = args.a1 as u32;
    let op_base = op & FUTEX_CMD_MASK;

    // Linux `do_futex`: FUTEX_CLOCK_REALTIME is only valid paired with
    // FUTEX_WAIT_BITSET / FUTEX_WAIT_REQUEUE_PI / FUTEX_LOCK_PI2 — any other
    // cmd (in particular plain FUTEX_WAIT) returns -ENOSYS. Previously this
    // was never checked, so FUTEX_WAIT|FUTEX_CLOCK_REALTIME silently behaved
    // as a monotonic-relative wait instead of being rejected.
    if (op & FUTEX_CLOCK_REALTIME) != 0
        && op_base != FUTEX_WAIT_BITSET && op_base != FUTEX_WAIT_REQUEUE_PI && op_base != FUTEX_LOCK_PI2 {
        return -(Errno::Enosys.as_i32() as i64);
    }

    // REQUEUE/CMP_REQUEUE/WAKE_OP operate on TWO futex words and carry their
    // operands in a3/a4/a5 (uaddr2 = a4). Previously these fell through the
    // futex dispatch's `_ => 0` no-op, so glibc condvar broadcast / requeue and
    // WAKE_OP fast paths silently did nothing → waiters never moved/woken
    // (deadlock). Wire them to the real implementations (Linux semantics).
    const FUTEX_REQUEUE: u32 = 3;
    const FUTEX_CMP_REQUEUE: u32 = 4;
    const FUTEX_WAKE_OP: u32 = 5;
    const FUTEX_CMP_REQUEUE_PI: u32 = 12;
    let private = (op & ::ipc::live::futex::FUTEX_PRIVATE_FLAG) != 0;
    // `val`/`val2` are `int` in the ABI; a negative count is EINVAL, decided by
    // the work fns. `a2`/`a3` are sign-extended here rather than truncated to a
    // count type, so `-1` cannot become an unbounded wake.
    let (val_i, val2_i) = (args.a2 as i32 as i64, args.a3 as i32 as i64);
    match op_base {
        FUTEX_REQUEUE => {
            return ::ipc::live::futex::requeue(args.a0, args.a4, val_i, val2_i, private);
        }
        FUTEX_CMP_REQUEUE => {
            return ::ipc::live::futex::cmp_requeue(
                args.a0, args.a4, val_i, val2_i, args.a5 as u32, private);
        }
        FUTEX_WAKE_OP => {
            return ::ipc::live::futex::wake_op(
                args.a0, args.a4, val_i, val2_i, args.a5 as u32, private);
        }
        FUTEX_CMP_REQUEUE_PI => {
            return ::ipc::live::futex::cmp_requeue_pi(
                args.a0, args.a4, val_i, val2_i, args.a5 as u32, private);
        }
        _ => {}
    }
    // `val3` (a5) is the wake bitset for the BITSET ops; Linux forces
    // FUTEX_BITSET_MATCH_ANY for the plain (non-BITSET) ops regardless of
    // whatever garbage a caller left in that register.
    let bitset = if op_base == FUTEX_WAIT_BITSET || op_base == FUTEX_WAKE_BITSET {
        args.a5 as u32
    } else {
        FUTEX_BITSET_MATCH_ANY
    };

    // Linux `futex_cmd_has_timeout`: only these five commands read `utime` as a
    // timespec at all. Every other command reuses that register as a plain
    // integer operand (`val2`), so dereferencing it would be a wild read.
    const FUTEX_LOCK_PI: u32 = 6;
    let has_timeout = matches!(op_base,
        FUTEX_WAIT | FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI);
    // `FUTEX_LOCK_PI`'s timeout is ABSOLUTE `CLOCK_REALTIME` — `do_futex` sets
    // the realtime flag for it unconditionally and falls through to
    // `FUTEX_LOCK_PI2`, whose timeout is absolute `CLOCK_MONOTONIC` unless the
    // caller asked for realtime. Treating `FUTEX_LOCK_PI`'s as relative (the
    // shape the plain `FUTEX_WAIT` path uses) would give a `pthread_mutex_timedlock`
    // on a PI mutex a deadline decades in the future.
    let clock_realtime = (op & FUTEX_CLOCK_REALTIME) != 0 || op_base == FUTEX_LOCK_PI;
    let ts = args.a3;
    let deadline_ns = if has_timeout && ts != 0 && ts < hal::USER_VA_END {
        // SAFETY: ts validated < USER_VA_END; timespec is 2×i64 at +0/+8 in
        // the caller's AS; CPL=0 reads via active CR3.
        let secs = unsafe { core::ptr::read_volatile(ts as *const i64) };
        // SAFETY: same validated range; tv_nsec at +8.
        let nsec = unsafe { core::ptr::read_volatile((ts + 8) as *const i64) };
        // `ktime_set`-clamped decode (`syscall::time::timespec_to_ns`): a
        // FUTEX_WAIT_BITSET absolute timespec with a huge-but-valid tv_sec
        // clamps to KTIME_MAX_NS instead of installing an unbounded
        // wakeup_deadline_ns the deadline scanner can never reach.
        let t = match ::syscall::time::timespec_to_ns(secs, nsec) {
            Ok(ns) => ns,
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        // FUTEX_WAIT timeout is relative; FUTEX_WAIT_BITSET is absolute.
        // `.max(1)` keeps 0 reserved for "no timeout".
        if op_base == FUTEX_WAIT {
            now.saturating_add(t).max(1)
        } else if !clock_realtime {
            match crate::time_common::current_sleep_target_to_host(
                crate::time_common::CLOCK_MONOTONIC, true, t)
            {
                Ok(host) => host.max(1),
                Err(_) => return -(Errno::Eio.as_i32() as i64),
            }
        } else {
            let now_realtime = crate::time_common::ns_for_clock(
                crate::time_common::CLOCK_REALTIME);
            if t <= now_realtime { now.max(1) }
            else { now.saturating_add(t - now_realtime).max(1) }
        }
    } else {
        0
    };
    // debug-ustack: on a FUTEX_WAIT by gdm-session-worker against a STACK
    // address (a GCond/join/barrier — the greeter deadlock), dump the user
    // return-address chain so the exact glibc/GLib/gdm call site that never
    // wakes can be symbolized offline (objdump of the stripped PIE). Equivalent
    // to a gdb backtrace of the parked thread, but captured in the worker's own
    // context (its CR3 is live) where the user stack is directly readable.
    // Its own feature, not `debug-boot`: this walks up to 80 user stack words
    // and emits a line per plausible code address, on EVERY `FUTEX_WAIT`
    // against a stack address — and pays a `with_exe_path` lock + substring
    // scan even when the caller is not the traced process.
    #[cfg(all(feature = "debug-ustack", target_arch = "x86_64"))]
    if (op_base == FUTEX_WAIT || op_base == FUTEX_WAIT_BITSET) && args.a0 >= 0x7fff_0000_0000 {
        let is_worker = sched::live::current()
            .map(|c| c.with_exe_path(|p| p.map(|s| s.ends_with("gdm-session-worker")).unwrap_or(false)))
            .unwrap_or(false);
        if is_worker {
            // SAFETY: dispatch context; current_pt_regs() is THIS task's live
            // syscall entry frame on its kernel stack (hal-x86_64 pt_regs.rs).
            let ff = hal_x86_64::current_pt_regs();
            // SAFETY: null-checked; a non-null `current_pt_regs` is THIS task's
            // live syscall entry frame on its own kernel stack.
            let user_rip = if ff.is_null() { 0 } else { unsafe { (*ff).rip } };
            // SAFETY: same null-checked live entry frame as the line above.
            let user_rsp = if ff.is_null() { 0 } else { unsafe { (*ff).rsp } };
            // DIAG: read the cond word ourselves via the same read_volatile the
            // futex uses — if this != val the read path is broken in this ctx.
            let condw = { let mut b = [0u8; 8];
                if uaccess::copy_from_user(&mut b, args.a0).is_err() { b = [0u8; 8]; }
                u64::from_ne_bytes(b) };
            klog::write_raw(b"[USTACK uaddr="); klog::write_hex_u64(args.a0);
            klog::write_raw(b" rip="); klog::write_hex_u64(user_rip);
            klog::write_raw(b" rsp="); klog::write_hex_u64(user_rsp);
            klog::write_raw(b" condw="); klog::write_hex_u64(condw);
            klog::write_raw(b" ubound="); klog::write_hex_u64(hal::USER_VA_END);
            klog::write_raw(b"]\n");
            // For each stack word that is a plausible CODE address (the PIE
            // .text or a shared-lib mmap), resolve its VMA so the lib base
            // (vma.start) + backing inode are known → offline symbolization.
            let cur_task = sched::live::current();
            // SAFETY: `mm_ref` needs no concurrent execve replacing the mm; this
            // is the CURRENT task's own slot, read inside its own futex syscall.
            let mm = cur_task.as_ref().and_then(|c| unsafe { c.mm_ref() });
            let mut i = 0u64;
            while i < 80 {
                let a = user_rsp.wrapping_add(i * 8);
                if a >= hal::USER_VA_END { break; }
                // A user stack slot may be unmapped; the uaccess path faults to
                // EFAULT rather than taking a kernel #PF on a raw dereference.
                let w = { let mut b = [0u8; 8];
                    if uaccess::copy_from_user(&mut b, a).is_err() { break; }
                    u64::from_ne_bytes(b) };
                let is_code = (w >= 0x1_0000 && w < 0x2000_0000)
                    || (w >= 0x7f00_0000_0000 && w < 0x8000_0000_0000);
                if is_code {
                    klog::write_raw(b"  +"); klog::write_dec_u64(i * 8);
                    klog::write_raw(b" a="); klog::write_hex_u64(w);
                    if let Some(m) = mm {
                        if let Some(v) = hal::UserVirtAddr::new(w).and_then(|u| m.find_vma(u)) {
                            klog::write_raw(b" base="); klog::write_hex_u64(v.start.as_u64());
                            klog::write_raw(b" off="); klog::write_hex_u64(w - v.start.as_u64());
                            match &v.backing {
                                vmm::VmaBacking::File { backing, .. } => {
                                    klog::write_raw(b" ino="); klog::write_dec_u64(backing.ino());
                                }
                                _ => klog::write_raw(b" anon"),
                            }
                        }
                    }
                    klog::write_raw(b"\n");
                }
                i += 1;
            }
        }
    }
    // `FUTEX_WAIT_REQUEUE_PI` takes a SECOND futex address (uaddr2 = a4) and so
    // cannot go through the single-address dispatch. `do_futex` forces its
    // bitset to match-any before the call.
    if op_base == FUTEX_WAIT_REQUEUE_PI {
        return ::ipc::live::futex::wait_requeue_pi(
            args.a0, args.a2 as u32, FUTEX_BITSET_MATCH_ANY, args.a4, private, deadline_ns);
    }
    ::ipc::live::futex::dispatch_timed(args.a0, op, args.a2 as u32, bitset, deadline_ns)
}
