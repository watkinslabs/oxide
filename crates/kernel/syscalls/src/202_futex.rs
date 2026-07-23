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
    const FUTEX_CLOCK_REALTIME: u32 = 0x100;
    let op = args.a1 as u32;
    let op_base = op & 0x7f;

    // REQUEUE/CMP_REQUEUE/WAKE_OP operate on TWO futex words and carry their
    // operands in a3/a4/a5 (uaddr2 = a4). Previously these fell through the
    // futex dispatch's `_ => 0` no-op, so glibc condvar broadcast / requeue and
    // WAKE_OP fast paths silently did nothing → waiters never moved/woken
    // (deadlock). Wire them to the real implementations (Linux semantics).
    const FUTEX_REQUEUE: u32 = 3;
    const FUTEX_CMP_REQUEUE: u32 = 4;
    const FUTEX_WAKE_OP: u32 = 5;
    let private = (op & ::ipc::live::futex::FUTEX_PRIVATE_FLAG) != 0;
    match op_base {
        FUTEX_REQUEUE => {
            return ::ipc::live::futex::requeue(args.a0, args.a4, args.a2 as usize, args.a3 as usize, private);
        }
        FUTEX_CMP_REQUEUE => {
            return ::ipc::live::futex::cmp_requeue(
                args.a0, args.a4, args.a2 as usize, args.a3 as usize, args.a5 as u32, private);
        }
        FUTEX_WAKE_OP => {
            return ::ipc::live::futex::wake_op(
                args.a0, args.a4, args.a2 as usize, args.a3 as usize, args.a5 as u32, private);
        }
        _ => {}
    }

    let ts = args.a3;
    let deadline_ns = if (op_base == FUTEX_WAIT || op_base == FUTEX_WAIT_BITSET)
        && ts != 0 && ts < hal::USER_VA_END
    {
        // SAFETY: ts validated < USER_VA_END; timespec is 2×i64 at +0/+8 in
        // the caller's AS; CPL=0 reads via active CR3.
        let secs = unsafe { core::ptr::read_volatile(ts as *const i64) };
        // SAFETY: same validated range; tv_nsec at +8.
        let nsec = unsafe { core::ptr::read_volatile((ts + 8) as *const i64) };
        if secs < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return -(Errno::Einval.as_i32() as i64);
        }
        let t = (secs as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        // FUTEX_WAIT timeout is relative; FUTEX_WAIT_BITSET is absolute.
        // `.max(1)` keeps 0 reserved for "no timeout".
        if op_base == FUTEX_WAIT {
            now.saturating_add(t).max(1)
        } else if (op & FUTEX_CLOCK_REALTIME) == 0 {
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
    #[cfg(all(feature = "debug-boot", target_arch = "x86_64"))]
    if (op_base == FUTEX_WAIT || op_base == FUTEX_WAIT_BITSET) && args.a0 >= 0x7fff_0000_0000 {
        let is_worker = sched::live::current()
            .map(|c| c.with_exe_path(|p| p.map(|s| s.ends_with("gdm-session-worker")).unwrap_or(false)))
            .unwrap_or(false);
        if is_worker {
            // SAFETY: dispatch context; current_user_full_frame() points at the
            // 15-quadword saved-syscall block on THIS task's kernel stack. The
            // r12 slot (+0x48 = index 9) holds the user RSP, rcx (+0x38 =
            // index 7) the user RIP (see hal-x86_64 syscall.rs layout).
            let ff = unsafe { hal_x86_64::current_user_full_frame() };
            let user_rip = unsafe { *ff.add(7) };
            let user_rsp = unsafe { *ff.add(9) };
            // DIAG: read the cond word ourselves via the same read_volatile the
            // futex uses — if this != val the read path is broken in this ctx.
            let condw = unsafe { core::ptr::read_volatile(args.a0 as *const u64) };
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
            let mm = cur_task.as_ref().and_then(|c| unsafe { c.mm_ref() });
            let mut i = 0u64;
            while i < 80 {
                let a = user_rsp.wrapping_add(i * 8);
                if a >= hal::USER_VA_END { break; }
                let w = unsafe { core::ptr::read_volatile(a as *const u64) };
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
    ::ipc::live::futex::dispatch_timed(args.a0, op, args.a2 as u32, deadline_ns)
}
