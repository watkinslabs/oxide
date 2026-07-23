use alloc::sync::Arc;

use sched::{Task, TaskState};
use syscall::errno::Errno;

use super::core::{
    FUTEX_OP_MASK, FUTEX_PRIVATE_FLAG, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE, FUTEX_WAKE_BITSET, WAITERS,
    Waiter, current_key, load_user_u32, remove_waiter, wake_key,
};

/// debug-futextrace: true iff the current task's process is gdm-session-worker
/// (all its threads share the exe path, so this catches the main thread AND the
/// gdbus/gmain helper threads involved in the greeter pthread deadlock).
#[cfg(feature = "debug-futextrace")]
fn ftx_target_exe() -> bool {
    // gdm + the glib D-Bus services that block gdm's start (they hang while
    // acquiring their bus name — main thread parks in futex). Trace their
    // FTX-WAIT/WAKE to see whether the wake is lost.
    sched::live::current()
        .map(|c| c.with_exe_path(|p| p.map(|s|
            s.contains("gdm") || s.contains("switcheroo") || s.contains("accounts-daemon")
            || s.contains("polkit") || s.contains("upower")).unwrap_or(false)))
        .unwrap_or(false)
}

/// Back-compat shim for callers without a timeout (deadline 0 = block forever).
/// # C: O(W) waiters per WAKE; O(1) WAIT
pub fn dispatch(uaddr: u64, op_full: u32, val: u32) -> i64 {
    dispatch_timed(uaddr, op_full, val, 0)
}

/// `dispatch` + absolute monotonic deadline (ns). `deadline_ns == 0` means no
/// timeout. FUTEX_WAIT/FUTEX_WAIT_BITSET park with the deadline so a timed wait
/// (glibc pthread_cond_timedwait / sem_timedwait / any timeout-only futex)
/// actually wakes on expiry and returns ETIMEDOUT instead of hanging forever.
/// # C: O(W) waiters per WAKE; O(1) WAIT
pub fn dispatch_timed(uaddr: u64, op_full: u32, val: u32, deadline_ns: u64) -> i64 {
    if uaddr == 0 || uaddr >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if (uaddr & 0x3) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let private = (op_full & FUTEX_PRIVATE_FLAG) != 0;
    match op_full & FUTEX_OP_MASK {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            // SAFETY: bounded user VA validated above; CR3 is current's.
            let cur_val = unsafe { load_user_u32(uaddr) };
            if cur_val != val { return -(Errno::Eagain.as_i32() as i64); }
            #[cfg(feature = "debug-displaystack")]
            if uaddr >= 0x7fff_0000_0000 {
                let nm = sched::live::current()
                    .and_then(|c| c.exe_path())
                    .unwrap_or_default();
                klog::write_raw(b"[futex park] uaddr="); klog::write_hex_u64(uaddr);
                klog::write_raw(b" val="); klog::write_dec_u64(val as u64);
                klog::write_raw(b" exe="); klog::write_raw(nm.as_bytes());
                klog::write_raw(b"\n");
            }
            let key = match current_key(uaddr, private) {
                Some(k) => k, None => return -(Errno::Einval.as_i32() as i64),
            };
            let cur = match sched::live::current() {
                Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
            };
            let tid = cur.tid;
            #[cfg(feature = "debug-mount")]
            if (uaddr & !0xfff) == 0x7ffffe88d000 {
                let mut vstart: u64 = 0;
                let mut voff: u64 = 0;
                let mut vprot: u8 = 0;
                let mut vino: u64 = 0;
                let (kind, foff): (&str, u64) = match unsafe { cur.mm_ref() } {
                    None => ("NOMM", 0),
                    // SAFETY: single-mutator mm slot per 13§5.
                    Some(mm) => match hal::UserVirtAddr::new(uaddr).and_then(|u| mm.find_vma(u)) {
                        None => ("NOVMA", 0),
                        Some(v) => {
                            vstart = v.start.as_u64();
                            vprot = v.prot.bits();
                            match &v.backing {
                                vmm::VmaBacking::File { off, backing } => { voff = *off; vino = backing.ino();
                                    ("File", off.wrapping_add(uaddr - v.start.as_u64())) }
                                vmm::VmaBacking::KernelBytes { off, .. } => { voff = *off as u64;
                                    ("KernelBytes", (*off as u64).wrapping_add(uaddr - v.start.as_u64())) }
                                vmm::VmaBacking::Anonymous => ("Anon", 0),
                                _ => ("Other", 0),
                            }
                        }
                    },
                };
                let root = unsafe { cur.mm_ref() }.map(|m| m.root_pa()).unwrap_or(0);
                klog::write_raw(b"[mnt] FUTEXWAIT root=");
                klog::write_hex_u64(root);
                klog::write_raw(b" op=");
                klog::write_hex_u64((op_full & FUTEX_OP_MASK) as u64);
                klog::write_raw(b" dl=");
                klog::write_hex_u64(deadline_ns);
                klog::write_raw(b" uaddr=");
                klog::write_hex_u64(uaddr);
                klog::write_raw(b" val=");
                klog::write_dec_u64(val as u64);
                klog::write_raw(b" backing=");
                klog::write_raw(kind.as_bytes());
                klog::write_raw(b" foff=");
                klog::write_hex_u64(foff);
                klog::write_raw(b" vstart=");
                klog::write_hex_u64(vstart);
                klog::write_raw(b" voff=");
                klog::write_hex_u64(voff);
                klog::write_raw(b" prot=");
                klog::write_hex_u64(vprot as u64);
                klog::write_raw(b" ino=");
                klog::write_dec_u64(vino);
                klog::write_raw(b" fpa=");
                {
                    use hal::{MmuOps, Va};
                    #[cfg(target_arch = "x86_64")]
                    let fpa = hal_x86_64::mmu_ops::X86Mmu::translate(Va(uaddr)).map(|(p, _)| p.0 & !0xfff).unwrap_or(0);
                    #[cfg(target_arch = "aarch64")]
                    let fpa = hal_aarch64::mmu_ops::ArmMmu::translate(Va(uaddr)).map(|(p, _)| p.0 & !0xfff).unwrap_or(0);
                    klog::write_hex_u64(fpa);
                }
                klog::write_raw(b" ctx=");
                let base = uaddr & !0xf;
                for i in 0..8u64 {
                    // SAFETY: same page as the validated futex word; CR3 current's.
                    let w = unsafe { load_user_u32(base.wrapping_add(i * 4)) };
                    klog::write_hex_u64(w as u64);
                    klog::write_raw(b",");
                }
                klog::write_raw(b"\n");
            }
            if deadline_ns != 0 {
                cur.wakeup_deadline_ns.store(deadline_ns, core::sync::atomic::Ordering::Release);
            }
            let raw = cur as *const Task;
            // SAFETY: cur came from sched::current() and is the running task on this CPU; bumping the strong count is sound.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: matching Arc::from_raw consumes the bumped ref.
            let arc = unsafe { Arc::from_raw(raw) };
            {
                let mut w = WAITERS.lock();
                // SAFETY: bounded user VA validated above; CR3 is the caller's.
                if unsafe { load_user_u32(uaddr) } != val {
                    drop(w);
                    drop(arc);
                    cur.wakeup_deadline_ns.store(0, core::sync::atomic::Ordering::Release);
                    return -(Errno::Eagain.as_i32() as i64);
                }
                arc.set_state(TaskState::Sleeping);
                cur.futex_uaddr.store(uaddr, core::sync::atomic::Ordering::Relaxed);
                w.push(Waiter { key, task: arc });
            }
            #[cfg(feature = "debug-futextrace")]
            if ftx_target_exe() {
                klog::write_raw(b"[FTX-WAIT tgid="); klog::write_dec_u64(sched::live::current().map(|c| c.tgid.load(core::sync::atomic::Ordering::Relaxed)).unwrap_or(0) as u64);
                klog::write_raw(b" tid="); klog::write_dec_u64(tid as u64);
                klog::write_raw(b" uaddr="); klog::write_hex_u64(uaddr);
                klog::write_raw(b" val="); klog::write_dec_u64(val as u64);
                klog::write_raw(b"] park\n");
            }
            // SAFETY: process ctx; runqueue installed; preempt-off.
            unsafe { sched::live::schedule(); }
            cur.futex_uaddr.store(0, core::sync::atomic::Ordering::Relaxed);
            cur.wakeup_deadline_ns.store(0, core::sync::atomic::Ordering::Release);
            if remove_waiter(tid) && deadline_ns != 0 {
                return -(Errno::Etimedout.as_i32() as i64);
            }
            0
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let key = match current_key(uaddr, private) {
                Some(k) => k, None => return -(Errno::Einval.as_i32() as i64),
            };
            let n = wake_key(key, val as usize);
            #[cfg(feature = "debug-futextrace")]
            if ftx_target_exe() {
                let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
                klog::write_raw(b"[FTX-WAKE tgid="); klog::write_dec_u64(sched::live::current().map(|c| c.tgid.load(core::sync::atomic::Ordering::Relaxed)).unwrap_or(0) as u64);
                klog::write_raw(b" tid="); klog::write_dec_u64(tid as u64);
                klog::write_raw(b" uaddr="); klog::write_hex_u64(uaddr);
                klog::write_raw(b" want="); klog::write_dec_u64(val as u64);
                klog::write_raw(b" woke="); klog::write_dec_u64(n as u64);
                klog::write_raw(b"]\n");
            }
            #[cfg(feature = "debug-mount")]
            if (uaddr & !0xfff) == 0x7ffffe88d000 {
                let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
                klog::write_raw(b"[mnt] FUTEXWAKE uaddr=");
                klog::write_hex_u64(uaddr);
                klog::write_raw(b" woke=");
                klog::write_dec_u64(n as u64);
                klog::write_raw(b" by_tid=");
                klog::write_dec_u64(tid as u64);
                klog::write_raw(b"\n");
            }
            n as i64
        }
        _ => 0,
    }
}
