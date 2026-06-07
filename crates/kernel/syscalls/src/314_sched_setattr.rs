// 314 sched_setattr — one syscall, one file (docs/53 §0).
// sched_setattr(pid, attr, flags): set policy + priority + nice. Mutates the
// task's SchedClass via the runqueue (dequeue→change→requeue). RT policies
// require privilege; SCHED_DEADLINE is not supported (EOPNOTSUPP).
use core::sync::atomic::Ordering;
use sched::{SchedClass, SchedPolicy};
use syscall::{errno::Errno, SyscallArgs};

const SCHED_OTHER:    u32 = 0;
const SCHED_FIFO:     u32 = 1;
const SCHED_RR:       u32 = 2;
const SCHED_BATCH:    u32 = 3;
const SCHED_IDLE:     u32 = 5;
const SCHED_DEADLINE: u32 = 6;
const SCHED_IDLE_WEIGHT: u32 = 3;   // Linux WEIGHT_IDLEPRIO
const SCHED_ATTR_MIN_SIZE: u64 = 48;
const RT_PRIO_MIN: u32 = 1;
const RT_PRIO_MAX: u32 = 99;
// struct sched_attr field offsets (uapi).
const SA_OFF_SIZE: u64 = 0;
const SA_OFF_POLICY: u64 = 4;
const SA_OFF_NICE: u64 = 16;
const SA_OFF_PRIORITY: u64 = 20;

/// Whether the calling task is privileged (euid 0) — gates RT policy changes.
/// # C: O(1)
pub(crate) fn caller_is_root() -> bool {
    sched::live::current().map(|c| c.creds.euid.load(Ordering::Acquire) == 0).unwrap_or(false)
}

/// `sys_sched_setattr(pid, attr, flags)` — slot 314.
/// # C: O(log N) requeue
pub fn sys_sched_setattr(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    let uattr = args.a1;
    if args.a2 != 0 { return -(Errno::Einval.as_i32() as i64); } // flags
    if uattr == 0 || uattr.saturating_add(SCHED_ATTR_MIN_SIZE) > hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: uattr range-checked for >=48 bytes < USER_VA_END; read the fields.
    let (size, policy, nice, prio) = unsafe {
        (core::ptr::read_unaligned((uattr + SA_OFF_SIZE) as *const u32),
         core::ptr::read_unaligned((uattr + SA_OFF_POLICY) as *const u32),
         core::ptr::read_unaligned((uattr + SA_OFF_NICE) as *const i32),
         core::ptr::read_unaligned((uattr + SA_OFF_PRIORITY) as *const u32))
    };
    if (size as u64) < SCHED_ATTR_MIN_SIZE { return -(Errno::Einval.as_i32() as i64); }
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else { sched::live::registry::lookup(pid) };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };

    let new_class = match policy {
        SCHED_OTHER | SCHED_BATCH => {
            let n = sched::rlimit::clamp_nice(nice);
            let w = sched::cputime::nice_to_weight(n);
            t.nice.store(n, Ordering::Release);
            t.load_weight.store(w, Ordering::Release);
            SchedClass::Normal { weight: w }
        }
        SCHED_IDLE => {
            t.load_weight.store(SCHED_IDLE_WEIGHT, Ordering::Release);
            SchedClass::Normal { weight: SCHED_IDLE_WEIGHT }
        }
        SCHED_FIFO | SCHED_RR => {
            if !(RT_PRIO_MIN..=RT_PRIO_MAX).contains(&prio) { return -(Errno::Einval.as_i32() as i64); }
            if !caller_is_root() { return -(Errno::Eperm.as_i32() as i64); }
            let p = if policy == SCHED_FIFO { SchedPolicy::Fifo } else { SchedPolicy::Rr };
            SchedClass::Rt { prio: prio as u8, policy: p }
        }
        SCHED_DEADLINE => return -(Errno::Eopnotsupp.as_i32() as i64),
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    sched::live::runqueue::set_class(&t, new_class);
    0
}
