// 314 sched_setattr — one syscall, one file (docs/53 §0).
// sched_setattr(pid, attr, flags): set policy + priority + nice. Thin shim:
// the policy/priority/permission rules are `crate::sched_policy` (Linux
// `__sched_setscheduler`), shared verbatim with slots 142/144.
#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};
use crate::sched_policy;
use crate::userbuf::validate_user_buf;

/// Linux `SCHED_ATTR_SIZE_VER0`.
const SCHED_ATTR_MIN_SIZE: u64 = 48;
/// Linux caps `attr->size` at `PAGE_SIZE` in `sched_copy_attr`.
const SCHED_ATTR_MAX_SIZE: u64 = 4096;
// struct sched_attr field offsets (uapi).
const SA_OFF_SIZE: u64 = 0;
const SA_OFF_POLICY: u64 = 4;
const SA_OFF_FLAGS: u64 = 8;
const SA_OFF_NICE: u64 = 16;
const SA_OFF_PRIORITY: u64 = 20;
const SA_OFF_RUNTIME: u64 = 24;
const SA_OFF_DEADLINE: u64 = 32;
const SA_OFF_PERIOD: u64 = 40;

/// Linux `SCHED_FLAG_RESET_ON_FORK`.
const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
/// Linux `SCHED_FLAG_KEEP_POLICY`.
const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
/// Linux `SCHED_FLAG_ALL` minus the clamp/DL bits this scheduler has no state
/// for; anything outside it is EINVAL exactly as Linux rejects unknown flags.
const SCHED_FLAG_SUPPORTED: u64 = SCHED_FLAG_RESET_ON_FORK | SCHED_FLAG_KEEP_POLICY;

/// `sys_sched_setattr(pid, attr, flags)` — slot 314.
/// # C: O(log N) requeue
pub fn sys_sched_setattr(args: &SyscallArgs) -> i64 {
    let uattr = args.a1;
    if uattr == 0 || args.a2 != 0 { return -(Errno::Einval.as_i32() as i64); }
    let pid = match sched_policy::pid_arg(args.a0) { Ok(v) => v, Err(rv) => return rv };
    if let Err(rv) = validate_user_buf(uattr, SCHED_ATTR_MIN_SIZE, 1) { return rv; }
    // SAFETY: uattr validated readable for the fixed 48-byte sched_attr prefix.
    let (size, policy, flags, nice, prio, runtime, deadline, period) = unsafe {
        (core::ptr::read_unaligned((uattr + SA_OFF_SIZE) as *const u32),
         core::ptr::read_unaligned((uattr + SA_OFF_POLICY) as *const u32),
         core::ptr::read_unaligned((uattr + SA_OFF_FLAGS) as *const u64),
         core::ptr::read_unaligned((uattr + SA_OFF_NICE) as *const i32),
         core::ptr::read_unaligned((uattr + SA_OFF_PRIORITY) as *const u32),
         core::ptr::read_unaligned((uattr + SA_OFF_RUNTIME) as *const u64),
         core::ptr::read_unaligned((uattr + SA_OFF_DEADLINE) as *const u64),
         core::ptr::read_unaligned((uattr + SA_OFF_PERIOD) as *const u64))
    };
    // Linux `sched_copy_attr` ABI quirk: size 0 means SCHED_ATTR_SIZE_VER0.
    // Out-of-range sizes are E2BIG with the kernel's own size written back.
    let size = if size == 0 { SCHED_ATTR_MIN_SIZE as u32 } else { size };
    if (size as u64) < SCHED_ATTR_MIN_SIZE || size as u64 > SCHED_ATTR_MAX_SIZE {
        if crate::userbuf::validate_user_buf_writable(uattr, 4, 1).is_ok() {
            // SAFETY: uattr just validated writable for its leading u32 `size` field, which Linux's err_size path overwrites with the kernel's own sched_attr size.
            unsafe { core::ptr::write_unaligned((uattr + SA_OFF_SIZE) as *mut u32, SCHED_ATTR_MIN_SIZE as u32); }
        }
        return -(Errno::E2big.as_i32() as i64);
    }
    if flags & !SCHED_FLAG_SUPPORTED != 0 { return -(Errno::Einval.as_i32() as i64); }
    if (policy as i32) < 0 { return -(Errno::Einval.as_i32() as i64); }
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else { sched::live::registry::resolve_user_pid(pid) };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    let caller = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    // Linux folds SCHED_FLAG_KEEP_POLICY onto SETPARAM_POLICY and carries
    // SCHED_FLAG_RESET_ON_FORK the same way slot 144 carries the ORed bit.
    let policy_arg = if flags & SCHED_FLAG_KEEP_POLICY != 0 {
        sched_policy::SETPARAM_POLICY
    } else if flags & SCHED_FLAG_RESET_ON_FORK != 0 {
        (policy | sched_policy::SCHED_RESET_ON_FORK) as i32
    } else {
        policy as i32
    };
    let dl_ok = sched_policy::checkparam_dl(runtime, deadline, period);
    sched_policy::setscheduler(caller, &t, policy_arg, prio as i32,
                               sched::rlimit::clamp_nice(nice) as i32, dl_ok)
}
