// Kernel-side effects for `timex_policy::TimexOps`: real user memory, the real
// NTP state, the real capability set. All sequencing lives in `timex_policy`
// and `timekeeper::ntp`.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use timekeeper::ntp::{self, AdjError, Timex};

use crate::timex_abi::{self, TIMEX_SIZE};
use crate::timex_policy::TimexOps;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// `struct __kernel_timex` alignment: the widest member is `long long`.
const TIMEX_ALIGN: u64 = 8;

/// Errno carried back out of `userbuf`'s already-negated return value.
fn errno_of(rv: i64) -> Errno {
    if rv == -(Errno::Efault.as_i32() as i64) { Errno::Efault } else { Errno::Einval }
}

pub struct KernelTimexOps;

impl TimexOps for KernelTimexOps {
    fn read_timex(&mut self, ptr: u64) -> Result<Timex, Errno> {
        validate_user_buf(ptr, TIMEX_SIZE as u64, TIMEX_ALIGN).map_err(errno_of)?;
        let mut raw = [0u8; TIMEX_SIZE];
        uaccess::copy_from_user(&mut raw, ptr)?;
        Ok(timex_abi::decode(&raw))
    }

    fn write_timex(&mut self, ptr: u64, tx: &Timex) -> Result<(), Errno> {
        validate_user_buf_writable(ptr, TIMEX_SIZE as u64, TIMEX_ALIGN).map_err(errno_of)?;
        uaccess::copy_to_user(ptr, &timex_abi::encode(tx))
    }

    fn may_set_time(&mut self) -> bool {
        sched::live::current().map(|c| c.has_cap(sched::cap::SYS_TIME)).unwrap_or(false)
    }

    fn adjtimex(&mut self, tx: &mut Timex, capable: bool) -> Result<i32, Errno> {
        let outcome = ntp::do_adjtimex(tx, capable).map_err(|e| match e {
            AdjError::Perm => Errno::Eperm,
            AdjError::Inval => Errno::Einval,
        })?;
        if outcome.clock_stepped {
            // ADJ_SETOFFSET and a TAI-offset change both move a wall-domain
            // clock, so absolute CLOCK_REALTIME/TAI deadlines must reproject —
            // the same pairing `clock_settime` and `settimeofday` already do.
            sched::timers::clock_was_set();
        }
        Ok(outcome.state)
    }
}
