// Kernel-side effects for `clock_policy::ClockOps`: real user memory, the real
// timekeeper, the real capability set. All sequencing lives in `clock_policy`.
#![cfg(target_os = "oxide-kernel")]

use sched::posix_clock::ClockSpec;
use syscall::errno::Errno;

use crate::clock_policy::ClockOps;
use crate::time_common::current_ns_for_clock;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

const TIMESPEC_SIZE: u64 = 16;

/// Errno carried back out of `userbuf`'s already-negated return value.
fn errno_of(rv: i64) -> Errno {
    if rv == -(Errno::Efault.as_i32() as i64) { Errno::Efault } else { Errno::Einval }
}

pub struct KernelClockOps;

impl ClockOps for KernelClockOps {
    fn read_timespec(&mut self, ptr: u64) -> Result<(i64, i64), Errno> {
        validate_user_buf(ptr, TIMESPEC_SIZE, 1).map_err(errno_of)?;
        // SAFETY: ptr validated as readable 16-byte timespec storage.
        Ok(unsafe {
            (core::ptr::read_unaligned(ptr as *const i64),
             core::ptr::read_unaligned((ptr + 8) as *const i64))
        })
    }

    fn write_timespec(&mut self, ptr: u64, sec: u64, nsec: u64) -> Result<(), Errno> {
        validate_user_buf_writable(ptr, TIMESPEC_SIZE, 1).map_err(errno_of)?;
        // SAFETY: ptr validated writable for one 16-byte timespec result.
        unsafe {
            core::ptr::write_unaligned(ptr as *mut u64, sec);
            core::ptr::write_unaligned((ptr + 8) as *mut u64, nsec);
        }
        Ok(())
    }

    fn sample_ns(&mut self, clk_id: u64, _clock: ClockSpec) -> Result<u64, Errno> {
        current_ns_for_clock(clk_id)
    }

    fn cpu_clock_valid(&mut self, clock: ClockSpec) -> bool {
        match sched::live::current() {
            Some(current) => sched::timers::cpu_clock_valid(current, clock),
            None => false,
        }
    }

    fn may_set_time(&mut self) -> bool {
        sched::live::current().map(|c| c.has_cap(sched::cap::SYS_TIME)).unwrap_or(false)
    }

    fn set_realtime(&mut self, ns: u64) {
        timekeeper::set_realtime(ns);
        // Absolute CLOCK_REALTIME/TAI deadlines are stored against the wall
        // clock, so they must be reprojected the moment it moves.
        sched::timers::clock_was_set();
    }
}
