use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

extern crate alloc;
extern crate self as hal;
extern crate self as hal_x86_64;
extern crate self as ipc;

pub const USER_VA_END: u64 = u64::MAX;

pub struct MonotonicNs(pub u64);

pub trait TimerOps {
    fn monotonic_ns() -> MonotonicNs;
}

pub struct X86TimerOps;

impl TimerOps for X86TimerOps {
    fn monotonic_ns() -> MonotonicNs { MonotonicNs(time_common::monotonic_ns()) }
}

static DEADLINE: AtomicU64 = AtomicU64::new(0);
static CONVERSIONS: AtomicUsize = AtomicUsize::new(0);

pub mod live {
    pub mod futex {
        pub const FUTEX_PRIVATE_FLAG: u32 = 0x80;
        pub const FUTEX_CLOCK_REALTIME: u32 = 0x100;
        pub const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
        pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;

        pub fn requeue(_uaddr: u64, _uaddr2: u64, _wake: usize, _requeue: usize,
            _private: bool) -> i64 { 0 }
        pub fn cmp_requeue(_uaddr: u64, _uaddr2: u64, _wake: usize, _requeue: usize,
            _cmp: u32, _private: bool) -> i64 { 0 }
        pub fn wake_op(_uaddr: u64, _uaddr2: u64, _wake: usize, _wake2: usize,
            _op: u32, _private: bool) -> i64 { 0 }
        pub fn dispatch_timed(_uaddr: u64, _op: u32, _val: u32, _bitset: u32, deadline: u64) -> i64 {
            super::super::DEADLINE.store(deadline, core::sync::atomic::Ordering::SeqCst);
            0
        }
        pub fn dispatch_waitv_timed(_uaddrs: &[u64], _vals: &[u32], _private: bool,
            deadline: u64) -> i64
        {
            super::super::DEADLINE.store(deadline, core::sync::atomic::Ordering::SeqCst);
            0
        }
    }
}

mod userbuf {
    pub fn validate_user_buf(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        if ptr == 0 || ptr.checked_add(len).is_none() { Err(-14) } else { Ok(()) }
    }
}

mod time_common {
    use core::sync::atomic::Ordering;

    pub const NS_PER_SEC: u64 = 1_000_000_000;
    pub const CLOCK_REALTIME: u64 = 0;
    pub const CLOCK_MONOTONIC: u64 = 1;

    pub fn clock_id_known(clockid: u64) -> bool {
        matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC)
    }

    pub fn ns_for_clock(clockid: u64) -> u64 {
        if clockid == CLOCK_REALTIME { 20 * NS_PER_SEC } else { 9 * NS_PER_SEC }
    }

    pub fn monotonic_ns() -> u64 { 9 * NS_PER_SEC }

    pub fn current_sleep_target_to_host(clockid: u64, absolute: bool, target: u64)
        -> Result<u64, ()>
    {
        super::CONVERSIONS.fetch_add(1, Ordering::SeqCst);
        assert!(absolute);
        Ok(if clockid == CLOCK_MONOTONIC { target - 2 * NS_PER_SEC } else { target })
    }
}

#[path = "../src/202_futex.rs"]
mod s202_futex;
#[path = "../src/449_futex_waitv.rs"]
mod s449_futex_waitv;
#[path = "../src/455_futex_wait.rs"]
mod s455_futex_wait;

fn args(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64)
    -> syscall::SyscallArgs
{
    syscall::SyscallArgs { a0, a1, a2, a3, a4, a5 }
}

fn timespec(sec: i64) -> [i64; 2] { [sec, 0] }

fn reset() {
    DEADLINE.store(0, Ordering::SeqCst);
    CONVERSIONS.store(0, Ordering::SeqCst);
}

#[test]
fn classic_futex_converts_only_absolute_monotonic_deadlines() {
    reset();
    let relative = timespec(3);
    assert_eq!(s202_futex::sys_futex(&args(0x1000, 0, 7,
        relative.as_ptr() as u64, 0, 0)), 0);
    assert_eq!(DEADLINE.load(Ordering::SeqCst), 12 * time_common::NS_PER_SEC);
    assert_eq!(CONVERSIONS.load(Ordering::SeqCst), 0);

    let absolute = timespec(12);
    assert_eq!(s202_futex::sys_futex(&args(0x1000, 9, 7,
        absolute.as_ptr() as u64, 0, 0)), 0);
    assert_eq!(DEADLINE.load(Ordering::SeqCst), 10 * time_common::NS_PER_SEC);
    assert_eq!(CONVERSIONS.load(Ordering::SeqCst), 1);

    let realtime = timespec(25);
    assert_eq!(s202_futex::sys_futex(&args(0x1000, 9 | 0x100, 7,
        realtime.as_ptr() as u64, 0, 0)), 0);
    assert_eq!(DEADLINE.load(Ordering::SeqCst), 14 * time_common::NS_PER_SEC);
    assert_eq!(CONVERSIONS.load(Ordering::SeqCst), 1);
}

#[test]
fn futex_waitv_translates_namespace_deadlines_to_host_monotonic() {
    reset();
    let waiter = [7u64, 0x1000, 0x80];
    let monotonic = timespec(12);
    assert_eq!(s449_futex_waitv::sys_futex_waitv(&args(waiter.as_ptr() as u64, 1, 0,
        monotonic.as_ptr() as u64, time_common::CLOCK_MONOTONIC, 0)), 0);
    assert_eq!(DEADLINE.load(Ordering::SeqCst), 10 * time_common::NS_PER_SEC);
    assert_eq!(CONVERSIONS.load(Ordering::SeqCst), 1);

    let realtime = timespec(25);
    assert_eq!(s449_futex_waitv::sys_futex_waitv(&args(waiter.as_ptr() as u64, 1, 0,
        realtime.as_ptr() as u64, time_common::CLOCK_REALTIME, 0)), 0);
    assert_eq!(DEADLINE.load(Ordering::SeqCst), 14 * time_common::NS_PER_SEC);
    assert_eq!(CONVERSIONS.load(Ordering::SeqCst), 1);
}

#[test]
fn futex_wait_translates_namespace_deadlines_to_host_monotonic() {
    reset();
    let monotonic = timespec(12);
    assert_eq!(s455_futex_wait::sys_futex_wait(&args(0x1000, 7, u32::MAX as u64, 2,
        monotonic.as_ptr() as u64, time_common::CLOCK_MONOTONIC)), 0);
    assert_eq!(DEADLINE.load(Ordering::SeqCst), 10 * time_common::NS_PER_SEC);
    assert_eq!(CONVERSIONS.load(Ordering::SeqCst), 1);

    let realtime = timespec(25);
    assert_eq!(s455_futex_wait::sys_futex_wait(&args(0x1000, 7, u32::MAX as u64, 2,
        realtime.as_ptr() as u64, time_common::CLOCK_REALTIME)), 0);
    assert_eq!(DEADLINE.load(Ordering::SeqCst), 14 * time_common::NS_PER_SEC);
    assert_eq!(CONVERSIONS.load(Ordering::SeqCst), 1);
}
