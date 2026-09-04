//! Fault and race injection around the hosted uaccess implementation.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use syscall::errno::Errno;

pub use ipc::useraccess::{TIMESPEC_BYTES, read_bytes, read_i32, read_i64,
    read_timespec, read_u64, write_bytes, write_i64, write_u32};

static FAULT_ADDR: AtomicU64 = AtomicU64::new(0);
static FAULT_CALL: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);
static READ_ADDR: AtomicU64 = AtomicU64::new(0);
static READ_FAULT_CALL: AtomicU32 = AtomicU32::new(0);
static READ_CALLS: AtomicU32 = AtomicU32::new(0);
static EAGAIN_ADDR: AtomicU64 = AtomicU64::new(0);
static EAGAIN_CALLS: AtomicU32 = AtomicU32::new(0);
static MISMATCH_ADDR: AtomicU64 = AtomicU64::new(0);
static MISMATCH_CALL: AtomicU32 = AtomicU32::new(0);
static MISMATCH_CALLS: AtomicU32 = AtomicU32::new(0);

pub fn fault_read_on_call(addr: u64, call: u32) {
    READ_CALLS.store(0, Ordering::Release);
    READ_FAULT_CALL.store(call, Ordering::Release);
    READ_ADDR.store(addr, Ordering::Release);
}

pub fn read_u32(uptr: u64) -> Result<u32, Errno> {
    if READ_ADDR.load(Ordering::Acquire) == uptr
        && READ_CALLS.fetch_add(1, Ordering::AcqRel) + 1
            == READ_FAULT_CALL.load(Ordering::Acquire) { return Err(Errno::Efault); }
    ipc::useraccess::read_u32(uptr)
}

pub fn fault_cmpxchg_on_call(addr: u64, call: u32) {
    CALLS.store(0, Ordering::Release);
    FAULT_CALL.store(call, Ordering::Release);
    FAULT_ADDR.store(addr, Ordering::Release);
}

pub fn cmpxchg_calls() -> u32 { CALLS.load(Ordering::Acquire) }

pub fn cmpxchg_eagain_for(addr: u64, calls: u32) {
    CALLS.store(0, Ordering::Release);
    EAGAIN_CALLS.store(calls, Ordering::Release);
    EAGAIN_ADDR.store(addr, Ordering::Release);
}

pub fn mismatch_cmpxchg_on_call(addr: u64, call: u32) {
    MISMATCH_CALLS.store(0, Ordering::Release);
    MISMATCH_CALL.store(call, Ordering::Release);
    MISMATCH_ADDR.store(addr, Ordering::Release);
}

pub fn mismatch_cmpxchg_calls() -> u32 { MISMATCH_CALLS.load(Ordering::Acquire) }

pub fn cmpxchg_u32(uptr: u64, old: u32, new: u32) -> Result<u32, Errno> {
    if MISMATCH_ADDR.load(Ordering::Acquire) == uptr {
        let call = MISMATCH_CALLS.fetch_add(1, Ordering::AcqRel) + 1;
        if call == MISMATCH_CALL.load(Ordering::Acquire) { return Ok(old.wrapping_add(1)); }
    }
    if FAULT_ADDR.load(Ordering::Acquire) == uptr {
        let call = CALLS.fetch_add(1, Ordering::AcqRel) + 1;
        if call == FAULT_CALL.load(Ordering::Acquire) { return Err(Errno::Efault); }
    } else if EAGAIN_ADDR.load(Ordering::Acquire) == uptr {
        let call = CALLS.fetch_add(1, Ordering::AcqRel) + 1;
        if call <= EAGAIN_CALLS.load(Ordering::Acquire) { return Err(Errno::Eagain); }
    }
    ipc::useraccess::cmpxchg_u32(uptr, old, new)
}
