use syscall::errno::Errno;

use crate::uapi::{UserBuf, PCM_PROTO_TSTAMP_TYPE, SP_STATUS_TSTAMP_NSEC,
    SP_STATUS_TSTAMP_SEC, ST_TSTAMP_NSEC, ST_TSTAMP_SEC, ST_TRIGGER_NSEC,
    ST_TRIGGER_SEC, SWP_PROTO, SWP_TSTAMP_MODE, SWP_TSTAMP_TYPE, TSTAMP_ENABLE,
    TSTAMP_TYPE_MONOTONIC_RAW, TSTAMP_TYPE_REALTIME};

const NS_PER_SEC: u64 = 1_000_000_000;

#[derive(Copy, Clone)]
pub(crate) struct PcmTime {
    pub mode: u32,
    pub kind: u32,
    pub trigger_ns: u64,
}

impl PcmTime {
    pub const fn new() -> Self {
        Self { mode: crate::uapi::TSTAMP_NONE, kind: TSTAMP_TYPE_REALTIME, trigger_ns: 0 }
    }

    pub fn set_kind(&mut self, kind: u32) -> Result<(), Errno> {
        if kind > TSTAMP_TYPE_MONOTONIC_RAW { return Err(Errno::Einval); }
        self.kind = kind;
        Ok(())
    }

    pub fn apply_sw(&mut self, b: &UserBuf) -> Result<(), Errno> {
        let mode = b.r32(SWP_TSTAMP_MODE);
        if mode > TSTAMP_ENABLE { return Err(Errno::Einval); }
        let kind = if b.r32(SWP_PROTO) >= PCM_PROTO_TSTAMP_TYPE {
            b.r32(SWP_TSTAMP_TYPE)
        } else {
            self.kind
        };
        if kind > TSTAMP_TYPE_MONOTONIC_RAW { return Err(Errno::Einval); }
        self.mode = mode;
        self.kind = kind;
        Ok(())
    }

    pub fn stamp_trigger(&mut self) { self.trigger_ns = now_ns(self.kind); }

    pub fn write_status(&self, b: &UserBuf, state: u32) {
        if state == crate::uapi::STATE_OPEN { return; }
        write_timespec(b, ST_TRIGGER_SEC, ST_TRIGGER_NSEC, self.trigger_ns);
        if self.mode == TSTAMP_ENABLE {
            write_timespec(b, ST_TSTAMP_SEC, ST_TSTAMP_NSEC, now_ns(self.kind));
        }
    }

    pub fn write_sync(&self, b: &UserBuf, state: u32) {
        if state == crate::uapi::STATE_OPEN { return; }
        if self.mode == TSTAMP_ENABLE {
            write_timespec(b, SP_STATUS_TSTAMP_SEC, SP_STATUS_TSTAMP_NSEC, now_ns(self.kind));
        }
    }
}

fn write_timespec(b: &UserBuf, sec_off: usize, nsec_off: usize, ns: u64) {
    b.w64(sec_off, ns / NS_PER_SEC);
    b.w64(nsec_off, ns % NS_PER_SEC);
}

#[cfg(not(test))]
fn now_ns(kind: u32) -> u64 {
    match kind {
        TSTAMP_TYPE_REALTIME => timekeeper::realtime_ns(),
        crate::uapi::TSTAMP_TYPE_MONOTONIC | TSTAMP_TYPE_MONOTONIC_RAW => timekeeper::monotonic_ns(),
        _ => 0,
    }
}

#[cfg(test)]
static TEST_CLOCKS: [core::sync::atomic::AtomicU64; 3] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

#[cfg(test)]
fn now_ns(kind: u32) -> u64 {
    TEST_CLOCKS[kind.min(TSTAMP_TYPE_MONOTONIC_RAW) as usize]
        .load(core::sync::atomic::Ordering::Acquire)
}

#[cfg(test)]
pub(crate) fn set_test_clock(kind: u32, ns: u64) {
    TEST_CLOCKS[kind.min(TSTAMP_TYPE_MONOTONIC_RAW) as usize]
        .store(ns, core::sync::atomic::Ordering::Release);
}
