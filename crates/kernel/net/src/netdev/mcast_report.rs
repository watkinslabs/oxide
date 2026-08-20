// Serialization state for multicast report production and interface removal.

use core::sync::atomic::{AtomicU8, Ordering};

pub(crate) struct McastReportState { state: AtomicU8 }

impl McastReportState {
    const LIVE: u8 = 1 << 0;
    const V4: u8 = 1 << 1;
    const V6: u8 = 1 << 2;

    pub(super) fn new() -> Self { Self { state: AtomicU8::new(Self::LIVE) } }
    pub(crate) fn live(&self) -> bool {
        self.state.load(Ordering::Acquire) & Self::LIVE != 0
    }
    pub(crate) fn retire(&self) {
        self.state.fetch_and(!Self::LIVE, Ordering::AcqRel);
        while self.state.load(Ordering::Acquire) & (Self::V4 | Self::V6) != 0 {
            sync::relax();
        }
    }
    pub(crate) fn try_v4(&self) -> bool { self.try_drive(Self::V4) }
    pub(crate) fn release_v4(&self) { self.state.fetch_and(!Self::V4, Ordering::Release); }
    pub(crate) fn try_v6(&self) -> bool { self.try_drive(Self::V6) }
    pub(crate) fn release_v6(&self) { self.state.fetch_and(!Self::V6, Ordering::Release); }

    fn try_drive(&self, bit: u8) -> bool {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & Self::LIVE == 0 || state & bit != 0 { return false; }
            match self.state.compare_exchange_weak(state, state | bit,
                Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(next) => state = next,
            }
        }
    }
}
