/// Spin iterations a probe-time submission waits for device retirement.
/// Exceeding it leaves the descriptor device-owned, so its DMA frame leaks.
pub(super) const SUBMIT_POLL_BUDGET: u32 = 1_000_000;
