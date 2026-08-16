// The simulated medium: the radio list and the frame fan-out.
//
// The list is CLONED out of its lock before any frame is delivered. Delivery
// re-enters the layer above, which answers by transmitting — an answer that
// comes straight back here — so holding the lock across delivery is a
// deadlock the first time two radios talk to each other, which is the first
// thing anyone does with this driver.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Devices as MediumLock, Spinlock};

use crate::limits;
use crate::radio::Radio;

static RADIOS: Spinlock<Vec<Arc<Radio>>, MediumLock> = Spinlock::new(Vec::new());
/// The medium's clock. Nothing here has a timer, so time advances with
/// traffic — which is enough for every deadline the layer above measures and
/// makes a sequence of exchanges reproducible.
static CLOCK_NS: AtomicU64 = AtomicU64::new(0);

/// Current time. # C: O(1)
pub fn now_ns() -> u64 { CLOCK_NS.load(Ordering::Relaxed) }
/// Move time forward. # C: O(1)
pub fn advance_ns(by: u64) -> u64 { CLOCK_NS.fetch_add(by, Ordering::Relaxed) + by }
/// Set the clock outright, for a caller driving the layer's deadlines.
/// # C: O(1)
pub fn set_now_ns(at: u64) { CLOCK_NS.store(at, Ordering::Relaxed); }

/// Add a radio to the medium. # C: O(1)
pub fn attach(radio: Arc<Radio>) { RADIOS.lock().push(radio); }

/// Take a radio off the medium. # C: O(N radios)
pub fn detach(index: u32) { RADIOS.lock().retain(|r| r.index != index); }

/// Every radio currently on the medium. # C: O(N radios)
pub fn radios() -> Vec<Arc<Radio>> { RADIOS.lock().clone() }

/// The radio at an index. # C: O(N radios)
pub fn radio(index: u32) -> Option<Arc<Radio>> {
    RADIOS.lock().iter().find(|r| r.index == index).cloned()
}

/// Radios on the medium. # C: O(1)
pub fn count() -> usize { RADIOS.lock().len() }

/// Remove every radio. # C: O(N radios)
pub fn clear() { RADIOS.lock().clear(); }

/// Carry one frame from `from` to every other radio tuned to the same
/// channel. A frame nobody is listening for is counted rather than dropped
/// silently: a test that wired two radios to different channels should be
/// able to see why nothing arrived. # C: O(N radios × len)
pub fn transmit(from: u32, frame: &[u8]) {
    let all = radios();
    let Some(sender) = all.iter().find(|r| r.index == from) else { return; };
    sender.note_tx(frame.len());
    let Some(chan) = sender.channel() else {
        sender.stats.tx_unheard.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let now = advance_ns(limits::CLOCK_STEP_NS);

    let mut heard = 0usize;
    for other in all.iter() {
        if other.index == from { continue; }
        if !other.is_running() { continue; }
        let Some(their) = other.channel() else { continue; };
        if their.chan.center_freq != chan.chan.center_freq { continue; }
        heard += 1;
        other.note_rx(frame.len());
        let status = mac80211::RxStatus {
            freq: chan.chan.center_freq,
            signal: limits::SIGNAL_DBM,
            rate_idx: 0,
            flags: 0,
            now_ns: now,
            mactime: now / 1000,
        };
        mac80211::rx(&other.local, &status, frame);
    }
    if heard == 0 { sender.stats.tx_unheard.fetch_add(1, Ordering::Relaxed); }
}
