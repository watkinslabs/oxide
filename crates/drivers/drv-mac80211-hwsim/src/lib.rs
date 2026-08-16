// mac80211_hwsim — virtual 802.11 radios on a shared simulated medium
// (`62§10`).
//
// A frame one radio transmits is delivered to every OTHER radio tuned to the
// same channel. That is the whole medium, and it is enough to run the entire
// wireless stack — scan, authenticate, associate, encrypt, aggregate — on a
// machine with no wireless hardware. It is also what keeps the softmac layer
// from being machinery with no caller.
//
// Module manifest:
// - `limits`: what the radios are configured with.
// - `radio`:  one virtual radio and what it advertises.
// - `medium`: the radio list, the clock, and the frame fan-out.
// - `ops`:    the driver operations the softmac layer calls.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod limits;
pub mod medium;
pub mod ops;
pub mod radio;

use alloc::sync::Arc;

use sync::Spinlock;
use mac80211::Errno;

pub use radio::{radio_addr, Radio};

/// Create `n` virtual radios and register each with the softmac layer.
/// Registration order is the index order, so `phy0` is radio 0 — which
/// matters to anything that addresses a radio by name. # C: O(n × channels)
pub fn init(n_radios: u32) -> Result<u32, Errno> {
    let n = n_radios.min(limits::MAX_RADIOS);
    let mut made = 0;
    for index in 0..n {
        if add_radio(index).is_err() { break; }
        made += 1;
    }
    if made == 0 && n > 0 { return Err(Errno::Enodev); }
    Ok(made)
}

/// Create the radios nothing asked a number for. # C: O(channels)
pub fn init_default() -> Result<u32, Errno> { init(limits::DEFAULT_RADIOS) }

/// Create and register one virtual radio. # C: O(channels)
pub fn add_radio(index: u32) -> Result<Arc<Radio>, Errno> {
    if medium::radio(index).is_some() { return Err(Errno::Eexist); }
    let hw = radio::hw_for(index);
    let addr = hw.addr;
    let local = mac80211::alloc_hw(hw, Arc::new(ops::HwsimOps::new(index)));
    let radio = Arc::new(Radio {
        index, addr, local: local.clone(),
        chan: Spinlock::new(None),
        started: Spinlock::new(false),
        stats: radio::RadioStats::default(),
    });
    // The radio joins the medium BEFORE it is registered: registration lets
    // the layer above configure it immediately, and a configuration that
    // arrived before the medium knew the radio would set a channel nobody
    // could read back.
    medium::attach(radio.clone());
    if let Err(e) = mac80211::register_hw(&local) {
        medium::detach(index);
        return Err(e);
    }
    Ok(radio)
}

/// Withdraw one virtual radio. # C: O(N interfaces)
pub fn remove_radio(index: u32) {
    let Some(radio) = medium::radio(index) else { return; };
    mac80211::unregister_hw(&radio.local);
    medium::detach(index);
}

/// Withdraw every radio. # C: O(N radios)
pub fn shutdown() {
    for radio in medium::radios() { remove_radio(radio.index); }
}

#[cfg(test)]
#[path = "tests/assoc.rs"] mod tests_assoc;
