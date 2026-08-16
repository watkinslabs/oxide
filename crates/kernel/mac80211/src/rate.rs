// Rate selection.
//
// The rule is the classic one: step down after consecutive failures, step up
// after a run of successes, and periodically probe a higher rate so a link
// that settled low while conditions were bad discovers that they improved.
// A selector with no probe never recovers from one bad minute.

extern crate alloc;

use alloc::vec::Vec;

use wireless::sta::{rate_gen, RateInfo};
use wireless::wiphy::Bitrate;

use crate::limits;
use crate::uapi;

/// Per-peer rate state.
#[derive(Clone, Copy, Debug)]
pub struct RateCtl {
    /// Index into the band's rate table currently in use.
    pub idx: u8,
    /// Highest index the peer and this radio both support.
    pub max_idx: u8,
    /// Bit rate at `idx`, in 100 kbit/s units, cached for reporting.
    pub bitrate: u32,
    failures: u32,
    successes: u32,
    since_probe: u32,
}

impl Default for RateCtl {
    fn default() -> Self {
        Self { idx: 0, max_idx: 0, bitrate: 0, failures: 0, successes: 0, since_probe: 0 }
    }
}

impl RateCtl {
    /// Start at the lowest rate in the usable set. Starting high on an
    /// unknown link costs several retries per frame before the selector
    /// finds the floor; starting low costs one step per frame to climb.
    /// # C: O(1)
    pub fn start(&mut self, usable: &[Bitrate]) {
        self.idx = 0;
        self.max_idx = usable.len().saturating_sub(1) as u8;
        self.bitrate = usable.first().map_or(0, |b| b.bitrate);
        self.failures = 0;
        self.successes = 0;
        self.since_probe = 0;
    }

    /// Record the outcome of one frame and pick the rate for the next.
    /// # C: O(1)
    pub fn report(&mut self, acked: bool, usable: &[Bitrate]) {
        if usable.is_empty() { return; }
        self.since_probe = self.since_probe.saturating_add(1);
        if acked {
            self.failures = 0;
            self.successes += 1;
            let climb = self.successes >= limits::RATE_UP_SUCCESSES
                || self.since_probe >= limits::RATE_PROBE_INTERVAL;
            if climb && self.idx < self.max_idx {
                self.idx += 1;
                self.successes = 0;
                self.since_probe = 0;
            }
        } else {
            self.successes = 0;
            self.failures += 1;
            if self.failures >= limits::RATE_DOWN_FAILURES && self.idx > 0 {
                self.idx -= 1;
                self.failures = 0;
            }
        }
        self.bitrate = usable.get(self.idx as usize).map_or(self.bitrate, |b| b.bitrate);
    }

    /// The rate to send the next frame at. # C: O(1)
    pub fn current(&self) -> u8 { self.idx }

    /// The rate as it is reported upward. # C: O(1)
    pub fn current_info(&self) -> RateInfo {
        RateInfo { bitrate: self.bitrate, generation: rate_gen::LEGACY, ..Default::default() }
    }
}

/// The rates both ends support, in the radio's own table order. A rate the
/// peer named that this radio does not have is dropped rather than
/// approximated: transmitting at a rate the radio cannot produce is not a
/// degraded link, it is no link. # C: O(N rates)
pub fn intersect(local: &[Bitrate], peer_rates: &[u32]) -> Vec<Bitrate> {
    local.iter().copied().filter(|b| peer_rates.contains(&b.bitrate)).collect()
}

/// The rates a supported-rates element names, in 100 kbit/s units. Both the
/// element and its extension are walked; splitting them is a length
/// limitation of the element, not two different rate sets. # C: O(len)
pub fn rates_from_elements(supp: &[u8], ext: &[u8]) -> Vec<u32> {
    supp.iter().chain(ext.iter()).map(|&b| uapi::elem_to_rate(b)).collect()
}

/// The rates a peer must support to join, as a bit mask over the band's rate
/// table. A peer missing one of them cannot be admitted, which is why the
/// mask travels with the association decision. # C: O(N rates)
pub fn basic_rate_mask(local: &[Bitrate], supp: &[u8], ext: &[u8]) -> u32 {
    let mut mask = 0u32;
    for &byte in supp.iter().chain(ext.iter()) {
        if byte & uapi::RATE_BASIC == 0 { continue; }
        let rate = uapi::elem_to_rate(byte);
        if let Some(i) = local.iter().position(|b| b.bitrate == rate) { mask |= 1 << i; }
    }
    mask
}

/// Build a supported-rates element body from a rate table, marking the ones
/// every member must support. # C: O(N rates)
pub fn rates_element(local: &[Bitrate], basic_mask: u32) -> Vec<u8> {
    local.iter().enumerate().map(|(i, b)| {
        let mut byte = uapi::rate_to_elem(b.bitrate);
        if basic_mask & (1 << i) != 0 { byte |= uapi::RATE_BASIC; }
        byte
    }).collect()
}

/// Rates an element body may hold before the extension element is needed.
pub const MAX_SUPP_RATES: usize = 8;

/// Split a rate list into the element and its extension. # C: O(N rates)
pub fn split_rates(all: &[u8]) -> (&[u8], &[u8]) {
    if all.len() <= MAX_SUPP_RATES { (all, &[]) } else { all.split_at(MAX_SUPP_RATES) }
}
