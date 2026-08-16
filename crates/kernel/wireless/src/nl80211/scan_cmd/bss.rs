// One cached network as a `GET_SCAN` dump reports it.
//
// The element sets are the whole point of the message. A hidden network's
// name appears only in the probe-response elements and the channel it really
// operates on appears only in the beacon's, so both sets go out and the flag
// that says which one is current goes with them.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;

use crate::scan::{Bss, BssCache};
use crate::uapi::attr as a;
use crate::uapi::nested::bss;
use crate::wdev::Wdev;
use crate::wiphy::Wiphy;

use super::super::msg;

/// Append one cached network, nested, with the identity attributes that say
/// which radio and interface heard it outside the nest. # C: O(len)
pub fn put(out: &mut Vec<u8>, wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, entry: &Bss,
           generation: u32, now_ns: u64) {
    attr::put_u32(out, a::GENERATION, generation);
    if let Some(ifindex) = wdev.ifindex() { attr::put_u32(out, a::IFINDEX, ifindex); }
    msg::put_u64(out, a::WDEV, wdev.identifier, a::PAD);
    attr::put_u32(out, a::WIPHY, wiphy.index);

    let at = attr::nest_start(out, a::BSS);
    if !entry.bssid.is_zero() { msg::put_mac(out, bss::BSSID, entry.bssid); }
    if entry.presp_data { msg::put_flag(out, bss::PRESP_DATA); }
    msg::put_u64(out, bss::TSF, entry.tsf, bss::PAD);
    if !entry.ies.is_empty() { attr::put(out, bss::INFORMATION_ELEMENTS, &entry.ies); }
    if !entry.beacon_ies.is_empty() && entry.beacon_ies != entry.ies {
        msg::put_u64(out, bss::BEACON_TSF, entry.tsf, bss::PAD);
        attr::put(out, bss::BEACON_IES, &entry.beacon_ies);
    }
    if entry.beacon_interval != 0 {
        attr::put_u16(out, bss::BEACON_INTERVAL, entry.beacon_interval);
    }
    attr::put_u16(out, bss::CAPABILITY, entry.capability);
    attr::put_u32(out, bss::FREQUENCY, entry.freq);
    if entry.freq_offset != 0 {
        attr::put_u32(out, bss::FREQUENCY_OFFSET, entry.freq_offset);
    }
    attr::put_u32(out, bss::SEEN_MS_AGO, entry.age_ms(now_ns));
    if entry.last_seen_ns != 0 {
        msg::put_u64(out, bss::LAST_SEEN_BOOTTIME, entry.last_seen_ns, bss::PAD);
    }
    attr::put_u32(out, bss::CHAN_WIDTH, entry.chan_width.as_u32());
    if wiphy.caps.signal_dbm { msg::put_i32(out, bss::SIGNAL_MBM, entry.signal_mbm); }
    if let Some(status) = entry.status { attr::put_u32(out, bss::STATUS, status); }
    attr::nest_end(out, at);
}

/// The moment a dump reports ages against.
///
/// This layer has no clock of its own, so the most recently heard entry is
/// taken as the present: right after a scan that is the truth, and every
/// other entry's age is then correct relative to it. # C: O(N entries)
pub fn reference_now(cache: &BssCache) -> u64 {
    cache.snapshot().first().map_or(0, |e| e.last_seen_ns)
}
