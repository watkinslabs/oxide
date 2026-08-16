// Building a channel definition out of the addressing attributes three
// commands share: `SET_CHANNEL`, `START_AP` and a management transmission.
//
// Two encodings reach this code and both are live. Modern userspace sends an
// explicit width plus segment centres; older userspace sends only the legacy
// secondary-channel selection and expects the kernel to derive the centre.
// A build that read only one of them would work with `iw` and not with
// `hostapd`, or the other way round.

extern crate alloc;

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::chan::{ChanDef, Channel};
use crate::uapi::attr as a;
use crate::uapi::enums::{channel_type, ChanWidth};
use crate::wiphy::Wiphy;

use super::msg;

/// Offset in MHz from the primary channel to the centre of a 40 MHz channel.
const HT40_CENTER_OFFSET_MHZ: u32 = 10;

/// The channel a request's frequency attribute names. # C: O(N channels)
pub fn channel(wiphy: &Arc<Wiphy>, attrs: &[u8]) -> Result<Channel, Errno> {
    let freq = msg::get_u32(attrs, a::WIPHY_FREQ).ok_or(Errno::Einval)?;
    wiphy.channel(freq).ok_or(Errno::Einval)
}

/// Read a channel definition out of a request.
///
/// The width defaults to the no-high-throughput 20 MHz form, which is what a
/// request naming only a frequency asks for; anything wider is stated.
/// # C: O(N channels)
pub fn parse(wiphy: &Arc<Wiphy>, attrs: &[u8]) -> Result<ChanDef, Errno> {
    let chan = channel(wiphy, attrs)?;
    let mut def = ChanDef {
        chan, width: ChanWidth::Width20NoHt,
        center_freq1: chan.center_freq, freq1_offset: chan.freq_offset, center_freq2: 0,
    };
    if let Some(ty) = msg::get_u32(attrs, a::WIPHY_CHANNEL_TYPE) {
        legacy(&mut def, ty)?;
        // A request that states both encodings must state them consistently:
        // silently preferring one hands the radio a channel the caller did
        // not ask for.
        if let Some(c1) = msg::get_u32(attrs, a::CENTER_FREQ1) {
            if c1 != def.center_freq1 { return Err(Errno::Einval); }
        }
        if msg::get_u32(attrs, a::CENTER_FREQ2).is_some_and(|c| c != 0) {
            return Err(Errno::Einval);
        }
        return Ok(def);
    }
    if let Some(w) = msg::get_u32(attrs, a::CHANNEL_WIDTH) {
        def.width = ChanWidth::from_u32(w).ok_or(Errno::Einval)?;
        if let Some(c1) = msg::get_u32(attrs, a::CENTER_FREQ1) {
            def.center_freq1 = c1;
            def.freq1_offset = msg::get_u32(attrs, a::CENTER_FREQ1_OFFSET).unwrap_or(0);
        }
        if let Some(c2) = msg::get_u32(attrs, a::CENTER_FREQ2) { def.center_freq2 = c2; }
    }
    Ok(def)
}

/// Apply the legacy secondary-channel selection. # C: O(1)
fn legacy(def: &mut ChanDef, ty: u32) -> Result<(), Errno> {
    let (width, center) = match ty {
        channel_type::NO_HT => (ChanWidth::Width20NoHt, def.chan.center_freq),
        channel_type::HT20 => (ChanWidth::Width20, def.chan.center_freq),
        channel_type::HT40MINUS =>
            (ChanWidth::Width40, def.chan.center_freq - HT40_CENTER_OFFSET_MHZ),
        channel_type::HT40PLUS =>
            (ChanWidth::Width40, def.chan.center_freq + HT40_CENTER_OFFSET_MHZ),
        _ => return Err(Errno::Einval),
    };
    def.width = width;
    def.center_freq1 = center;
    def.freq1_offset = 0;
    def.center_freq2 = 0;
    Ok(())
}

/// Whether the regulatory domain in force on this radio permits the whole
/// definition. Checked separately from parsing because a definition that is
/// internally consistent can still be one the domain does not allow.
/// # C: O(width × N rules)
pub fn usable(wiphy: &Arc<Wiphy>, def: &ChanDef) -> bool {
    if !def.is_valid() { return false; }
    let regdom = wiphy.regdom();
    crate::reg::apply::chandef_usable(&regdom, def)
}

/// Parse and check in one step, which is what every caller wants.
/// # C: O(width × N rules)
pub fn parse_usable(wiphy: &Arc<Wiphy>, attrs: &[u8]) -> Result<ChanDef, Errno> {
    let def = parse(wiphy, attrs)?;
    if !usable(wiphy, &def) { return Err(Errno::Einval); }
    Ok(def)
}

/// Append the attributes describing an operating channel. # C: O(1)
pub fn put(out: &mut alloc::vec::Vec<u8>, def: &ChanDef) {
    use netlink::genetlink::attr;
    attr::put_u32(out, a::WIPHY_FREQ, def.chan.center_freq);
    if def.chan.freq_offset != 0 {
        attr::put_u32(out, a::WIPHY_FREQ_OFFSET, def.chan.freq_offset);
    }
    attr::put_u32(out, a::CHANNEL_WIDTH, def.width.as_u32());
    attr::put_u32(out, a::CENTER_FREQ1, def.center_freq1);
    if def.center_freq2 != 0 { attr::put_u32(out, a::CENTER_FREQ2, def.center_freq2); }
}
