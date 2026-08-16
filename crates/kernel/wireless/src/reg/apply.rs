// Projecting a regulatory domain onto a radio's channel list: the pass that
// turns "these rules are in force" into "this channel is disabled, that one
// is receive-only, that one needs a radar check".
//
// A channel no rule covers is DISABLED, not merely restricted. The difference
// decides whether the radio can be told to tune there at all, and a channel
// left enabled because no rule mentioned it is the exact shape of an
// out-of-band transmission.

use super::domain::RegDomain;
use super::rule::{self, RegRule};
use crate::chan::{chan_flags, mhz_to_khz, Channel};
use crate::uapi::enums::{dfs_state, reg_rule_flags};
use crate::wiphy::caps::WiphyBand;

/// Widest single channel a rule must admit for the channel to be usable at
/// all, in kHz. A rule too narrow for one 20 MHz channel disables it.
pub const MIN_CHANNEL_BW_KHZ: u32 = 20_000;

/// Channel restrictions a rule's flags imply. The mapping is not the identity:
/// a rule flag bars a bandwidth across a whole range, and the channel flag
/// records that the individual channel cannot be used at that width. # C: O(1)
pub fn chan_flags_from_rule(flags: u32) -> u32 {
    let mut out = 0;
    if flags & reg_rule_flags::NO_IR != 0 { out |= chan_flags::NO_IR; }
    if flags & reg_rule_flags::DFS != 0 { out |= chan_flags::RADAR; }
    if flags & reg_rule_flags::NO_OFDM != 0 { out |= chan_flags::NO_OFDM; }
    if flags & reg_rule_flags::NO_INDOOR != 0 { out |= chan_flags::INDOOR_ONLY; }
    if flags & reg_rule_flags::NO_HT40MINUS != 0 { out |= chan_flags::NO_HT40MINUS; }
    if flags & reg_rule_flags::NO_HT40PLUS != 0 { out |= chan_flags::NO_HT40PLUS; }
    if flags & reg_rule_flags::NO_80MHZ != 0 { out |= chan_flags::NO_80MHZ; }
    if flags & reg_rule_flags::NO_160MHZ != 0 { out |= chan_flags::NO_160MHZ; }
    if flags & reg_rule_flags::NO_320MHZ != 0 { out |= chan_flags::NO_320MHZ; }
    if flags & reg_rule_flags::NO_HE != 0 { out |= chan_flags::NO_HE; }
    if flags & reg_rule_flags::NO_EHT != 0 { out |= chan_flags::NO_EHT; }
    if flags & reg_rule_flags::IR_CONCURRENT != 0 { out |= chan_flags::IR_CONCURRENT; }
    if flags & reg_rule_flags::PSD != 0 { out |= chan_flags::PSD; }
    if flags & reg_rule_flags::DFS_CONCURRENT != 0 { out |= chan_flags::DFS_CONCURRENT; }
    out
}

/// Apply a domain to one channel. Every restriction is recomputed from the
/// domain, so a domain change that lifts a restriction really lifts it rather
/// than leaving the old flag behind. # C: O(N rules)
pub fn apply_to_channel(domain: &RegDomain, chan: &mut Channel) {
    let center_khz = chan.center_freq_khz();
    let Some(r) = domain.rule_for(center_khz, MIN_CHANNEL_BW_KHZ) else {
        chan.flags = chan_flags::DISABLED;
        chan.max_power = 0;
        chan.max_antenna_gain = 0;
        return;
    };
    chan.flags = chan_flags_from_rule(r.flags);
    // A rule whose whole range is narrower than a wide channel bars that
    // width even when it did not say so, because the channel would not fit.
    let bw = r.freq_range.max_bandwidth_khz;
    if bw < 40_000 { chan.flags |= chan_flags::NO_HT40; }
    if bw < 80_000 { chan.flags |= chan_flags::NO_80MHZ; }
    if bw < 160_000 { chan.flags |= chan_flags::NO_160MHZ; }
    if bw < 320_000 { chan.flags |= chan_flags::NO_320MHZ; }
    chan.max_antenna_gain = r.power_rule.max_antenna_gain_mbi / 100;
    chan.max_power = r.power_rule.max_eirp_mbm / 100;
    if r.flags & reg_rule_flags::DFS != 0 {
        chan.dfs_cac_ms = rule::dfs_cac_ms(r, domain.dfs_region);
        // A channel that has just come under radar rules has not been
        // checked; it becomes usable only after its availability check.
        if chan.dfs_state == dfs_state::AVAILABLE { chan.dfs_state = dfs_state::USABLE; }
    } else {
        chan.dfs_cac_ms = 0;
        chan.dfs_state = dfs_state::USABLE;
    }
}

/// Apply a domain to every channel of every band. # C: O(N channels × N rules)
pub fn apply_to_bands(domain: &RegDomain, bands: &mut [WiphyBand]) {
    for band in bands.iter_mut() {
        for chan in band.channels.iter_mut() { apply_to_channel(domain, chan); }
    }
}

/// Whether a channel definition is permitted in full: every 20 MHz channel it
/// occupies must be usable, and a rule must admit the whole width at the
/// definition's centre. Checking only the primary channel is how an 80 MHz
/// definition ends up straddling a range boundary. # C: O(width × N rules)
pub fn chandef_usable(domain: &RegDomain, def: &crate::chan::ChanDef) -> bool {
    if !def.is_valid() { return false; }
    // Receive-only is not checked here: it bars transmitting on a channel,
    // not tuning to it, and whoever wants to transmit asks separately.
    for freq in def.covered_freqs() {
        if domain.rule_for(mhz_to_khz(freq), MIN_CHANNEL_BW_KHZ).is_none() { return false; }
    }
    let bw = def.width.khz();
    let centre = mhz_to_khz(def.center_freq1);
    if domain.rule_for(centre, bw).is_none() { return false; }
    if def.center_freq2 != 0 {
        if domain.rule_for(mhz_to_khz(def.center_freq2), bw / 2).is_none() { return false; }
    }
    true
}

/// The strictest rule covering any part of a channel definition, which is the
/// power ceiling the whole definition must respect. # C: O(width × N rules)
pub fn chandef_max_power(domain: &RegDomain, def: &crate::chan::ChanDef) -> Option<i32> {
    let mut ceiling: Option<i32> = None;
    for freq in def.covered_freqs() {
        let r: &RegRule = domain.rule_for(mhz_to_khz(freq), MIN_CHANNEL_BW_KHZ)?;
        let dbm = r.power_rule.max_eirp_mbm / 100;
        ceiling = Some(ceiling.map_or(dbm, |c: i32| c.min(dbm)));
    }
    ceiling
}
