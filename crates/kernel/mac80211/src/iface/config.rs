// Pushing configuration down to the driver.
//
// Every change is expressed as WHAT MOVED, not as the whole configuration, so
// a driver reprograms only the part that changed. A layer that told the
// driver "everything changed" on every edit would retune the radio each time
// a beacon interval was adjusted, which on real hardware costs a link.

extern crate alloc;

use alloc::sync::Arc;

use wireless::chan::ChanDef;
use wireless::uapi::enums::IfType;

use super::sdata::Sdata;
use crate::flags::{bss_changed, conf_changed};
use crate::hw::Local;
use crate::ops::BssConf;

/// Recompute the device-wide configuration from every interface and apply
/// whatever moved. The channel is whichever operating interface has one, the
/// radio is idle only when no interface is up, and power save is on only when
/// every interface that could object is happy with it. # C: O(N interfaces)
pub fn apply_conf(local: &Arc<Local>) {
    let ifaces = local.ifaces();
    let chandef = ifaces.iter().find_map(|s| s.chandef());
    let monitor = ifaces.iter().any(|s| s.is_up() && s.iftype() == IfType::Monitor);
    let idle = !ifaces.iter().any(|s| s.is_up());
    // Power save belongs to a client with nothing else going on: an interface
    // that beacons cannot sleep, and neither can a monitor.
    let ps = ifaces.iter().any(|s| s.is_up() && s.with(|st| st.ps))
        && !ifaces.iter().any(|s| s.is_up()
            && (s.iftype().is_ap() || s.iftype() == IfType::Monitor));

    let changed = local.with(|s| {
        let mut changed = 0u32;
        if s.conf.chandef.map(|c| c.chan.center_freq) != chandef.map(|c| c.chan.center_freq) {
            s.conf.chandef = chandef;
            changed |= conf_changed::CHANNEL;
        }
        if s.conf.monitor != monitor { s.conf.monitor = monitor; changed |= conf_changed::MONITOR; }
        if s.conf.idle != idle { s.conf.idle = idle; changed |= conf_changed::IDLE; }
        if s.conf.ps != ps { s.conf.ps = ps; changed |= conf_changed::PS; }
        changed
    });
    if changed == 0 { return; }
    let conf = local.with(|s| s.conf);
    let _ = local.ops.config(&local.hw, &conf, changed);
}

/// Put one interface on a channel and apply it. # C: driver-dependent
pub fn set_channel(local: &Arc<Local>, sdata: &Arc<Sdata>, def: ChanDef) {
    sdata.with(|s| s.chandef = Some(def));
    sdata.wdev.with(|w| w.chandef = Some(def));
    apply_conf(local);
}

/// Replace an interface's network configuration and tell the driver which
/// fields moved. # C: O(1)
pub fn set_bss(local: &Arc<Local>, sdata: &Arc<Sdata>, new: BssConf) {
    let changed = sdata.with(|s| {
        let old = &s.bss;
        let mut changed = 0u32;
        if old.assoc != new.assoc { changed |= bss_changed::ASSOC; }
        if old.bssid != new.bssid { changed |= bss_changed::BSSID; }
        if old.beacon_int != new.beacon_int { changed |= bss_changed::BEACON_INT; }
        if old.enable_beacon != new.enable_beacon { changed |= bss_changed::BEACON_ENABLED; }
        if old.basic_rates != new.basic_rates { changed |= bss_changed::BASIC_RATES; }
        if old.qos != new.qos { changed |= bss_changed::QOS; }
        if old.use_cts_prot != new.use_cts_prot { changed |= bss_changed::ERP_CTS_PROT; }
        if old.use_short_preamble != new.use_short_preamble {
            changed |= bss_changed::ERP_PREAMBLE;
        }
        if old.use_short_slot != new.use_short_slot { changed |= bss_changed::ERP_SLOT; }
        if old.ssid != new.ssid { changed |= bss_changed::SSID; }
        s.bss = new;
        changed
    });
    if changed == 0 { return; }
    let conf = sdata.bss_conf();
    local.ops.bss_info_changed(&local.hw, &sdata.vif(), &conf, changed);
}

/// Edit one interface's network configuration in place and report what moved.
/// # C: O(f)
pub fn update_bss(local: &Arc<Local>, sdata: &Arc<Sdata>, f: impl FnOnce(&mut BssConf)) {
    let mut conf = sdata.bss_conf();
    f(&mut conf);
    set_bss(local, sdata, conf);
}

/// Apply the contention parameters for one access category. # C: driver-dependent
pub fn set_tx_params(local: &Arc<Local>, sdata: &Arc<Sdata>, ac: u8,
                     params: crate::ops::TxQueueParams) {
    if (ac as usize) >= crate::uapi::ac::COUNT { return; }
    local.with(|s| s.tx_params[ac as usize] = params);
    let _ = local.ops.conf_tx(&local.hw, &sdata.vif(), ac, &params);
}
