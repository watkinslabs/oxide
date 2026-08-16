// Creating, starting, stopping and destroying an interface.
//
// The order in each direction is the whole content of this file. Coming up:
// the radio starts, the driver learns about the interface, the interface is
// configured, and only then is it marked up — so nothing can transmit through
// an interface the driver has not been told about. Going down: the reverse,
// with the station table emptied before the driver is told, so no station
// callback names an interface the driver has already released.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;

use syscall::errno::Errno;
use wireless::ieee80211::MacAddr;
use wireless::uapi::enums::IfType;
use wireless::Wdev;

use super::sdata::Sdata;
use crate::flags;
use crate::hw::{start_hw, stop_hw, Local};
use crate::ops::StaState;

/// Derive an address for the interface at `index` from the radio's permanent
/// address. The locally administered bit is set on every derived address but
/// the first, so several interfaces on one radio never claim the same
/// globally assigned address. # C: O(1)
pub fn derive_addr(perm: MacAddr, index: u32) -> MacAddr {
    if index == 0 { return perm; }
    let mut a = perm.0;
    a[0] |= 0x02;
    a[5] = a[5].wrapping_add(index as u8);
    MacAddr(a)
}

/// Create an interface on a radio. # C: O(N interfaces)
pub fn add(local: &Arc<Local>, iftype: IfType, name: String, addr: Option<MacAddr>)
    -> Result<Arc<Sdata>, Errno>
{
    let wiphy = local.wiphy().ok_or(Errno::Enodev)?;
    if !wiphy.supports_iftype(iftype) { return Err(Errno::Eopnotsupp); }
    let id = local.with(|s| { let id = s.next_iface_id; s.next_iface_id += 1; id });
    let addr = addr.unwrap_or_else(|| derive_addr(local.hw.addr, id));
    if local.iface_by_addr(addr).is_some() { return Err(Errno::Eexist); }

    let identifier = wiphy.next_wdev_identifier();
    let wdev = Arc::new(Wdev::new(identifier, wiphy.index, iftype, name.clone(), addr));
    let sdata = Arc::new(Sdata::new(Arc::downgrade(local), wdev.clone(), id, iftype,
                                    name, addr));
    local.with(|s| s.ifaces.push(sdata.clone()));
    wiphy.add_wdev(wdev);
    Ok(sdata)
}

/// Bring an interface up. # C: driver-dependent
pub fn up(local: &Arc<Local>, sdata: &Arc<Sdata>) -> Result<(), Errno> {
    if sdata.is_up() { return Ok(()); }
    start_hw(local)?;
    local.ops.add_interface(&local.hw, &sdata.vif())?;
    sdata.with(|s| s.up = true);
    sdata.wdev.with(|w| w.up = true);
    // A monitor interface makes the radio stop filtering; anything else
    // leaves the filter where the interface's own configuration put it.
    if sdata.iftype() == IfType::Monitor {
        let filter = local.with(|s| { s.filter |= flags::filter::OTHER_BSS; s.filter });
        local.ops.configure_filter(&local.hw, filter, 0);
    }
    crate::iface::config::apply_conf(local);
    Ok(())
}

/// Take an interface down. # C: O(N stations)
pub fn down(local: &Arc<Local>, sdata: &Arc<Sdata>) {
    if !sdata.is_up() { return; }
    // Every peer is torn down first, so the driver is never asked about a
    // station on an interface it has already been told to release.
    for addr in sdata.stas.addrs() {
        sdata.stas.set_state(addr, StaState::NotExist, |from, to| {
            let _ = local.ops.sta_state(&local.hw, &sdata.vif(), addr, from, to);
            true
        });
    }
    sdata.stas.flush();
    sdata.with(|s| {
        s.up = false;
        s.keys.flush();
        s.mlme = Default::default();
        s.bss.assoc = false;
        s.bss.enable_beacon = false;
        s.bss.port_authorized = false;
        s.frags.clear();
    });
    sdata.wdev.with(|w| { w.up = false; w.beaconing = false; w.conn.disconnected(); });
    local.ops.remove_interface(&local.hw, &sdata.vif());
    stop_hw(local);
}

/// Destroy an interface. # C: O(N interfaces)
pub fn remove(local: &Arc<Local>, sdata: &Arc<Sdata>) {
    down(local, sdata);
    local.with(|s| s.ifaces.retain(|i| i.id != sdata.id));
    if let Some(wiphy) = local.wiphy() { wiphy.remove_wdev(sdata.wdev.identifier); }
}

/// Change an interface's type in place. Only an interface that is DOWN may
/// change: the driver's per-interface state, the station table and the key
/// set all mean different things for a different type, and changing under a
/// live interface leaves whichever of them the new type does not use.
/// # C: driver-dependent
pub fn change_type(local: &Arc<Local>, sdata: &Arc<Sdata>, new: IfType) -> Result<(), Errno> {
    if sdata.iftype() == new { return Ok(()); }
    let wiphy = local.wiphy().ok_or(Errno::Enodev)?;
    if !wiphy.supports_iftype(new) { return Err(Errno::Eopnotsupp); }
    if sdata.is_up() { return Err(Errno::Ebusy); }
    match local.ops.change_interface(&local.hw, &sdata.vif(), new) {
        Ok(()) | Err(Errno::Eopnotsupp) => {}
        Err(e) => return Err(e),
    }
    sdata.with(|s| { s.iftype = new; s.mlme = Default::default(); s.keys.flush(); });
    sdata.wdev.with(|w| w.iftype = new);
    Ok(())
}
