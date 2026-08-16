// One interface's description, shared by the query, the dump and the reply a
// creation sends back. The three must agree: userspace caches what a creation
// returned and expects a later dump to match it.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;

use crate::uapi::attr as a;
use crate::uapi::enums::IfType;
use crate::wdev::Wdev;
use crate::wiphy::Wiphy;

use super::super::{chandef, msg};

/// Append everything a `GET_INTERFACE` reply carries about one interface.
///
/// The name and interface index appear only for a type that has a network
/// device: reporting index zero for a type that has none would let a reader
/// address the wrong interface. # C: O(1)
pub fn put(out: &mut Vec<u8>, wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>) {
    let (iftype, name, ifindex, addr, use_4addr, ssid, def) = wdev.with(|w| {
        (w.iftype, w.name.clone(), w.ifindex, w.addr, w.use_4addr, w.ssid.clone(), w.chandef)
    });
    if let Some(ifindex) = ifindex {
        attr::put_u32(out, a::IFINDEX, ifindex);
        attr::put_str(out, a::IFNAME, &name);
    }
    attr::put_u32(out, a::WIPHY, wiphy.index);
    attr::put_u32(out, a::IFTYPE, iftype.as_u32());
    msg::put_u64(out, a::WDEV, wdev.identifier);
    msg::put_mac(out, a::MAC, addr);
    attr::put_u32(out, a::GENERATION, wiphy.generation());
    msg::put_u8(out, a::_4ADDR, u8::from(use_4addr));
    if let Some(def) = def { chandef::put(out, &def); }
    // Only the three types that own an SSID report one; on any other type the
    // field is not a network name and reporting it would be a lie.
    if !ssid.is_empty() && owns_ssid(iftype) { attr::put(out, a::SSID, &ssid); }
}

/// Whether an interface type has an SSID of its own. # C: O(1)
fn owns_ssid(iftype: IfType) -> bool {
    matches!(iftype, IfType::Ap | IfType::P2pGo | IfType::Station | IfType::P2pClient
        | IfType::Adhoc)
}
