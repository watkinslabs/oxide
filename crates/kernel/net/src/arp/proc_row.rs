//! `/proc/net/arp` row rendering — the pre-netlink neighbour ABI `arp(8)` reads.
//!
//! Ungated on purpose: this is column-exact text formatting, and the procfs
//! module that emits the file is target-gated, where a test compiles away in
//! silence (`08§7`).

extern crate alloc;
use alloc::string::String;

use super::NudState;
use crate::addr::{Ipv4Addr, MacAddr};

/// Column header, emitted once whether or not any neighbour exists.
pub const HEADER: &str =
    "IP address       HW type     Flags       HW address            Mask     Device\n";

/// Hardware type of every Ethernet neighbour row.
const HW_TYPE_ETHER: u32 = 1;
/// `ATF_COM`: the row carries a resolved link-layer address.
const ATF_COM: u32 = 0x02;
/// `ATF_PERM`: installed administratively, never ages out.
const ATF_PERM: u32 = 0x04;
/// Stand-in for a neighbour that has no link-layer address yet.
const UNRESOLVED_HW_ADDRESS: &str = "00:00:00:00:00:00";

/// Flag word for one neighbour state. A permanent binding reports both bits;
/// any other usable state reports only that an address is present; a state with
/// no address reports neither. # C: O(1)
pub fn flags(state: NudState) -> u32 {
    if matches!(state, NudState::Permanent) { ATF_PERM | ATF_COM }
    else if state.usable() { ATF_COM }
    else { 0 }
}

/// One neighbour row. Column widths are the ABI: the address pads to 16 then a
/// space, each flag word is `0x` plus a 10-wide field, the link address pads to
/// its own full width, and the mask column is a literal `*`. # C: O(1)
pub fn row(ip: Ipv4Addr, mac: Option<MacAddr>, state: NudState, iface: &str) -> String {
    use core::fmt::Write as _;
    let hw = match mac {
        Some(mac) => alloc::format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]),
        None => String::from(UNRESOLVED_HW_ADDRESS),
    };
    let o = ip.octets();
    let mut s = String::new();
    let _ = write!(s, "{:<16} 0x{:<10x}0x{:<10x}{:<17}     *        {}\n",
        alloc::format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]),
        HW_TYPE_ETHER, flags(state), hw, iface);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr = MacAddr([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);
    fn ip() -> Ipv4Addr { Ipv4Addr::new(10, 0, 2, 2) }

    #[test]
    fn a_resolved_neighbour_renders_the_column_exact_row_arp_reads() {
        assert_eq!(row(ip(), Some(MAC), NudState::Reachable, "eth0"),
            "10.0.2.2         0x1         0x2         52:55:0a:00:02:02     *        eth0\n");
    }

    #[test]
    fn a_permanent_binding_reports_both_flag_bits() {
        assert_eq!(flags(NudState::Permanent), ATF_PERM | ATF_COM);
        assert!(row(ip(), Some(MAC), NudState::Permanent, "eth0").contains("0x6"));
    }

    #[test]
    fn an_unresolved_neighbour_keeps_its_row_with_no_flags_and_a_zero_address() {
        for state in [NudState::Incomplete, NudState::Failed] {
            assert_eq!(flags(state), 0);
            let rendered = row(ip(), None, state, "eth0");
            assert!(rendered.contains("00:00:00:00:00:00"), "{rendered}");
            assert!(rendered.contains("0x0"), "{rendered}");
        }
    }

    #[test]
    fn every_usable_state_short_of_permanent_reports_only_a_present_address() {
        for state in [NudState::Reachable, NudState::Stale, NudState::Delay, NudState::Probe] {
            assert_eq!(flags(state), ATF_COM, "{state:?}");
        }
    }

    #[test]
    fn the_columns_stay_aligned_for_the_widest_and_narrowest_address() {
        let wide = row(Ipv4Addr::new(255, 255, 255, 255), Some(MAC), NudState::Stale, "eth0");
        let narrow = row(Ipv4Addr::new(1, 1, 1, 1), Some(MAC), NudState::Stale, "eth0");
        let column = |s: &str| s.find("0x1").expect("hardware type column");
        assert_eq!(column(&wide), column(&narrow));
        assert_eq!(HEADER.find("HW type"), Some(column(&wide)));
    }
}
