// Per-interface VLAN behaviour bits and the arithmetic of a flag change.

use syscall::errno::Errno;

/// Tag travels beside the frame rather than inside it: egress hands the tag to
/// the lower device out of band and ingress leaves the detagged frame detagged.
pub const VLAN_FLAG_REORDER_HDR: u32 = 0x1;
/// GARP VLAN registration join/leave around the interface's up/down edges.
pub const VLAN_FLAG_GVRP: u32 = 0x2;
/// Administrative state is decoupled from the lower device's.
pub const VLAN_FLAG_LOOSE_BINDING: u32 = 0x4;
/// Multiple VLAN registration join/leave around the interface's up/down edges.
pub const VLAN_FLAG_MVRP: u32 = 0x8;
/// Carrier is owned by a bridge above, not propagated from the lower device;
/// the interface starts with no carrier.
pub const VLAN_FLAG_BRIDGE_BINDING: u32 = 0x10;

/// Every bit an interface accepts. A request touching anything else is refused.
pub const VLAN_FLAG_MASK: u32 = VLAN_FLAG_REORDER_HDR | VLAN_FLAG_GVRP
    | VLAN_FLAG_LOOSE_BINDING | VLAN_FLAG_MVRP | VLAN_FLAG_BRIDGE_BINDING;

/// State a freshly created interface starts in.
pub const VLAN_FLAG_DEFAULT: u32 = VLAN_FLAG_REORDER_HDR;

/// Whether every requested bit is one the interface implements. # C: O(1)
pub const fn known(bits: u32) -> bool { bits & !VLAN_FLAG_MASK == 0 }

/// Fold a `{flags, mask}` request into the current word.
///
/// The refusal is keyed on the MASK, not the values: selecting an unimplemented
/// bit is an error even when the request clears it, because the caller is
/// asking for behaviour that does not exist either way.
/// # C: O(1)
pub const fn change(current: u32, flags: u32, mask: u32) -> Result<u32, Errno> {
    if !known(mask) { return Err(Errno::Einval); }
    Ok((current & !mask) | (flags & mask))
}

/// Whether the tag is carried out of band on this interface. # C: O(1)
pub const fn reorder_hdr(current: u32) -> bool { current & VLAN_FLAG_REORDER_HDR != 0 }
