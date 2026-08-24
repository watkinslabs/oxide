//! Controller registry and per-controller state.
//!
//! One entry per controller, named by the index its `hci` device name is built
//! from. The index is allocated from the lowest free slot, so a controller that
//! goes away and comes back takes the same name — the tooling identifies a
//! controller by that name, and a monotonically increasing index would rename
//! the only controller on the machine every time it was reset.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::uapi::bt::{BdAddr, BDADDR_ANY};
use crate::uapi::hci::{DEV_CLASS_LEN, HCI_MAX_NAME_LENGTH};
use crate::uapi::hci_sock::{HCI_INIT, HCI_RAW, HCI_RUNNING, HCI_UP};
use super::cmd::CmdQueue;
use super::conn::ConnList;
use crate::l2cap::L2capRegistry;

/// Counters a controller reports through the device-info ioctl.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct DevStats {
    pub err_rx: u32,
    pub err_tx: u32,
    pub cmd_tx: u32,
    pub evt_rx: u32,
    pub acl_tx: u32,
    pub acl_rx: u32,
    pub sco_tx: u32,
    pub sco_rx: u32,
    pub byte_rx: u32,
    pub byte_tx: u32,
}

/// Buffer geometry the controller reported, which bounds every payload the host
/// may hand it. A zero packet count means the controller declared no separate
/// buffer of that kind and the ACL pool is used instead.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct BufferSizes {
    pub acl_mtu: u16,
    pub acl_pkts: u16,
    pub sco_mtu: u16,
    pub sco_pkts: u16,
    pub le_mtu: u16,
    pub le_pkts: u16,
}

/// Width of the supported-command bitmap the controller reports.
pub const HCI_COMMANDS_LEN: usize = 64;

/// Version and capability words read out of the controller during setup.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LocalInfo {
    pub hci_ver: u8,
    pub hci_rev: u16,
    pub lmp_ver: u8,
    pub lmp_subver: u16,
    pub manufacturer: u16,
    /// Page 0 of the local feature mask.
    pub features: [u8; 8],
    /// Page 1 of the extended feature mask, which carries the host-side flags.
    pub features_page1: [u8; 8],
    pub le_features: [u8; 8],
    /// Supported-command bitmap. A command whose bit is clear must not be sent:
    /// a controller answers an unsupported command with a refusal that the host
    /// would otherwise treat as a setup failure.
    pub commands: [u8; HCI_COMMANDS_LEN],
}

impl Default for LocalInfo {
    fn default() -> LocalInfo {
        LocalInfo {
            hci_ver: 0, hci_rev: 0, lmp_ver: 0, lmp_subver: 0, manufacturer: 0,
            features: [0; 8], features_page1: [0; 8], le_features: [0; 8],
            commands: [0; HCI_COMMANDS_LEN],
        }
    }
}

/// Feature-mask bit positions the setup sequence branches on. A feature bit is
/// named by its byte within the mask and its bit within that byte.
///
/// BR/EDR is the one capability expressed as a NEGATIVE bit: the mask carries a
/// "no BR/EDR" flag, so a controller that reports nothing at all reads as
/// BR/EDR capable, which is what a classic-only controller is. Reading it as a
/// positive bit inverts the whole BR/EDR half of the setup sequence.
pub const LMP_NO_BREDR_BYTE: usize = 4;
pub const LMP_NO_BREDR_BIT:  u8 = 5;
pub const LMP_LE_BYTE:    usize = 4;
pub const LMP_LE_BIT:     u8 = 6;
pub const LMP_ESCO_BYTE:  usize = 3;
pub const LMP_ESCO_BIT:   u8 = 7;
pub const LMP_SSP_BYTE:   usize = 6;
pub const LMP_SSP_BIT:    u8 = 3;
pub const LMP_RSSI_INQ_BYTE: usize = 3;
pub const LMP_RSSI_INQ_BIT:  u8 = 6;
pub const LMP_ESCO_2M_BYTE:  usize = 5;
pub const LMP_ESCO_2M_BIT:   u8 = 5;

/// Whether a feature bit is set in a mask. A byte index past the mask is
/// treated as clear rather than panicking: a controller may report a shorter
/// page than the host asks about. # C: O(1)
pub fn feature_set(mask: &[u8], byte: usize, bit: u8) -> bool {
    match mask.get(byte) { Some(b) => b & (1 << bit) != 0, None => false }
}

impl LocalInfo {
    /// Whether the controller speaks BR/EDR, which the mask states negatively.
    /// # C: O(1)
    pub fn bredr_capable(&self) -> bool {
        !feature_set(&self.features, LMP_NO_BREDR_BYTE, LMP_NO_BREDR_BIT)
    }
    /// Whether the controller speaks LE. Gates the whole LE half of setup.
    /// # C: O(1)
    pub fn le_capable(&self) -> bool { feature_set(&self.features, LMP_LE_BYTE, LMP_LE_BIT) }
    /// Whether the controller supports extended synchronous links. # C: O(1)
    pub fn esco_capable(&self) -> bool { feature_set(&self.features, LMP_ESCO_BYTE, LMP_ESCO_BIT) }
    /// Whether the controller supports secure simple pairing. # C: O(1)
    pub fn ssp_capable(&self) -> bool { feature_set(&self.features, LMP_SSP_BYTE, LMP_SSP_BIT) }
    /// Whether inquiry results can carry a signal-strength reading. # C: O(1)
    pub fn rssi_inquiry_capable(&self) -> bool {
        feature_set(&self.features, LMP_RSSI_INQ_BYTE, LMP_RSSI_INQ_BIT)
    }
    /// Whether 2-Mbit extended synchronous packets are available, which decides
    /// which entries of the voice-parameter table are usable. # C: O(1)
    pub fn esco_2m_capable(&self) -> bool {
        feature_set(&self.features, LMP_ESCO_2M_BYTE, LMP_ESCO_2M_BIT)
    }

    /// Whether the supported-command bitmap has the bit at this byte and bit
    /// position. # C: O(1)
    pub fn command_supported(&self, byte: usize, bit: u8) -> bool {
        feature_set(&self.commands, byte, bit)
    }
}

/// Everything one controller carries. Held without a lock here; the registry
/// owns the locking, so this whole type is testable without a kernel target.
pub struct HciDevState {
    pub index: u16,
    pub bus: u8,
    pub bdaddr: BdAddr,
    /// Bit set of the `HCI_*` device-state flags.
    pub flags: u32,
    pub info: LocalInfo,
    pub buffers: BufferSizes,
    pub class: [u8; DEV_CLASS_LEN],
    /// Local name, as many bytes as the controller reported, never terminated.
    pub local_name: Vec<u8>,
    pub cmd: CmdQueue,
    pub conns: ConnList,
    /// L2CAP ownership is per HCI connection, not global: handles are only
    /// unique within a controller.
    pub l2cap: L2capRegistry,
    pub stats: DevStats,
}

impl HciDevState {
    /// A controller freshly registered and not yet brought up. # C: O(1)
    pub fn new(index: u16, bus: u8) -> HciDevState {
        HciDevState {
            index, bus, bdaddr: BDADDR_ANY, flags: 0, info: LocalInfo::default(),
            buffers: BufferSizes::default(), class: [0; DEV_CLASS_LEN],
            local_name: Vec::new(), cmd: CmdQueue::new(), conns: ConnList::new(), l2cap: L2capRegistry::default(),
            stats: DevStats::default(),
        }
    }

    /// The controller's device name, which is what every tool identifies it by.
    /// # C: O(1)
    pub fn name(&self) -> String {
        let mut s = String::from("hci");
        push_index(&mut s, self.index);
        s
    }

    /// Whether a state flag is set. # C: O(1)
    pub fn flag(&self, bit: u32) -> bool { self.flags & (1u32 << bit) != 0 }

    /// Set or clear a state flag. # C: O(1)
    pub fn set_flag(&mut self, bit: u32, on: bool) {
        if on { self.flags |= 1u32 << bit; } else { self.flags &= !(1u32 << bit); }
    }

    /// Whether the controller is up and usable. # C: O(1)
    pub fn is_up(&self) -> bool { self.flag(HCI_UP) }

    /// Whether the transport is open, which is true from just before the setup
    /// sequence starts until just after the controller goes down — a window
    /// wider than `is_up`, because setup runs inside it. # C: O(1)
    pub fn is_running(&self) -> bool { self.flag(HCI_RUNNING) }

    /// Whether the setup sequence is in progress. # C: O(1)
    pub fn is_initialising(&self) -> bool { self.flag(HCI_INIT) }

    /// Whether a user-channel or raw owner has taken the controller, which
    /// suspends the host's own use of it. # C: O(1)
    pub fn is_raw(&self) -> bool { self.flag(HCI_RAW) }

    /// Record the local name the controller reported, bounded by the field
    /// width. A name is not terminated, so a reader bounds by the length.
    /// # C: O(n)
    pub fn set_local_name(&mut self, name: &[u8]) {
        let n = name.len().min(HCI_MAX_NAME_LENGTH);
        self.local_name.clear();
        self.local_name.extend_from_slice(&name[..n]);
    }

    /// Drop everything that describes a live controller, as going down
    /// requires: the links no longer exist and the queued commands name a state
    /// the controller has forgotten. # C: O(n)
    pub fn tear_down(&mut self) {
        self.l2cap.clear();
        self.conns.clear();
        self.cmd.flush();
        self.set_flag(HCI_UP, false);
        self.set_flag(HCI_INIT, false);
        self.set_flag(HCI_RUNNING, false);
    }
}

/// Append a controller index in decimal. Written here rather than through a
/// formatter so the name costs no formatting machinery in a `no_std` crate.
fn push_index(out: &mut String, mut index: u16) {
    if index == 0 { out.push('0'); return; }
    let mut digits = [0u8; 5];
    let mut n = 0;
    while index > 0 { digits[n] = b'0' + (index % 10) as u8; index /= 10; n += 1; }
    while n > 0 { n -= 1; out.push(digits[n] as char); }
}

/// The lowest index not already taken. Allocating the lowest free slot rather
/// than the next unused number is what keeps a controller's name stable across
/// a reset. # C: O(n^2) worst case over a small n
pub fn lowest_free_index(taken: &[u16]) -> Option<u16> {
    (0..u16::MAX).find(|candidate| !taken.contains(candidate))
}

#[cfg(test)]
#[path = "tests/dev.rs"]
mod tests;
