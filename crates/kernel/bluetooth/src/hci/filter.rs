//! Raw-socket packet filter.
//!
//! A raw HCI socket sees every frame on its controller unless it installs a
//! filter. The filter is three independent screens: a packet-type mask, an
//! event mask covering the first sixty-four event codes, and — for command
//! packets only — an opcode screen expressed as a group and command bit index.
//!
//! Every mask is a mask, not a modulus: a bit index past the mask's width fails
//! the screen instead of wrapping onto an unrelated bit. That distinction is
//! the difference between a socket seeing nothing and a socket seeing the wrong
//! traffic, and it is why the event codes above the mask width are dropped.

use crate::uapi::hci::{HCI_COMMAND_PKT, HCI_EVENT_PKT};
use crate::uapi::hci_cmd::{opcode_ocf, opcode_ogf};
use crate::uapi::hci_sock::{
    HCI_FLT_EVENT_BITS, HCI_FLT_OCF_BITS, HCI_FLT_OGF_BITS, HCI_FLT_TYPE_BITS,
    HCI_UFILTER_EVENT_MASK_OFF, HCI_UFILTER_LEN, HCI_UFILTER_OPCODE_OFF,
    HCI_UFILTER_TYPE_MASK_OFF,
};

/// The filter a raw socket carries. A freshly created socket has every bit
/// clear, which passes nothing until the socket sets a filter — a socket that
/// received everything by default would leak another process's traffic.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Filter {
    pub type_mask: u32,
    pub event_mask: [u32; 2],
    pub opcode: u16,
}

impl Filter {
    /// A filter passing nothing. # C: O(1)
    pub fn new() -> Filter { Filter::default() }

    /// A filter passing every packet type and every event code, which is what a
    /// socket asks for when it wants an unfiltered trace. # C: O(1)
    pub fn pass_all() -> Filter {
        Filter { type_mask: u32::MAX, event_mask: [u32::MAX, u32::MAX], opcode: 0 }
    }

    /// Decode a filter from its ABI form. # C: O(1)
    pub fn from_wire(buf: &[u8]) -> Option<Filter> {
        if buf.len() < HCI_UFILTER_LEN { return None; }
        let word = |off: usize| u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let op = HCI_UFILTER_OPCODE_OFF;
        Some(Filter {
            type_mask: word(HCI_UFILTER_TYPE_MASK_OFF),
            event_mask: [word(HCI_UFILTER_EVENT_MASK_OFF), word(HCI_UFILTER_EVENT_MASK_OFF + 4)],
            opcode: u16::from_le_bytes([buf[op], buf[op + 1]]),
        })
    }

    /// Encode the filter into its ABI form. # C: O(1)
    pub fn to_wire(&self) -> [u8; HCI_UFILTER_LEN] {
        let mut out = [0u8; HCI_UFILTER_LEN];
        out[HCI_UFILTER_TYPE_MASK_OFF..HCI_UFILTER_TYPE_MASK_OFF + 4]
            .copy_from_slice(&self.type_mask.to_ne_bytes());
        out[HCI_UFILTER_EVENT_MASK_OFF..HCI_UFILTER_EVENT_MASK_OFF + 4]
            .copy_from_slice(&self.event_mask[0].to_ne_bytes());
        out[HCI_UFILTER_EVENT_MASK_OFF + 4..HCI_UFILTER_EVENT_MASK_OFF + 8]
            .copy_from_slice(&self.event_mask[1].to_ne_bytes());
        out[HCI_UFILTER_OPCODE_OFF..HCI_UFILTER_OPCODE_OFF + 2]
            .copy_from_slice(&self.opcode.to_le_bytes());
        out
    }

    /// Whether the packet-type screen passes this type. # C: O(1)
    pub fn passes_type(&self, pkt_type: u8) -> bool {
        if pkt_type as u32 > HCI_FLT_TYPE_BITS { return false; }
        self.type_mask & (1u32 << pkt_type) != 0
    }

    /// Whether the event screen passes this event code. # C: O(1)
    pub fn passes_event(&self, event: u8) -> bool {
        let bit = event as u32;
        if bit > HCI_FLT_EVENT_BITS { return false; }
        let (word, shift) = ((bit / 32) as usize, bit % 32);
        self.event_mask[word] & (1u32 << shift) != 0
    }

    /// Whether the command screen passes this opcode. An opcode of zero in the
    /// filter means the socket named no command, so every command passes; a
    /// non-zero one screens on the group and command indexes separately, which
    /// is how a socket watches one whole command group. # C: O(1)
    pub fn passes_opcode(&self, opcode: u16) -> bool {
        if self.opcode == 0 { return true; }
        let (want_ogf, want_ocf) = (opcode_ogf(self.opcode), opcode_ocf(self.opcode));
        let (ogf, ocf) = (opcode_ogf(opcode), opcode_ocf(opcode));
        if want_ogf as u32 > HCI_FLT_OGF_BITS || want_ocf as u32 > HCI_FLT_OCF_BITS { return false; }
        want_ogf == ogf && want_ocf == ocf
    }

    /// Whether a whole frame passes. Only the two typed screens apply to their
    /// own packet type; every other type is decided by the type mask alone.
    /// # C: O(1)
    pub fn passes(&self, pkt_type: u8, head: u16) -> bool {
        if !self.passes_type(pkt_type) { return false; }
        match pkt_type {
            HCI_EVENT_PKT   => self.passes_event(head as u8),
            HCI_COMMAND_PKT => self.passes_opcode(head),
            _ => true,
        }
    }
}

#[cfg(test)]
#[path = "tests/filter.rs"]
mod tests;
