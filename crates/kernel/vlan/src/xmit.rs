// Where the tag goes on the way out, and the frame that results.

extern crate alloc;
use alloc::vec::Vec;

use crate::flags::reorder_hdr;
use crate::tci;

/// Placement chosen for the outgoing tag.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TagMode {
    /// The interface writes the 4 tag bytes into the frame as it builds it.
    Inline,
    /// The tag travels beside the frame; whoever can insert it does so last.
    Offload,
    /// The frame already carries this interface's tag — the header path put it
    /// there — so nothing further is added.
    AlreadyTagged,
}

/// Choose where the tag goes.
///
/// `outer_ethertype` is `None` while the interface is still building the link
/// header and `Some` for a frame handed over complete. A complete frame whose
/// outer type is not this interface's tag protocol is untagged as far as this
/// interface is concerned — a raw sender may inject one — so it is tagged out
/// of band even when this interface would otherwise write tags inline.
/// # C: O(1)
pub fn egress_tag_mode(flags: u32, outer_ethertype: Option<u16>, vlan_proto: u16) -> TagMode {
    if reorder_hdr(flags) { return TagMode::Offload; }
    match outer_ethertype {
        Some(et) if et == vlan_proto => TagMode::AlreadyTagged,
        Some(_) => TagMode::Offload,
        None => TagMode::Inline,
    }
}

/// A frame ready for the lower interface, plus the tag that did not fit inside
/// it. `hw_tag` is `Some` only when the lower interface inserts tags itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressFrame {
    pub frame: Vec<u8>,
    pub hw_tag: Option<(u16, u16)>,
}

/// Apply the chosen placement to a built frame.
///
/// An out-of-band tag survives as one only if the lower interface can insert
/// it; otherwise it is pushed into the frame here, before the frame is handed
/// down, so the bytes reach the wire either way.
/// # C: O(len)
pub fn apply(mode: TagMode, frame: &[u8], proto: u16, tci_value: u16, hw_tag_insert: bool)
    -> Result<EgressFrame, tci::TagError>
{
    match mode {
        TagMode::AlreadyTagged => Ok(EgressFrame { frame: frame.to_vec(), hw_tag: None }),
        TagMode::Inline => Ok(EgressFrame {
            frame: tci::insert(frame, proto, tci_value)?, hw_tag: None,
        }),
        TagMode::Offload if hw_tag_insert => Ok(EgressFrame {
            frame: frame.to_vec(), hw_tag: Some((proto, tci_value)),
        }),
        TagMode::Offload => Ok(EgressFrame {
            frame: tci::insert(frame, proto, tci_value)?, hw_tag: None,
        }),
    }
}
