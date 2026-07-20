use super::{frame_protocol, ETH_HLEN};

pub(super) fn resolved_protocol(frame: &[u8], skb_proto: u16) -> u16 {
    if skb_proto != 0 { skb_proto } else { frame_protocol(frame) }
}

pub(super) fn l2_frame(frame: &[u8], proto: u16) -> Option<&[u8]> {
    if frame.len() >= ETH_HLEN && frame_protocol(frame) == proto { Some(frame) } else { None }
}

pub(super) fn l3_payload(frame: &[u8], proto: u16) -> &[u8] {
    l2_frame(frame, proto).map_or(frame, |l2| &l2[ETH_HLEN..])
}
