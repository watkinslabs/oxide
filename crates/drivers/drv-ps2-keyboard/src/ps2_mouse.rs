// Standard three-byte PS/2 relative packet assembly. This stays outside the
// kernel-target gate so byte framing has a fast hosted verification path.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Packet {
    pub(crate) dx: i16,
    pub(crate) dy: i16,
    pub(crate) left: bool,
    pub(crate) right: bool,
    pub(crate) middle: bool,
}

/// Decode one standard three-byte packet. Overflow packets are discarded: the
/// controller reports saturated deltas and forwarding them creates false input.
/// # C: O(1)
pub(crate) fn decode(bytes: [u8; 3]) -> Option<Packet> {
    let flags = bytes[0];
    if flags & 0x08 == 0 || flags & 0xc0 != 0 { return None; }
    let dx = i16::from(bytes[1]) - if flags & 0x10 != 0 { 256 } else { 0 };
    let dy = i16::from(bytes[2]) - if flags & 0x20 != 0 { 256 } else { 0 };
    Some(Packet {
        dx,
        dy: -dy,
        left: flags & 0x01 != 0,
        right: flags & 0x02 != 0,
        middle: flags & 0x04 != 0,
    })
}

#[derive(Copy, Clone)]
pub(crate) struct Assembler {
    bytes: [u8; 3],
    len: u8,
}

impl Assembler {
    pub(crate) const fn new() -> Self { Self { bytes: [0; 3], len: 0 } }

    /// Drop a partial packet when the controller device lifecycle changes.
    /// # C: O(1)
    pub(crate) fn clear(&mut self) { self.len = 0; }

    /// Consume one auxiliary byte and return a packet only at packet boundary.
    /// # C: O(1)
    pub(crate) fn push(&mut self, byte: u8) -> Option<Packet> {
        if self.len == 0 && byte & 0x08 == 0 { return None; }
        self.bytes[self.len as usize] = byte;
        self.len += 1;
        if self.len != 3 { return None; }
        self.len = 0;
        decode(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_requires_sync_and_converts_signed_axes() {
        assert_eq!(decode([0, 1, 1]), None);
        let packet = decode([0x19, 0xfe, 0x02]).expect("standard packet");
        assert_eq!(packet.dx, -2);
        assert_eq!(packet.dy, -2);
        assert!(packet.left);
    }

    #[test]
    fn assembler_discards_desynchronized_prefix() {
        let mut assembler = Assembler::new();
        assert_eq!(assembler.push(0x01), None);
        assert_eq!(assembler.push(0x08), None);
        assert_eq!(assembler.push(3), None);
        assert_eq!(assembler.push(4).map(|packet| (packet.dx, packet.dy)), Some((3, -4)));
    }

    #[test]
    fn overflow_packet_does_not_become_false_relative_motion() {
        assert_eq!(decode([0xc8, 1, 2]), None);
    }
}
