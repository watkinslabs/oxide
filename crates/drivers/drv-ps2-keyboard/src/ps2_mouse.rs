// Standard three-byte PS/2 relative packet assembly. This stays outside the
// kernel-target gate so byte framing has a fast hosted verification path.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Packet {
    pub(crate) dx: i16,
    pub(crate) dy: i16,
    pub(crate) left: bool,
    pub(crate) right: bool,
    pub(crate) middle: bool,
    pub(crate) wheel: i8,
    pub(crate) hwheel: i8,
    pub(crate) side: bool,
    pub(crate) extra: bool,
}

/// Negotiated PS/2 packet layout. The device-ID reply, not a controller or
/// platform identifier, selects this layout.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PacketMode {
    Bare,
    Wheel,
    Explorer,
}

impl PacketMode {
    pub(crate) const fn packet_len(self) -> u8 {
        match self { Self::Bare => 3, Self::Wheel | Self::Explorer => 4 }
    }
}

const EXPLORER_VERTICAL: u8 = 0x80;
const EXPLORER_HORIZONTAL: u8 = 0x40;
const EXPLORER_BUTTON_MASK: u8 = 0x30;
const EXPLORER_SIDE: u8 = 0x10;
const EXPLORER_EXTRA: u8 = 0x20;

const fn sign_extend_4(value: u8) -> i8 {
    let value = value & 0x0f;
    if value & 0x08 != 0 { (value | 0xf0) as i8 } else { value as i8 }
}

const fn sign_extend_6(value: u8) -> i8 {
    let value = value & 0x3f;
    if value & 0x20 != 0 { (value | 0xc0) as i8 } else { value as i8 }
}

/// Decode one standard, IntelliMouse, or Explorer PS/2 packet. Overflow packets are discarded: the
/// controller reports saturated deltas and forwarding them creates false input.
/// # C: O(1)
pub(crate) fn decode(bytes: [u8; 4], mode: PacketMode) -> Option<Packet> {
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
        wheel: match mode {
            PacketMode::Bare => 0,
            PacketMode::Wheel => -(bytes[3] as i8),
            PacketMode::Explorer if bytes[3] & (EXPLORER_VERTICAL | EXPLORER_HORIZONTAL) == EXPLORER_VERTICAL => -sign_extend_6(bytes[3]),
            PacketMode::Explorer if bytes[3] & (EXPLORER_VERTICAL | EXPLORER_HORIZONTAL) == 0 => -sign_extend_4(bytes[3]),
            PacketMode::Explorer => 0,
        },
        hwheel: match mode {
            PacketMode::Explorer if bytes[3] & (EXPLORER_VERTICAL | EXPLORER_HORIZONTAL) == EXPLORER_HORIZONTAL => -sign_extend_6(bytes[3]),
            _ => 0,
        },
        side: mode == PacketMode::Explorer && bytes[3] & (EXPLORER_VERTICAL | EXPLORER_HORIZONTAL | EXPLORER_BUTTON_MASK) == EXPLORER_SIDE,
        extra: mode == PacketMode::Explorer && bytes[3] & (EXPLORER_VERTICAL | EXPLORER_HORIZONTAL | EXPLORER_BUTTON_MASK) == EXPLORER_EXTRA,
    })
}

#[derive(Copy, Clone)]
pub(crate) struct Assembler {
    bytes: [u8; 4],
    len: u8,
    mode: PacketMode,
}

impl Assembler {
    pub(crate) const fn new(mode: PacketMode) -> Self { Self { bytes: [0; 4], len: 0, mode } }

    /// Drop a partial packet when the controller device lifecycle changes.
    /// # C: O(1)
    pub(crate) fn clear(&mut self) { self.len = 0; }

    /// Consume one auxiliary byte and return a packet only at packet boundary.
    /// # C: O(1)
    pub(crate) fn push(&mut self, byte: u8) -> Option<Packet> {
        if self.len == 0 && byte & 0x08 == 0 { return None; }
        self.bytes[self.len as usize] = byte;
        self.len += 1;
        if self.len != self.mode.packet_len() { return None; }
        self.len = 0;
        decode(self.bytes, self.mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_requires_sync_and_converts_signed_axes() {
        assert_eq!(decode([0, 1, 1, 0], PacketMode::Bare), None);
        let packet = decode([0x19, 0xfe, 0x02, 0], PacketMode::Bare).expect("standard packet");
        assert_eq!(packet.dx, -2);
        assert_eq!(packet.dy, -2);
        assert!(packet.left);
    }

    #[test]
    fn assembler_discards_desynchronized_prefix() {
        let mut assembler = Assembler::new(PacketMode::Bare);
        assert_eq!(assembler.push(0x01), None);
        assert_eq!(assembler.push(0x08), None);
        assert_eq!(assembler.push(3), None);
        assert_eq!(assembler.push(4).map(|packet| (packet.dx, packet.dy)), Some((3, -4)));
    }

    #[test]
    fn overflow_packet_does_not_become_false_relative_motion() {
        assert_eq!(decode([0xc8, 1, 2, 0], PacketMode::Bare), None);
    }

    #[test]
    fn wheel_packets_consume_the_fourth_byte_and_invert_the_axis() {
        let mut assembler = Assembler::new(PacketMode::Wheel);
        assert_eq!(assembler.push(0x08), None);
        assert_eq!(assembler.push(0), None);
        assert_eq!(assembler.push(0), None);
        assert_eq!(assembler.push(2).map(|packet| packet.wheel), Some(-2));
    }

    #[test]
    fn explorer_packet_reports_extra_buttons_and_horizontal_wheel() {
        let packet = decode([0x08, 0, 0, 0x41], PacketMode::Explorer).expect("explorer packet");
        assert_eq!(packet.wheel, 0);
        assert_eq!(packet.hwheel, -1);
        assert!(!packet.side);
        assert!(!packet.extra);
    }

    #[test]
    fn explorer_vertical_wheel_uses_low_nibble_sign() {
        let packet = decode([0x08, 0, 0, 0x8f], PacketMode::Explorer).expect("explorer wheel");
        assert_eq!(packet.wheel, -15);
        let buttons = decode([0x08, 0, 0, 0x10], PacketMode::Explorer).expect("explorer buttons");
        assert!(buttons.side);
    }
}
