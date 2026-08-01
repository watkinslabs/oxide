// Byte-granular config-space access behind a dword accessor, plus the
// window rules userspace sees through the `config` sysfs blob.
//
// Sub-dword writes are read-modify-write on the containing dword: the
// accessor contract is dword-only, so a byte store re-emits its three
// neighbours unchanged.

use crate::types::{Bdf, ConfigSpaceReader};
use crate::uapi::{
    CFG_SPACE_SIZE, CFG_SPACE_UNPRIV_CARDBUS_SIZE, CFG_SPACE_UNPRIV_SIZE, HEADER_TYPE_CARDBUS,
    HEADER_TYPE_MASK, HEADER_TYPE_NORMAL, SUBSYSTEM_ID_OFF, SUBSYSTEM_VENDOR_ID_OFF,
    CB_SUBSYSTEM_ID_OFF, CB_SUBSYSTEM_VENDOR_ID_OFF, INTERRUPT_LINE_OFF, INTERRUPT_PIN_OFF,
};

/// Bytes of config space a reader may observe. A privileged reader sees the
/// whole space; everyone else sees the header window only, widened for a
/// CardBus bridge. # C: O(1)
pub fn visible_size(privileged: bool, header_type: u8) -> usize {
    if privileged {
        CFG_SPACE_SIZE
    } else if header_type & HEADER_TYPE_MASK == HEADER_TYPE_CARDBUS {
        CFG_SPACE_UNPRIV_CARDBUS_SIZE
    } else {
        CFG_SPACE_UNPRIV_SIZE
    }
}

/// Bytes actually transferred for a `count`-byte access at `off` against a
/// `size`-byte window: past the end is a short (possibly empty) transfer, not
/// an error. # C: O(1)
pub fn span(size: usize, off: u64, count: usize) -> usize {
    let size = size as u64;
    if off >= size { return 0; }
    core::cmp::min(count as u64, size - off) as usize
}

/// Dword offset containing byte `off`. # C: O(1)
fn dword_base(off: usize) -> u8 { (off & !0b11) as u8 }

/// Read `buf.len()` bytes of config space starting at `off`, assembling from
/// dword reads. Callers clamp `off`/len with [`span`] first. # C: O(n)
pub fn read_bytes<R: ConfigSpaceReader>(r: &R, bdf: Bdf, off: usize, buf: &mut [u8]) {
    let mut pos = off;
    let end = off + buf.len();
    while pos < end {
        let base = dword_base(pos) as usize;
        let word = r.read32(bdf, dword_base(pos)).to_le_bytes();
        let stop = core::cmp::min(base + word.len(), end);
        for byte in pos..stop {
            buf[byte - off] = word[byte - base];
        }
        pos = stop;
    }
}

/// Write `buf` into config space at `off`, read-modify-writing every partially
/// covered dword. Callers clamp `off`/len with [`span`] first. # C: O(n)
pub fn write_bytes<R: ConfigSpaceReader>(r: &R, bdf: Bdf, off: usize, buf: &[u8]) {
    let mut pos = off;
    let end = off + buf.len();
    while pos < end {
        let base = dword_base(pos) as usize;
        let mut word = r.read32(bdf, dword_base(pos)).to_le_bytes();
        let stop = core::cmp::min(base + word.len(), end);
        for byte in pos..stop {
            word[byte - base] = buf[byte - off];
        }
        r.write32(bdf, dword_base(pos), u32::from_le_bytes(word));
        pos = stop;
    }
}

/// Read one 16-bit config register. # C: O(1)
pub fn read16<R: ConfigSpaceReader>(r: &R, bdf: Bdf, off: u8) -> u16 {
    let word = r.read32(bdf, dword_base(off as usize));
    ((word >> ((off as u32 & 0b11) * 8)) & 0xFFFF) as u16
}

/// Read one 8-bit config register. # C: O(1)
pub fn read8<R: ConfigSpaceReader>(r: &R, bdf: Bdf, off: u8) -> u8 {
    let word = r.read32(bdf, dword_base(off as usize));
    ((word >> ((off as u32 & 0b11) * 8)) & 0xFF) as u8
}

/// `(subsystem_vendor, subsystem_device)` for a function. Only endpoints and
/// CardBus bridges carry the pair; a PCI-to-PCI bridge reports zeroes.
/// # C: O(1)
pub fn subsystem_ids<R: ConfigSpaceReader>(r: &R, bdf: Bdf, header_type: u8) -> (u16, u16) {
    match header_type & HEADER_TYPE_MASK {
        HEADER_TYPE_NORMAL => (
            read16(r, bdf, SUBSYSTEM_VENDOR_ID_OFF),
            read16(r, bdf, SUBSYSTEM_ID_OFF),
        ),
        HEADER_TYPE_CARDBUS => (
            read16(r, bdf, CB_SUBSYSTEM_VENDOR_ID_OFF),
            read16(r, bdf, CB_SUBSYSTEM_ID_OFF),
        ),
        _ => (0, 0),
    }
}

/// Legacy INTx line register value, or 0 when the function reports no INTx
/// pin. # C: O(1)
pub fn interrupt_line<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u32 {
    if read8(r, bdf, INTERRUPT_PIN_OFF) == 0 { return 0; }
    read8(r, bdf, INTERRUPT_LINE_OFF) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::HEADER_TYPE_BRIDGE;
    use std::collections::HashMap;
    use std::vec;

    struct Fake { m: HashMap<u8, u32> }
    impl ConfigSpaceReader for Fake {
        fn read32(&self, _bdf: Bdf, offset: u8) -> u32 {
            self.m.get(&offset).copied().unwrap_or(0)
        }
        fn write32(&self, _bdf: Bdf, _offset: u8, _val: u32) { unreachable!("read-only fake") }
    }

    struct Recorder { m: std::sync::Mutex<HashMap<u8, u32>> }
    impl ConfigSpaceReader for Recorder {
        fn read32(&self, _bdf: Bdf, offset: u8) -> u32 {
            self.m.lock().unwrap().get(&offset).copied().unwrap_or(0)
        }
        fn write32(&self, _bdf: Bdf, offset: u8, val: u32) {
            self.m.lock().unwrap().insert(offset, val);
        }
    }

    const BDF: Bdf = Bdf { bus: 0, device: 3, function: 0 };

    fn fake() -> Fake {
        let mut m = HashMap::new();
        // vendor 1af4 device 1050, class/revision, header type 0, subsystem 1af4:1100.
        m.insert(0x00, 0x1050_1AF4);
        m.insert(0x08, 0x0300_0001);
        m.insert(0x0c, 0x0000_0000);
        m.insert(0x2c, 0x1100_1AF4);
        m.insert(0x3c, 0x0000_010B);
        Fake { m }
    }

    #[test]
    fn unprivileged_window_is_the_header_only() {
        assert_eq!(visible_size(false, HEADER_TYPE_NORMAL), 64);
        assert_eq!(visible_size(false, HEADER_TYPE_BRIDGE), 64);
        assert_eq!(visible_size(false, HEADER_TYPE_CARDBUS), 128);
        // The multifunction bit never widens or narrows the window.
        assert_eq!(visible_size(false, HEADER_TYPE_CARDBUS | 0x80), 128);
        assert_eq!(visible_size(true, HEADER_TYPE_NORMAL), 256);
        assert_eq!(visible_size(true, HEADER_TYPE_CARDBUS), 256);
    }

    #[test]
    fn access_past_the_window_is_short_not_an_error() {
        assert_eq!(span(64, 0, 4096), 64);
        assert_eq!(span(64, 60, 8), 4);
        assert_eq!(span(64, 64, 8), 0);
        assert_eq!(span(64, 4096, 8), 0);
        assert_eq!(span(256, 0, 256), 256);
    }

    #[test]
    fn byte_reads_assemble_little_endian_dwords() {
        let r = fake();
        let mut buf = [0u8; 4];
        read_bytes(&r, BDF, 0, &mut buf);
        assert_eq!(buf, [0xF4, 0x1A, 0x50, 0x10]);
    }

    #[test]
    fn unaligned_spanning_read_crosses_dwords() {
        let r = fake();
        let mut buf = [0u8; 3];
        read_bytes(&r, BDF, 0x2b, &mut buf);
        // 0x2b is an unset dword's top byte, then the subsystem vendor id.
        assert_eq!(buf, [0x00, 0xF4, 0x1A]);
    }

    #[test]
    fn revision_and_class_share_one_dword() {
        let r = fake();
        assert_eq!(read8(&r, BDF, crate::uapi::REVISION_ID_OFF), 0x01);
        let mut buf = [0u8; 4];
        read_bytes(&r, BDF, 0x08, &mut buf);
        assert_eq!(buf, [0x01, 0x00, 0x00, 0x03]);
    }

    #[test]
    fn subsystem_ids_follow_the_header_type() {
        let r = fake();
        assert_eq!(subsystem_ids(&r, BDF, HEADER_TYPE_NORMAL), (0x1AF4, 0x1100));
        assert_eq!(subsystem_ids(&r, BDF, HEADER_TYPE_BRIDGE), (0, 0));
        assert_eq!(subsystem_ids(&r, BDF, HEADER_TYPE_NORMAL | 0x80), (0x1AF4, 0x1100));
    }

    #[test]
    fn interrupt_line_is_zero_without_a_pin() {
        let mut r = fake();
        assert_eq!(interrupt_line(&r, BDF), 0x0B);
        r.m.insert(0x3c, 0x0000_000B);
        assert_eq!(interrupt_line(&r, BDF), 0);
    }

    #[test]
    fn sub_dword_write_preserves_neighbouring_bytes() {
        let r = Recorder { m: std::sync::Mutex::new(HashMap::new()) };
        r.write32(BDF, 0x04, 0xAABB_CCDD);
        write_bytes(&r, BDF, 0x05, &[0x11]);
        assert_eq!(r.read32(BDF, 0x04), 0xAABB_11DD);
    }

    #[test]
    fn spanning_write_touches_every_covered_dword() {
        let r = Recorder { m: std::sync::Mutex::new(HashMap::new()) };
        r.write32(BDF, 0x04, 0xFFFF_FFFF);
        r.write32(BDF, 0x08, 0xFFFF_FFFF);
        write_bytes(&r, BDF, 0x06, &[1, 2, 3, 4]);
        assert_eq!(r.read32(BDF, 0x04), 0x0201_FFFF);
        assert_eq!(r.read32(BDF, 0x08), 0xFFFF_0403);
    }

    #[test]
    fn write_then_read_round_trips_a_byte_range() {
        let r = Recorder { m: std::sync::Mutex::new(HashMap::new()) };
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        write_bytes(&r, BDF, 0x11, &payload);
        let mut back = [0u8; 5];
        read_bytes(&r, BDF, 0x11, &mut back);
        assert_eq!(&back[..], &payload[..]);
    }
}
