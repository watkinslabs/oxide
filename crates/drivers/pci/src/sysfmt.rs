// sysfs/udev-facing PCI formatting (DVR-0008/0009/0010). Pure functions
// over the decoded config space so the kernel's sysfs `bus.rs` renders the
// exact Linux byte format `udevadm info`/libpci parse, and the hosted tests
// assert that format without a boot.
//
// Linux refs:
//   - `resource` file: drivers/pci/pci-sysfs.c `resource_show` prints one
//     line per BAR, `0x%016llx 0x%016llx 0x%016llx\n` = (start, end, flags),
//     flags = `pci_resource_flags()` (IORESOURCE_* bits below).
//   - `modalias`: `pci:v%08Xd%08Xsv%08Xsd%08Xbc%02Xsc%02Xi%02X` (file_pci.c).

extern crate alloc;
use alloc::string::String;

use crate::{bar_offset, Bar, Bdf, ConfigSpaceReader};

/// Linux `IORESOURCE_*` flag bits as printed in the sysfs `resource` file.
pub const IORESOURCE_IO:       u64 = 0x0000_0100;
pub const IORESOURCE_MEM:      u64 = 0x0000_0200;
pub const IORESOURCE_PREFETCH: u64 = 0x0000_2000;
pub const IORESOURCE_MEM_64:   u64 = 0x0010_0000;

/// One decoded BAR region as the sysfs `resource` file reports it:
/// `start`/`size` in bytes, `flags` the IORESOURCE_* set. An empty BAR
/// (or the high half of a 64-bit pair) is `{0,0,0}`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct BarRegion { pub start: u64, pub size: u64, pub flags: u64 }

impl BarRegion {
    /// Inclusive end (Linux `pci_resource_end`): `start+size-1`, or 0 when
    /// the region is empty. # C: O(1)
    pub fn end(self) -> u64 { if self.size == 0 { 0 } else { self.start + self.size - 1 } }
}

/// Size one 32-bit BAR by the standard write-all-ones / read-mask / restore
/// probe. `mask_bits` is the address mask (`!0xF` mem, `!0x3` io). Returns the
/// decoded size in bytes (0 if the BAR doesn't respond). # C: O(1)
fn size32<R: ConfigSpaceReader>(r: &R, bdf: Bdf, off: u8, orig: u32, mask_bits: u32) -> u64 {
    r.write32(bdf, off, 0xFFFF_FFFF);
    let probed = r.read32(bdf, off) & mask_bits;
    r.write32(bdf, off, orig);
    if probed == 0 { return 0; }
    ((!probed).wrapping_add(1) & mask_bits) as u64
}

/// Size a 64-bit BAR pair (`off` lo, `off+4` hi). # C: O(1)
fn size64<R: ConfigSpaceReader>(r: &R, bdf: Bdf, off: u8, orig_lo: u32, orig_hi: u32) -> u64 {
    r.write32(bdf, off,             0xFFFF_FFFF);
    r.write32(bdf, off.wrapping_add(4), 0xFFFF_FFFF);
    let lo = (r.read32(bdf, off) & 0xFFFF_FFF0) as u64;
    let hi = r.read32(bdf, off.wrapping_add(4)) as u64;
    r.write32(bdf, off,             orig_lo);
    r.write32(bdf, off.wrapping_add(4), orig_hi);
    let probed = (hi << 32) | lo;
    if probed == 0 { return 0; }
    (!probed).wrapping_add(1)
}

/// Decode + size all 6 BARs into Linux `resource`-file regions. Performs the
/// write-all-ones sizing probe with memory+IO decode temporarily disabled in
/// the command register (Linux `pci_read_bases`), restoring both the command
/// register and every BAR value before returning. # C: O(1) — ≤ ~16 cfg ops.
pub fn bar_regions<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> [BarRegion; 6] {
    // Disable IO(bit0)+MEM(bit1) decode during sizing; zero the status field
    // (high 16) on write so no W1C status bit is cleared. Restore at the end.
    let cmd_status = r.read32(bdf, 0x04);
    let cmd = cmd_status & 0x0000_FFFF;
    r.write32(bdf, 0x04, cmd & !0b11);

    let mut out = [BarRegion::default(); 6];
    let mut idx = 0u8;
    while idx < 6 {
        let off = bar_offset(idx);
        let raw = r.read32(bdf, off);
        if raw == 0 { idx += 1; continue; }
        if raw & 0x1 != 0 {
            let size = size32(r, bdf, off, raw, 0xFFFF_FFFC);
            out[idx as usize] = BarRegion { start: (raw & 0xFFFF_FFFC) as u64, size, flags: IORESOURCE_IO };
            idx += 1;
            continue;
        }
        let prefetch = raw & 0x8 != 0;
        let kind = (raw >> 1) & 0x3;
        let lo = (raw & 0xFFFF_FFF0) as u64;
        let mut flags = IORESOURCE_MEM;
        if prefetch { flags |= IORESOURCE_PREFETCH; }
        if kind == 0x2 && idx + 1 < 6 {
            let hi_raw = r.read32(bdf, bar_offset(idx + 1));
            let size = size64(r, bdf, off, raw, hi_raw);
            out[idx as usize] = BarRegion { start: ((hi_raw as u64) << 32) | lo, size, flags: flags | IORESOURCE_MEM_64 };
            // High half: empty resource slot (Linux leaves resource[i+1] zeroed).
            idx += 2;
        } else {
            let size = size32(r, bdf, off, raw, 0xFFFF_FFF0);
            out[idx as usize] = BarRegion { start: lo, size, flags };
            idx += 1;
        }
    }
    r.write32(bdf, 0x04, cmd);
    out
}

/// Render the sysfs `resource` file body: one `0x<start> 0x<end> 0x<flags>`
/// line per BAR (6 lines), matching `resource_show`. # C: O(1)
pub fn resource_text(regions: &[BarRegion; 6]) -> String {
    let mut s = String::with_capacity(6 * 58);
    for reg in regions.iter() {
        s.push_str(&alloc::format!("0x{:016x} 0x{:016x} 0x{:016x}\n", reg.start, reg.end(), reg.flags));
    }
    s
}

/// Render the sysfs `modalias` body (with trailing `\n`). `class` is the
/// 8-bit base class, `subclass`/`prog_if` the next two bytes. # C: O(1)
pub fn modalias(vendor: u16, device: u16, subv: u16, subd: u16,
                class: u8, subclass: u8, prog_if: u8) -> String {
    alloc::format!(
        "pci:v{:08X}d{:08X}sv{:08X}sd{:08X}bc{:02X}sc{:02X}i{:02X}\n",
        vendor as u32, device as u32, subv as u32, subd as u32, class, subclass, prog_if)
}

/// Decode the 6 BARs to regions WITHOUT the sizing probe (read-only base
/// only). Used where write-probe is undesirable; `size` stays 0. # C: O(1)
pub fn bar_regions_readonly(bars: &[Bar; 6]) -> [BarRegion; 6] {
    let mut out = [BarRegion::default(); 6];
    for (i, b) in bars.iter().enumerate() {
        out[i] = match *b {
            Bar::Io { port }            => BarRegion { start: port as u64, size: 0, flags: IORESOURCE_IO },
            Bar::Mem32 { base, prefetch } => {
                let f = IORESOURCE_MEM | if prefetch { IORESOURCE_PREFETCH } else { 0 };
                BarRegion { start: base as u64, size: 0, flags: f }
            }
            Bar::Mem64 { base, prefetch } => {
                let f = IORESOURCE_MEM | IORESOURCE_MEM_64 | if prefetch { IORESOURCE_PREFETCH } else { 0 };
                BarRegion { start: base, size: 0, flags: f }
            }
            Bar::None | Bar::HighHalfConsumed => BarRegion::default(),
        };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::vec::Vec;

    // Reader that models BAR sizing: each BAR offset has a (orig, size_mask).
    // Writing 0xFFFFFFFF returns the size mask on next read; any other write
    // is stored and read back verbatim.
    struct SizeReader {
        cur:  Mutex<HashMap<(Bdf, u8), u32>>,
        mask: HashMap<(Bdf, u8), u32>, // size-probe readback for this offset
    }
    impl ConfigSpaceReader for SizeReader {
        fn read32(&self, bdf: Bdf, off: u8) -> u32 {
            *self.cur.lock().unwrap().get(&(bdf, off)).unwrap_or(&0)
        }
        fn write32(&self, bdf: Bdf, off: u8, val: u32) {
            let v = if val == 0xFFFF_FFFF {
                *self.mask.get(&(bdf, off)).unwrap_or(&0)
            } else { val };
            self.cur.lock().unwrap().insert((bdf, off), v);
        }
    }

    fn mk(orig: &[(u8, u32)], mask: &[(u8, u32)]) -> (SizeReader, Bdf) {
        let bdf = Bdf { bus: 0, device: 3, function: 0 };
        let mut cur = HashMap::new();
        let mut m = HashMap::new();
        cur.insert((bdf, 0x04u8), 0x0010_0006); // cmd=0x6 (MEM|BM), status set
        for (o, v) in orig { cur.insert((bdf, *o), *v); }
        for (o, v) in mask { m.insert((bdf, *o), *v); }
        (SizeReader { cur: Mutex::new(cur), mask: m }, bdf)
    }

    #[test]
    fn mem32_region_sized() {
        // BAR0 = Mem32 base 0x1000_0000, size 0x1000 (mask 0xFFFFF000).
        let (r, bdf) = mk(&[(0x10, 0x1000_0000)], &[(0x10, 0xFFFF_F000)]);
        let regs = bar_regions(&r, bdf);
        assert_eq!(regs[0], BarRegion { start: 0x1000_0000, size: 0x1000, flags: IORESOURCE_MEM });
        assert_eq!(regs[0].end(), 0x1000_0FFF);
        // command register restored to original low 16 (0x0006).
        assert_eq!(r.read32(bdf, 0x04) & 0xFFFF, 0x0006);
        // BAR value restored.
        assert_eq!(r.read32(bdf, 0x10), 0x1000_0000);
    }

    #[test]
    fn mem64_prefetch_region_sized() {
        // BAR0/1 = Mem64 prefetch, base 0x8000_0000, size 0x40_0000 (4MiB).
        let (r, bdf) = mk(
            &[(0x10, 0x8000_000C), (0x14, 0x0000_0000)],
            &[(0x10, 0xFFC0_0000), (0x14, 0xFFFF_FFFF)]);
        let regs = bar_regions(&r, bdf);
        assert_eq!(regs[0].start, 0x8000_0000);
        assert_eq!(regs[0].size, 0x40_0000);
        assert_eq!(regs[0].flags, IORESOURCE_MEM | IORESOURCE_MEM_64 | IORESOURCE_PREFETCH);
        assert_eq!(regs[1], BarRegion::default(), "64-bit high half is an empty slot");
    }

    #[test]
    fn io_region_sized() {
        // BAR0 = IO port 0xC000, size 0x20.
        let (r, bdf) = mk(&[(0x10, 0x0000_C001)], &[(0x10, 0xFFFF_FFE1)]);
        let regs = bar_regions(&r, bdf);
        assert_eq!(regs[0].start, 0xC000);
        assert_eq!(regs[0].size, 0x20);
        assert_eq!(regs[0].flags, IORESOURCE_IO);
    }

    #[test]
    fn resource_text_six_lines_linux_format() {
        let mut regs = [BarRegion::default(); 6];
        regs[0] = BarRegion { start: 0x1000_0000, size: 0x1000, flags: IORESOURCE_MEM };
        let txt = resource_text(&regs);
        let lines: Vec<&str> = txt.lines().collect();
        assert_eq!(lines.len(), 6, "one line per BAR");
        assert_eq!(lines[0], "0x0000000010000000 0x0000000010000fff 0x0000000000000200");
        assert_eq!(lines[1], "0x0000000000000000 0x0000000000000000 0x0000000000000000");
    }

    #[test]
    fn modalias_linux_format() {
        // virtio-net 1af4:1041, subsys 1af4:0001, class 02:00:00.
        let s = modalias(0x1AF4, 0x1041, 0x1AF4, 0x0001, 0x02, 0x00, 0x00);
        assert_eq!(s, "pci:v00001AF4d00001041sv00001AF4sd00000001bc02sc00i00\n");
    }
}
