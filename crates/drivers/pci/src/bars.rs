use crate::{Bdf, ConfigSpaceReader};

/// One decoded BAR. Header-type-0 devices have BAR0..BAR5.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Bar {
    /// Empty / unprogrammed slot (reads as 0).
    None,
    /// I/O port range. v1 only sees these on x86 legacy.
    Io { port: u32 },
    /// 32-bit memory BAR.
    Mem32 { base: u32, prefetch: bool },
    /// 64-bit memory BAR. Consumes BAR_N AND BAR_N+1.
    Mem64 { base: u64, prefetch: bool },
    /// The high half of a 64-bit BAR.
    HighHalfConsumed,
}

/// Linux-compatible resource flag bits for PCI BAR resources.
pub const IORESOURCE_IO: u64 = 0x0000_0100;
pub const IORESOURCE_MEM: u64 = 0x0000_0200;
pub const IORESOURCE_PREFETCH: u64 = 0x0000_2000;

/// One sized PCI BAR resource.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Resource {
    pub start: u64,
    pub end: u64,
    pub flags: u64,
}

impl Bar {
    /// Physical base of a memory BAR, or None for I/O/empty BAR slots.
    /// # C: O(1)
    pub const fn mem_base(self) -> Option<u64> {
        match self {
            Bar::Mem32 { base, .. } => Some(base as u64),
            Bar::Mem64 { base, .. } => Some(base),
            _ => None,
        }
    }
}

/// BAR offset in config space for header type 0. # C: O(1)
pub const fn bar_offset(idx: u8) -> u8 {
    debug_assert!(idx < 6);
    0x10 + idx * 4
}

/// Decode all 6 BARs of a header-type-0 device. # C: O(1) - at most 12 reads.
pub fn decode_bars<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> [Bar; 6] {
    let mut out = [Bar::None; 6];
    let mut idx = 0u8;
    while idx < 6 {
        let off = bar_offset(idx);
        let raw = r.read32(bdf, off);
        if raw == 0 {
            out[idx as usize] = Bar::None;
            idx += 1;
            continue;
        }
        if raw & 0x1 != 0 {
            out[idx as usize] = Bar::Io {
                port: raw & 0xFFFF_FFFC,
            };
            idx += 1;
            continue;
        }

        let prefetch = raw & 0x8 != 0;
        let kind = (raw >> 1) & 0x3;
        let lo = (raw & 0xFFFF_FFF0) as u64;
        if kind == 0x2 && idx + 1 < 6 {
            let hi = r.read32(bdf, bar_offset(idx + 1)) as u64;
            out[idx as usize] = Bar::Mem64 {
                base: (hi << 32) | lo,
                prefetch,
            };
            out[(idx + 1) as usize] = Bar::HighHalfConsumed;
            idx += 2;
        } else {
            out[idx as usize] = Bar::Mem32 {
                base: lo as u32,
                prefetch,
            };
            idx += 1;
        }
    }
    out
}

fn bar_size32(mask: u32, low_bits: u32) -> u64 {
    let m = mask & !low_bits;
    if m == 0 { 0 } else { (!m).wrapping_add(1) as u64 }
}

fn bar_size64(mask: u64, low_bits: u64) -> u64 {
    let m = mask & !low_bits;
    if m == 0 { 0 } else { (!m).wrapping_add(1) }
}

/// Size the programmed BARs of a header-type-0 function and return Linux
/// resource records. Temporarily disables I/O and memory decode while probing,
/// then restores every BAR and the command register.
/// # C: O(1) - at most 6 BARs, with bounded config-space writes.
pub fn probe_bar_resources<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> [Option<Resource>; 6] {
    let mut out = [None; 6];
    let cmd_status = r.read32(bdf, 0x04);
    let cmd = cmd_status & 0xFFFF;
    r.write32(bdf, 0x04, (cmd_status & 0xFFFF_0000) | (cmd & !0x3));

    let mut idx = 0u8;
    while idx < 6 {
        let off = bar_offset(idx);
        let orig = r.read32(bdf, off);
        if orig == 0 || orig == 0xFFFF_FFFF {
            idx += 1;
            continue;
        }

        if orig & 0x1 != 0 {
            r.write32(bdf, off, 0xFFFF_FFFF);
            let mask = r.read32(bdf, off);
            r.write32(bdf, off, orig);
            let start = (orig & 0xFFFF_FFFC) as u64;
            let size = bar_size32(mask, 0x3);
            if start != 0 && size != 0 {
                out[idx as usize] = Some(Resource {
                    start,
                    end: start.saturating_add(size).saturating_sub(1),
                    flags: IORESOURCE_IO,
                });
            }
            idx += 1;
            continue;
        }

        let prefetch = orig & 0x8 != 0;
        let kind = (orig >> 1) & 0x3;
        if kind == 0x2 && idx + 1 < 6 {
            let off_hi = bar_offset(idx + 1);
            let orig_hi = r.read32(bdf, off_hi);
            r.write32(bdf, off, 0xFFFF_FFFF);
            r.write32(bdf, off_hi, 0xFFFF_FFFF);
            let mask_lo = r.read32(bdf, off) as u64;
            let mask_hi = r.read32(bdf, off_hi) as u64;
            r.write32(bdf, off_hi, orig_hi);
            r.write32(bdf, off, orig);
            let start = ((orig_hi as u64) << 32) | ((orig & 0xFFFF_FFF0) as u64);
            let mask = (mask_hi << 32) | mask_lo;
            let size = bar_size64(mask, 0xF);
            if start != 0 && size != 0 {
                out[idx as usize] = Some(Resource {
                    start,
                    end: start.saturating_add(size).saturating_sub(1),
                    flags: IORESOURCE_MEM | if prefetch { IORESOURCE_PREFETCH } else { 0 },
                });
            }
            idx += 2;
        } else {
            r.write32(bdf, off, 0xFFFF_FFFF);
            let mask = r.read32(bdf, off);
            r.write32(bdf, off, orig);
            let start = (orig & 0xFFFF_FFF0) as u64;
            let size = bar_size32(mask, 0xF);
            if start != 0 && size != 0 {
                out[idx as usize] = Some(Resource {
                    start,
                    end: start.saturating_add(size).saturating_sub(1),
                    flags: IORESOURCE_MEM | if prefetch { IORESOURCE_PREFETCH } else { 0 },
                });
            }
            idx += 1;
        }
    }

    r.write32(bdf, 0x04, cmd_status);
    out
}
