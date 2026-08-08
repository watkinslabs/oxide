// One persistent-RAM zone: a header plus a circular byte buffer, laid out in
// memory that a warm reboot does not clear. The reference's `persistent_ram_*`
// family, expressed over a plain `&mut [u8]` so the whole decision surface —
// header validation, wrap arithmetic, overwrite policy, unwrapping a survivor —
// is reachable from `cargo test` on the host over a `Vec`.
//
// Layout (little-endian `u32` each, then the data area):
//
//     0  sig     signature XOR the zone's own tag; identifies OUR format
//     4  start   offset of the next byte to write, in the data area
//     8  size    valid bytes, saturating at the data capacity
//    12  crc     checksum of the valid bytes, in stream order
//
// The reference stops at the first three and checks integrity only when a
// platform enabled its optional error-correcting code. There is no
// error-correcting coder here, so the fourth word does the same job the
// weaker way: it cannot repair a bit flip, but a zone whose contents no
// longer match what was written is refused instead of published as a record.

use alloc::vec::Vec;

use crate::limits::ZONE_HDR_LEN;

/// The signature every zone header is stamped with, XOR the caller's
/// per-zone tag. A region of uninitialised or foreign memory reads as some
/// other value and is claimed rather than parsed.
pub const PERSISTENT_RAM_SIG: u32 = 0x4347_4244;

/// Seed for the zone checksum.
const CRC_SEED: u32 = 0xFFFF_FFFF;

/// What attaching to a zone found. The caller acts on the verdict; the zone
/// is left ready to write in every case.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Attach {
    /// No header of ours: fresh memory (a cold boot, or a region never used).
    /// Claimed and zeroed.
    Fresh,
    /// Our header, but nothing was ever written into it.
    Empty,
    /// Our header with `size`/`start` that cannot both be true, or contents
    /// that no longer match the recorded checksum. Discarded.
    Invalid,
    /// A survivor: `bytes` of valid data are recoverable.
    Valid { bytes: usize },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Hdr { sig: u32, start: u32, size: u32, crc: u32 }

fn rd32(z: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([z[off], z[off + 1], z[off + 2], z[off + 3]])
}

fn wr32(z: &mut [u8], off: usize, v: u32) {
    z[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn hdr(z: &[u8]) -> Hdr {
    Hdr { sig: rd32(z, 0), start: rd32(z, 4), size: rd32(z, 8), crc: rd32(z, 12) }
}

/// Bytes of a `len`-byte zone usable for data. A zone with no room for a
/// header has no capacity at all. # C: O(1)
pub fn capacity(len: usize) -> usize { len.saturating_sub(ZONE_HDR_LEN) }

/// Checksum of the valid bytes in stream order (oldest first), which is the
/// order [`read_all`] returns them in — so the check does not depend on where
/// the write cursor happens to sit. # C: O(size)
fn checksum(z: &[u8], start: usize, size: usize) -> u32 {
    let cap = capacity(z.len());
    let data = &z[ZONE_HDR_LEN..ZONE_HDR_LEN + cap];
    // Oldest byte first: a full buffer starts at the cursor and wraps; a
    // partly-filled one starts at zero.
    let head = if size == cap { start } else { 0 };
    // Two contiguous runs: cursor to end of the data area, then the wrap.
    let first = core::cmp::min(size, cap - head);
    let c = crc::crc32_update(CRC_SEED, &data[head..head + first]);
    crc::crc32_update(c, &data[..size - first])
}

fn stamp(z: &mut [u8], sig: u32, start: usize, size: usize) {
    let c = checksum(z, start, size);
    wr32(z, 0, sig);
    wr32(z, 4, start as u32);
    wr32(z, 8, size as u32);
    wr32(z, 12, c);
}

/// Reset the zone to empty, keeping its signature — the reference's
/// `persistent_ram_zap`. # C: O(1)
pub fn zap(z: &mut [u8], tag: u32) {
    if capacity(z.len()) == 0 { return; }
    let sig = tag ^ PERSISTENT_RAM_SIG;
    stamp(z, sig, 0, 0);
}

/// Attach to a zone that may hold a previous boot's contents.
///
/// Signature mismatch means the memory is not ours: claim it. A signature
/// match with impossible bookkeeping, or contents that no longer checksum,
/// is discarded rather than published. Anything else survives.
/// # C: O(size)
pub fn attach(z: &mut [u8], tag: u32) -> Attach {
    let cap = capacity(z.len());
    if cap == 0 { return Attach::Invalid; }
    let sig = tag ^ PERSISTENT_RAM_SIG;
    let h = hdr(z);
    if h.sig != sig {
        stamp(z, sig, 0, 0);
        return Attach::Fresh;
    }
    let (start, size) = (h.start as usize, h.size as usize);
    if size == 0 && start == 0 { return Attach::Empty; }
    if size > cap || start > size {
        stamp(z, sig, 0, 0);
        return Attach::Invalid;
    }
    if checksum(z, start, size) != h.crc {
        stamp(z, sig, 0, 0);
        return Attach::Invalid;
    }
    Attach::Valid { bytes: size }
}

/// The zone's valid bytes, oldest first — the reference's
/// `persistent_ram_save_old`, which unwraps the circular buffer into a linear
/// copy. Empty when nothing is stored. # C: O(size)
pub fn read_all(z: &[u8]) -> Vec<u8> {
    let cap = capacity(z.len());
    if cap == 0 { return Vec::new(); }
    let h = hdr(z);
    let (start, size) = (h.start as usize, h.size as usize);
    if size == 0 || size > cap || start > size { return Vec::new(); }
    let data = &z[ZONE_HDR_LEN..ZONE_HDR_LEN + cap];
    let head = if size == cap { start } else { 0 };
    let mut out = Vec::with_capacity(size);
    for i in 0..size {
        out.push(data[(head + i) % cap]);
    }
    out
}

/// Append `bytes`, overwriting the oldest content once the zone is full —
/// the reference's `persistent_ram_write`. A write longer than the zone
/// keeps its TAIL, because the newest bytes are the ones worth keeping.
/// Returns how many bytes were stored. # C: O(len bytes + size)
pub fn write(z: &mut [u8], tag: u32, bytes: &[u8]) -> usize {
    let cap = capacity(z.len());
    if cap == 0 || bytes.is_empty() { return 0; }
    let src = if bytes.len() > cap { &bytes[bytes.len() - cap..] } else { bytes };
    let h = hdr(z);
    let (mut start, mut size) = (h.start as usize, h.size as usize);
    if size > cap || start > cap { start = 0; size = 0; }
    let n = src.len();
    // The reference bumps the size counter first (saturating at capacity),
    // then advances and wraps the write cursor, returning its old value.
    size = core::cmp::min(size + n, cap);
    let at = start;
    start = (start + n) % cap;
    {
        let data = &mut z[ZONE_HDR_LEN..ZONE_HDR_LEN + cap];
        let rem = cap - at;
        if rem < n {
            data[at..at + rem].copy_from_slice(&src[..rem]);
            data[..n - rem].copy_from_slice(&src[rem..]);
        } else {
            data[at..at + n].copy_from_slice(src);
        }
    }
    let sig = tag ^ PERSISTENT_RAM_SIG;
    stamp(z, sig, start, size);
    n
}

#[cfg(test)]
#[path = "tests/zone.rs"]
mod tests;
