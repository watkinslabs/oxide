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

/// Optional RS8 protection for one zone. The defaults mirror Linux
/// `persistent_ram_init_ecc`: 128 data symbols per block and 16 parity
/// symbols, correcting up to eight corrupted symbols in each block.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EccConfig { pub block_size: usize, pub ecc_size: usize }

impl EccConfig {
    pub const fn new(ecc_size: usize) -> Option<EccConfig> {
        if ecc_size == 0 || ecc_size > 32 { None }
        else { Some(EccConfig { block_size: 128, ecc_size }) }
    }
}

#[derive(Copy, Clone)]
struct EccLayout { data_capacity: usize, parity_offset: usize, header_parity: usize, blocks: usize }

fn ecc_layout(len: usize, cfg: EccConfig) -> Option<EccLayout> {
    if cfg.block_size == 0 || cfg.ecc_size == 0 || cfg.block_size + cfg.ecc_size > 255
        || len < ZONE_HDR_LEN + cfg.ecc_size * 2 { return None; }
    let available = len - ZONE_HDR_LEN - cfg.ecc_size;
    let stride = cfg.block_size + cfg.ecc_size;
    let blocks = (available + stride - 1) / stride;
    let parity_total = (blocks + 1).checked_mul(cfg.ecc_size)?;
    let data_capacity = len.checked_sub(ZONE_HDR_LEN + parity_total)?;
    if data_capacity == 0 || data_capacity > blocks * cfg.block_size { return None; }
    Some(EccLayout {
        data_capacity,
        parity_offset: ZONE_HDR_LEN + data_capacity,
        header_parity: ZONE_HDR_LEN + data_capacity + blocks * cfg.ecc_size,
        blocks,
    })
}

/// Data bytes available after ECC parity is reserved inside the zone.
pub fn ecc_capacity(len: usize, cfg: EccConfig) -> Option<usize> {
    ecc_layout(len, cfg).map(|layout| layout.data_capacity)
}

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
fn checksum_with_capacity(z: &[u8], cap: usize, start: usize, size: usize) -> u32 {
    let data = &z[ZONE_HDR_LEN..ZONE_HDR_LEN + cap];
    // Oldest byte first: a full buffer starts at the cursor and wraps; a
    // partly-filled one starts at zero.
    let head = if size == cap { start } else { 0 };
    // Two contiguous runs: cursor to end of the data area, then the wrap.
    let first = core::cmp::min(size, cap - head);
    let c = crc::crc32_update(CRC_SEED, &data[head..head + first]);
    crc::crc32_update(c, &data[..size - first])
}

fn checksum(z: &[u8], start: usize, size: usize) -> u32 {
    checksum_with_capacity(z, capacity(z.len()), start, size)
}

fn stamp_with_capacity(z: &mut [u8], sig: u32, start: usize, size: usize, cap: usize) {
    let c = checksum_with_capacity(z, cap, start, size);
    wr32(z, 0, sig);
    wr32(z, 4, start as u32);
    wr32(z, 8, size as u32);
    wr32(z, 12, c);
}

fn stamp(z: &mut [u8], sig: u32, start: usize, size: usize) {
    stamp_with_capacity(z, sig, start, size, capacity(z.len()));
}

fn update_ecc(z: &mut [u8], layout: EccLayout, cfg: EccConfig) {
    for block in 0..layout.blocks {
        let off = block * cfg.block_size;
        if off >= layout.data_capacity { break; }
        let len = core::cmp::min(cfg.block_size, layout.data_capacity - off);
        let parity_off = layout.parity_offset + block * cfg.ecc_size;
        let (before, after) = z.split_at_mut(parity_off);
        let data = &before[ZONE_HDR_LEN + off..ZONE_HDR_LEN + off + len];
        crate::ecc::encode(data, &mut after[..cfg.ecc_size]);
    }
    let (before, after) = z.split_at_mut(layout.header_parity);
    crate::ecc::encode(&before[..ZONE_HDR_LEN], &mut after[..cfg.ecc_size]);
}

fn repair_ecc(z: &mut [u8], layout: EccLayout, cfg: EccConfig) -> Option<usize> {
    let mut corrected = 0;
    for block in 0..layout.blocks {
        let off = block * cfg.block_size;
        if off >= layout.data_capacity { break; }
        let len = core::cmp::min(cfg.block_size, layout.data_capacity - off);
        let parity_off = layout.parity_offset + block * cfg.ecc_size;
        let (before, after) = z.split_at_mut(parity_off);
        corrected += crate::ecc::decode(
            &mut before[ZONE_HDR_LEN + off..ZONE_HDR_LEN + off + len],
            &mut after[..cfg.ecc_size])?;
    }
    let (before, after) = z.split_at_mut(layout.header_parity);
    corrected += crate::ecc::decode(&mut before[..ZONE_HDR_LEN], &mut after[..cfg.ecc_size])?;
    Some(corrected)
}

/// Reset the zone to empty, keeping its signature — the reference's
/// `persistent_ram_zap`. # C: O(1)
pub fn zap(z: &mut [u8], tag: u32) {
    if capacity(z.len()) == 0 { return; }
    let sig = tag ^ PERSISTENT_RAM_SIG;
    stamp(z, sig, 0, 0);
}

/// ECC-enabled equivalent of [`zap`].
pub fn zap_with_ecc(z: &mut [u8], tag: u32, cfg: EccConfig) {
    let Some(layout) = ecc_layout(z.len(), cfg) else { return; };
    stamp(z, tag ^ PERSISTENT_RAM_SIG, 0, 0);
    update_ecc(z, layout, cfg);
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

/// Attach and repair an ECC-enabled zone before exposing its contents.
pub fn attach_with_ecc(z: &mut [u8], tag: u32, cfg: EccConfig) -> Attach {
    let Some(layout) = ecc_layout(z.len(), cfg) else { return Attach::Invalid; };
    let sig = tag ^ PERSISTENT_RAM_SIG;
    if rd32(z, 0) != sig {
        stamp(z, sig, 0, 0);
        update_ecc(z, layout, cfg);
        return Attach::Fresh;
    }
    if repair_ecc(z, layout, cfg).is_none() {
        stamp(z, sig, 0, 0);
        update_ecc(z, layout, cfg);
        return Attach::Invalid;
    }
    let h = hdr(z);
    if h.size == 0 && h.start == 0 { return Attach::Empty; }
    let cap = layout.data_capacity;
    let (start, size) = (h.start as usize, h.size as usize);
    if size > cap || start > size || checksum_with_capacity(z, cap, start, size) != h.crc {
        stamp(z, sig, 0, 0);
        update_ecc(z, layout, cfg);
        return Attach::Invalid;
    }
    Attach::Valid { bytes: size }
}

/// The zone's valid bytes, oldest first — the reference's
/// `persistent_ram_save_old`, which unwraps the circular buffer into a linear
/// copy. Empty when nothing is stored. # C: O(size)
pub fn read_all(z: &[u8]) -> Vec<u8> {
    read_all_capacity(z, capacity(z.len()))
}

fn read_all_capacity(z: &[u8], cap: usize) -> Vec<u8> {
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

/// Read an ECC-enabled zone. Call [`attach_with_ecc`] first; attach is where
/// correction is performed and the corrected bytes are made durable.
pub fn read_all_with_ecc(z: &[u8], cfg: EccConfig) -> Vec<u8> {
    let Some(layout) = ecc_layout(z.len(), cfg) else { return Vec::new(); };
    read_all_capacity(z, layout.data_capacity)
}

/// Append `bytes`, overwriting the oldest content once the zone is full —
/// the reference's `persistent_ram_write`. A write longer than the zone
/// keeps its TAIL, because the newest bytes are the ones worth keeping.
/// Returns how many bytes were stored. # C: O(len bytes + size)
pub fn write(z: &mut [u8], tag: u32, bytes: &[u8]) -> usize {
    write_inner(z, tag, bytes, capacity(z.len()), None)
}

fn write_inner(z: &mut [u8], tag: u32, bytes: &[u8], cap: usize, ecc: Option<(EccLayout, EccConfig)>) -> usize {
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
    if let Some((layout, _)) = ecc {
        stamp_with_capacity(z, sig, start, size, layout.data_capacity);
    } else {
        stamp(z, sig, start, size);
    }
    if let Some((layout, cfg)) = ecc { update_ecc(z, layout, cfg); }
    n
}

/// Append to an ECC-enabled zone and refresh the affected zone metadata.
pub fn write_with_ecc(z: &mut [u8], tag: u32, bytes: &[u8], cfg: EccConfig) -> usize {
    let Some(layout) = ecc_layout(z.len(), cfg) else { return 0; };
    write_inner(z, tag, bytes, layout.data_capacity, Some((layout, cfg)))
}

#[cfg(test)]
#[path = "tests/zone.rs"]
mod tests;
