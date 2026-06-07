// virtio-blk per Virtio 1.2 §5.2. Pure data shapes + request-chain
// encoding math — no MMIO, no HHDM. The arch-driven probe + the
// `drv-virtio-blk` engine consume these to build the 3-descriptor
// request chain (header IN + data + status WRITE) and decode the
// device status byte. Kept host-testable so the descriptor-direction
// invariant (T_IN data device-writable, T_OUT data device-readable)
// is proven in `cargo test` without a boot.

use crate::queue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

/// Request type at byte 0 of the 16-byte `virtio_blk_req` header
/// (spec §5.2.6). le32. T_GET_ID rides the read path (device-write
/// data) — used next stage for root identity.
pub const VIRTIO_BLK_T_IN:     u32 = 0;
pub const VIRTIO_BLK_T_OUT:    u32 = 1;
pub const VIRTIO_BLK_T_FLUSH:  u32 = 4;
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;

/// Status byte values written by the device into the status
/// descriptor (spec §5.2.6).
pub const VIRTIO_BLK_S_OK:     u8 = 0;
pub const VIRTIO_BLK_S_IOERR:  u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Feature bits (spec §5.2.3). Only the ones the engine negotiates.
pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
pub const VIRTIO_BLK_F_SEG_MAX:  u64 = 1 << 2;
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
pub const VIRTIO_BLK_F_FLUSH:    u64 = 1 << 9;

/// Default logical sector size when `VIRTIO_BLK_F_BLK_SIZE` is not
/// negotiated. virtio-blk sectors are always 512 on the wire for
/// addressing (the `sector` header field counts 512-byte units).
pub const VIRTIO_BLK_SECTOR_BYTES: u32 = 512;

/// `virtio_blk_config` device-cfg offsets (spec §5.2.4).
pub const BLK_CFG_OFF_CAPACITY: u64 = 0;   // le64 sectors (512B units)
pub const BLK_CFG_OFF_BLK_SIZE: u64 = 20;  // le32, valid iff F_BLK_SIZE
/// Length of the serial string returned by a `VIRTIO_BLK_T_GET_ID`
/// request (spec §5.2.6 — the device fills a 20-byte device-writable
/// data buffer with the configured serial). NOT a device-cfg offset:
/// device-cfg offset 24 is the topology block, not the serial.
pub const BLK_SERIAL_LEN: usize = 20;

/// Validate / clamp a device-reported `blk_size`. Logical sector size
/// must be ≥512 and a multiple of 512 (spec §5.2.4 + Linux
/// `virtio_blk` which rejects otherwise). Anything else (0, 100, 511,
/// 1000, …) truncates the sector-run math in the engine, so coerce to
/// the 512 default. Returns the validated size.
/// # C: O(1)
pub fn validate_blk_size(bs: u32) -> u32 {
    if bs >= VIRTIO_BLK_SECTOR_BYTES && bs % VIRTIO_BLK_SECTOR_BYTES == 0 {
        bs
    } else {
        VIRTIO_BLK_SECTOR_BYTES
    }
}

/// Convert device capacity (512-byte virtio sectors) to a count of
/// `blk_size`-sized logical blocks the `BlockDevice` reports. `blk_size`
/// is assumed already validated (≥512, multiple of 512). 0 if invalid.
/// # C: O(1)
pub fn capacity_blocks(capacity_sectors: u64, blk_size: u32) -> u64 {
    let bs = blk_size as u64;
    if bs == 0 { return 0; }
    capacity_sectors.saturating_mul(VIRTIO_BLK_SECTOR_BYTES as u64) / bs
}

/// One descriptor's wire fields (addr/len/flags/next) decomposed for
/// host testing. The kernel packs these into the 16-byte split-ring
/// descriptor; tests assert direction flags without touching memory.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DescSpec {
    pub addr:  u64,
    pub len:   u32,
    pub flags: u16,
    pub next:  u16,
}

/// Build the 3-descriptor chain for a single-sector-run blk request.
///
/// `hdr_pa`/`data_pa`/`status_pa` are the physical addresses of the
/// header (16B), data (`data_len` B) and status (1B) regions. `is_in`
/// selects direction:
///   * T_IN  (read):  data descriptor is device-WRITABLE (F_WRITE set)
///   * T_OUT (write): data descriptor is device-READABLE (F_WRITE clear)
/// The status descriptor is ALWAYS device-writable. For T_FLUSH pass
/// `data_len == 0`; the data descriptor is then omitted and the chain
/// is header→status (returned `[2]` valid, `[1]` is the status).
///
/// Returns `(descs, n)` where `descs[..n]` are the chain in order.
/// # C: O(1)
pub fn build_chain(
    is_in: bool,
    hdr_pa: u64,
    data_pa: u64,
    data_len: u32,
    status_pa: u64,
) -> ([DescSpec; 3], usize) {
    let mut d = [DescSpec { addr: 0, len: 0, flags: 0, next: 0 }; 3];
    // Header: always device-readable (driver writes it), chained.
    d[0] = DescSpec { addr: hdr_pa, len: 16, flags: VRING_DESC_F_NEXT, next: 1 };
    if data_len == 0 {
        // Flush: header → status (status device-writable, chain end).
        d[1] = DescSpec { addr: status_pa, len: 1, flags: VRING_DESC_F_WRITE, next: 0 };
        return (d, 2);
    }
    // Data: F_WRITE iff read (device fills it); cleared for write.
    let data_flags = VRING_DESC_F_NEXT | if is_in { VRING_DESC_F_WRITE } else { 0 };
    d[1] = DescSpec { addr: data_pa, len: data_len, flags: data_flags, next: 2 };
    // Status: device-writable, chain end.
    d[2] = DescSpec { addr: status_pa, len: 1, flags: VRING_DESC_F_WRITE, next: 0 };
    (d, 3)
}

/// Encode the 16-byte `virtio_blk_req` header into `out` (le).
/// `out` must be ≥16 bytes. `type_` is one of the `VIRTIO_BLK_T_*`.
/// # C: O(1)
pub fn encode_header(out: &mut [u8], type_: u32, sector: u64) {
    out[0..4].copy_from_slice(&type_.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes()); // reserved
    out[8..16].copy_from_slice(&sector.to_le_bytes());
}

/// Map a device status byte to Ok / error.
/// # C: O(1)
pub fn decode_status(status: u8) -> Result<(), u8> {
    if status == VIRTIO_BLK_S_OK { Ok(()) } else { Err(status) }
}

/// Trim a `GET_ID` serial buffer to its printable-ASCII core: stop at
/// the first NUL, drop trailing spaces, reject `/` (path-unsafe for a
/// registry name) and any non-printable byte by skipping it. Writes
/// into `out` (caller-provided, must be ≥ serial.len()); returns the
/// number of bytes written. Empty result (no NUL → all spaces, or no
/// printable bytes) means "use index-based naming" upstream.
/// # C: O(serial.len())
pub fn trim_serial(serial: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0usize;
    for &b in serial.iter() {
        if b == 0 { break; }
        if (0x20..0x7f).contains(&b) && b != b' ' && b != b'/' {
            out[n] = b;
            n += 1;
        }
    }
    n
}

/// Sector-run plan for one `BlockRequest`: the engine transfers in
/// 512-byte virtio sectors. Returns `(base_virtio_sector,
/// total_512B_sectors)`. `start_block`/`len_blocks` count `blk_size`
/// logical blocks; each spans `blk_size/512` virtio sectors. `None` on
/// overflow. The engine then loops `s in 0..total`, transferring
/// virtio sector `base + s` at byte offset `s*512` of the buffer.
/// # C: O(1)
pub fn sector_plan(
    start_block: u64,
    len_blocks: u32,
    blk_size: u32,
) -> Option<(u64, u64)> {
    let bs = blk_size as u64;
    if bs == 0 { return None; }
    let per = bs / VIRTIO_BLK_SECTOR_BYTES as u64;        // sectors / block
    let base = start_block.checked_mul(per)?;
    let total = (len_blocks as u64).checked_mul(per)?;
    Some((base, total))
}

/// Linux virtio-blk disk name for a 0-based registration order index:
/// 0→"vda", 1→"vdb", … 25→"vdz", 26→"vdaa", … Writes ASCII into `out`
/// (≥8 bytes is always enough); returns the byte length. Mirrors the
/// `sd`/`vd` base-26 bijective scheme `block/genhd` uses.
/// # C: O(log26 index)
pub fn vd_name(index: u32, out: &mut [u8; 8]) -> usize {
    out[0] = b'v';
    out[1] = b'd';
    // Bijective base-26 ("a".."z","aa"..) into a temp, reversed.
    let mut suffix = [0u8; 6];
    let mut k = 0usize;
    let mut n = index as u64 + 1; // 1-based for bijective base-26
    while n > 0 {
        n -= 1;
        suffix[k] = b'a' + (n % 26) as u8;
        k += 1;
        n /= 26;
    }
    let mut w = 2usize;
    while k > 0 {
        k -= 1;
        out[w] = suffix[k];
        w += 1;
    }
    w
}

/// Pack a `DescSpec` into the two little-endian u64 words a split-ring
/// descriptor occupies: word0 = addr, word1 = len | flags<<32 | next<<48.
/// Mirrors the kernel's `write_volatile` layout so the encoder is the
/// single source of truth for descriptor bit positions.
/// # C: O(1)
pub fn pack_desc(d: &DescSpec) -> (u64, u64) {
    let w1 = (d.len as u64)
        | ((d.flags as u64) << 32)
        | ((d.next as u64) << 48);
    (d.addr, w1)
}
