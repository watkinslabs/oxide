// FDT header decode + validation, and the struct-block token constants
// every walker in this crate shares.
//
// Wire format is big-endian; every u32 is read with `from_be_bytes`.

use core::convert::TryInto;

/// Magic value at the start of every FDT blob (big-endian).
pub const FDT_MAGIC: u32 = 0xd00d_feed;

/// Compatibility version we know how to read; the FDT spec
/// guarantees backward-compat from 17 onwards.
pub const FDT_LAST_COMPAT_VERSION: u32 = 16;

/// Fixed on-wire size of the FDT header (spec §5.2).
pub const FDT_HEADER_LEN: usize = 40;

/// Size of one memory-reservation-block entry (`address` + `size`, both u64).
/// The block always ends with an all-zero entry, so a blob reserving nothing
/// still carries one.
pub const FDT_RSVMAP_ENTRY_LEN: usize = 16;

/// Largest blob this kernel accepts. The arm64 boot protocol caps the
/// firmware-supplied device tree at 2 MiB; we keep the historical 4 MiB
/// ceiling used by the boot memmap carve so a legal blob is never rejected.
pub const FDT_MAX_TOTALSIZE: usize = 4 * 1024 * 1024;

/// FDT header per the flattened-format spec §5.2. Fields are big-endian
/// on the wire; this struct is the host-order decoded form.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FdtHeader {
    pub magic:             u32,
    pub totalsize:         u32,
    pub off_dt_struct:     u32,
    pub off_dt_strings:    u32,
    pub off_mem_rsvmap:    u32,
    pub version:           u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys:   u32,
    pub size_dt_strings:   u32,
    pub size_dt_struct:    u32,
}

/// Errors from `parse_header`.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DtbError {
    Truncated      = 1,
    BadMagic       = 2,
    UnsupportedVersion = 3,
    Inval          = 22,
}

pub type KResult<T> = core::result::Result<T, DtbError>;

/// Validate + decode the FDT header from `bytes`. Returns `Truncated`
/// if the slice is too short, `BadMagic` if the first u32 isn't
/// `0xd00dfeed`, `UnsupportedVersion` if last_comp_version > our
/// known value.
/// # C: O(1)
pub fn parse_header(bytes: &[u8]) -> KResult<FdtHeader> {
    if bytes.len() < FDT_HEADER_LEN { return Err(DtbError::Truncated); }
    let h = FdtHeader {
        magic:             read_be_u32(bytes,  0)?,
        totalsize:         read_be_u32(bytes,  4)?,
        off_dt_struct:     read_be_u32(bytes,  8)?,
        off_dt_strings:    read_be_u32(bytes, 12)?,
        off_mem_rsvmap:    read_be_u32(bytes, 16)?,
        version:           read_be_u32(bytes, 20)?,
        last_comp_version: read_be_u32(bytes, 24)?,
        boot_cpuid_phys:   read_be_u32(bytes, 28)?,
        size_dt_strings:   read_be_u32(bytes, 32)?,
        size_dt_struct:    read_be_u32(bytes, 36)?,
    };
    if h.magic != FDT_MAGIC { return Err(DtbError::BadMagic); }
    if h.last_comp_version > FDT_LAST_COMPAT_VERSION {
        return Err(DtbError::UnsupportedVersion);
    }
    if h.totalsize as usize > bytes.len() { return Err(DtbError::Truncated); }
    if (h.off_dt_struct  as usize)  > h.totalsize as usize { return Err(DtbError::Inval); }
    if (h.off_dt_strings as usize)  > h.totalsize as usize { return Err(DtbError::Inval); }
    if (h.off_mem_rsvmap as usize)  > h.totalsize as usize { return Err(DtbError::Inval); }
    // The reservation block is mandatory and cannot overlap the header. A blob
    // pointing at 0 parses fine without this check and is refused outright by
    // any reader holding to the rule — which is how a synthesized tree can look
    // healthy from inside this kernel and be rejected by every consumer.
    if (h.off_mem_rsvmap as usize) < FDT_HEADER_LEN { return Err(DtbError::Inval); }
    Ok(h)
}

/// `totalsize` read from a header-only prefix (>= 8 bytes), without the
/// whole-blob checks `parse_header` performs. The boot path needs the size
/// BEFORE it can bound a full-blob slice, so it cannot use `parse_header`
/// (whose `totalsize <= len` check rejects a header-only prefix). `None` when
/// the prefix is short, the magic is wrong, or the size is out of range.
/// # C: O(1)
pub fn totalsize_from_prefix(prefix: &[u8]) -> Option<usize> {
    if prefix.len() < 8 { return None; }
    if read_be_u32(prefix, 0).ok()? != FDT_MAGIC { return None; }
    let ts = read_be_u32(prefix, 4).ok()? as usize;
    if ts < FDT_HEADER_LEN || ts > FDT_MAX_TOTALSIZE { return None; }
    Some(ts)
}

/// Wire-order u32 at `off`, bounds-checked. Every field in the blob is
/// big-endian, so this is the only integer decode in the crate. # C: O(1)
#[inline]
pub(crate) fn read_be_u32(buf: &[u8], off: usize) -> KResult<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)
        .ok_or(DtbError::Truncated)?
        .try_into()
        .map_err(|_| DtbError::Truncated)?;
    Ok(u32::from_be_bytes(bytes))
}

// FDT struct-block tokens per devicetree-specification §5.4.
pub(crate) const FDT_BEGIN_NODE: u32 = 1;
pub(crate) const FDT_END_NODE:   u32 = 2;
pub(crate) const FDT_PROP:       u32 = 3;
pub(crate) const FDT_NOP:        u32 = 4;
pub(crate) const FDT_END:        u32 = 9;
