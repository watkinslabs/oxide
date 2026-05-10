// Flattened Device Tree (FDT) header per `36§4` U-Boot path. v1
// scope: validate the magic + compatibility version, expose
// totalsize / offsets so the kernel can copy the blob out of the
// bootloader-owned region into BSS before continuing. Full property
// walking lands once we have a real consumer (PMM init, ACPI fallback).
//
// FDT spec: https://devicetree-specification.readthedocs.io/en/v0.4/
// flattened-format.html
//
// Wire format is big-endian; we read u32 / u64 fields with explicit
// `from_be_bytes`.

extern crate alloc;
use core::convert::TryInto;

/// Magic value at the start of every FDT blob (big-endian).
pub const FDT_MAGIC: u32 = 0xd00d_feed;

/// Compatibility version we know how to read; the FDT spec
/// guarantees backward-compat from 17 onwards.
pub const FDT_LAST_COMPAT_VERSION: u32 = 16;

/// FDT header per `flattened-format.html` §5.2. Fields are big-endian
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
    if bytes.len() < 40 { return Err(DtbError::Truncated); }
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
    Ok(h)
}

#[inline]
fn read_be_u32(buf: &[u8], off: usize) -> KResult<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)
        .ok_or(DtbError::Truncated)?
        .try_into()
        .map_err(|_| DtbError::Truncated)?;
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(
        magic: u32, totalsize: u32, version: u32, last_comp: u32,
    ) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![0u8; 64];
        v[0..4]  .copy_from_slice(&magic.to_be_bytes());
        v[4..8]  .copy_from_slice(&totalsize.to_be_bytes());
        v[8..12] .copy_from_slice(&40u32.to_be_bytes());
        v[12..16].copy_from_slice(&48u32.to_be_bytes());
        v[16..20].copy_from_slice(&32u32.to_be_bytes());
        v[20..24].copy_from_slice(&version.to_be_bytes());
        v[24..28].copy_from_slice(&last_comp.to_be_bytes());
        v[28..32].copy_from_slice(&0u32.to_be_bytes());
        v[32..36].copy_from_slice(&8u32.to_be_bytes());
        v[36..40].copy_from_slice(&8u32.to_be_bytes());
        v
    }

    #[test]
    fn rejects_truncated() {
        let buf = alloc::vec![0u8; 16];
        assert_eq!(parse_header(&buf).err(), Some(DtbError::Truncated));
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = build(0xdead_beef, 64, 17, FDT_LAST_COMPAT_VERSION);
        assert_eq!(parse_header(&buf).err(), Some(DtbError::BadMagic));
    }

    #[test]
    fn accepts_known_version() {
        let buf = build(FDT_MAGIC, 64, 17, FDT_LAST_COMPAT_VERSION);
        let h = parse_header(&buf).unwrap();
        assert_eq!(h.magic, FDT_MAGIC);
        assert_eq!(h.totalsize, 64);
        assert_eq!(h.last_comp_version, FDT_LAST_COMPAT_VERSION);
    }

    #[test]
    fn rejects_future_compat_version() {
        let buf = build(FDT_MAGIC, 64, 99, FDT_LAST_COMPAT_VERSION + 1);
        assert_eq!(parse_header(&buf).err(), Some(DtbError::UnsupportedVersion));
    }

    #[test]
    fn rejects_totalsize_exceeding_buffer() {
        let mut buf = build(FDT_MAGIC, 1024, 17, FDT_LAST_COMPAT_VERSION);
        buf.truncate(64); // claim totalsize=1024 but only 64 B present
        assert_eq!(parse_header(&buf).err(), Some(DtbError::Truncated));
    }

    #[test]
    fn fdt_magic_is_big_endian_d00dfeed() {
        // Pin the constant — bootloaders write the magic in big-endian
        // wire order; we read with `from_be_bytes`.
        assert_eq!(FDT_MAGIC, 0xd00d_feed);
    }
}
