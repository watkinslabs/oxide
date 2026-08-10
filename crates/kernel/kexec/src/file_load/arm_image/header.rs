// The arm64 `Image` header, and the two questions it answers: is this file an
// arm64 kernel at all, and can THIS machine start it.
//
// Ungated on purpose. A header decode is pure byte arithmetic over a fixed
// 64-byte layout, and an offset that is one field out still produces a
// plausible-looking `image_size` — a placement that is wrong by megabytes and
// a machine that comes back with nothing on the console. Every offset below is
// therefore exercised by a hosted test against a real vendor kernel image.

extern crate alloc;

use crate::validate::{Error, KResult};

/// Bytes of header the boot protocol defines. The file may be shorter than
/// this only if it is not a kernel.
pub const HDR_SIZE: usize = 64;

/// Field offsets, in header order.
pub const OFF_CODE0: usize = 0x00;
/// See [`OFF_CODE0`].
pub const OFF_CODE1: usize = 0x04;
/// See [`OFF_CODE0`].
pub const OFF_TEXT_OFFSET: usize = 0x08;
/// See [`OFF_CODE0`].
pub const OFF_IMAGE_SIZE: usize = 0x10;
/// See [`OFF_CODE0`].
pub const OFF_FLAGS: usize = 0x18;
/// See [`OFF_CODE0`].
pub const OFF_RES2: usize = 0x20;
/// See [`OFF_CODE0`].
pub const OFF_RES3: usize = 0x28;
/// See [`OFF_CODE0`].
pub const OFF_RES4: usize = 0x30;
/// See [`OFF_CODE0`].
pub const OFF_MAGIC: usize = 0x38;
/// See [`OFF_CODE0`].
pub const OFF_RES5: usize = 0x3c;

/// The four magic bytes at [`OFF_MAGIC`], `"ARM\x64"` — `0x64` is `d`, so the
/// literal reads `ARMd`. Written as the escape the boot protocol spells it
/// with would be a lie about the byte at index 3.
pub const IMAGE_MAGIC: [u8; 4] = *b"ARMd";

/// `flags` bit 0: image byte order. See [`FLAG_LE`] / [`FLAG_BE`].
pub const FLAG_BE_SHIFT: u32 = 0;
/// Width of the byte-order field.
pub const FLAG_BE_MASK: u64 = 0x1;
/// `flags` bits [2:1]: the page size the image was built for.
pub const FLAG_PAGE_SIZE_SHIFT: u32 = FLAG_BE_SHIFT + 1;
/// Width of the page-size field.
pub const FLAG_PAGE_SIZE_MASK: u64 = 0x3;
/// `flags` bit 3: whether the image is position-independent of `text_offset`.
pub const FLAG_PHYS_BASE_SHIFT: u32 = FLAG_PAGE_SIZE_SHIFT + 2;
/// Width of the physical-base field.
pub const FLAG_PHYS_BASE_MASK: u64 = 0x1;

/// Byte-order field: little-endian image.
pub const FLAG_LE: u64 = 0;
/// Byte-order field: big-endian image.
pub const FLAG_BE: u64 = 1;
/// Page-size field: unspecified — pre-v3.17 images, and the value no check
/// applies to.
pub const FLAG_PAGE_SIZE_UNSPEC: u64 = 0;
/// Page-size field: 4 KiB.
pub const FLAG_PAGE_SIZE_4K: u64 = 1;
/// Page-size field: 16 KiB.
pub const FLAG_PAGE_SIZE_16K: u64 = 2;
/// Page-size field: 64 KiB.
pub const FLAG_PAGE_SIZE_64K: u64 = 3;
/// Physical-base field: `text_offset` is meaningful rather than assumed 0.
pub const FLAG_PHYS_BASE: u64 = 1;

/// The header, decoded out of its little-endian wire form.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ImageHeader {
    /// First instruction word, or the `MZ` stub of an EFI image.
    pub code0: u32,
    /// Second instruction word.
    pub code1: u32,
    /// Where the image wants to sit relative to the 2 MiB-aligned base.
    pub text_offset: u64,
    /// Bytes the image occupies once loaded, including its BSS.
    pub image_size: u64,
    /// Byte order, page size and physical-base bits.
    pub flags: u64,
    /// Magic, compared against [`IMAGE_MAGIC`].
    pub magic: [u8; 4],
}

impl ImageHeader {
    /// Byte-order field of `flags`.
    /// # C: O(1)
    pub fn endianness(&self) -> u64 { (self.flags >> FLAG_BE_SHIFT) & FLAG_BE_MASK }
    /// Page-size field of `flags`.
    /// # C: O(1)
    pub fn page_size_field(&self) -> u64 {
        (self.flags >> FLAG_PAGE_SIZE_SHIFT) & FLAG_PAGE_SIZE_MASK
    }
    /// Physical-base field of `flags`.
    /// # C: O(1)
    pub fn phys_base_field(&self) -> u64 {
        (self.flags >> FLAG_PHYS_BASE_SHIFT) & FLAG_PHYS_BASE_MASK
    }
}

/// Which translation granules the running machine's PE implements, and whether
/// it can run code of the opposite byte order.
///
/// Passed in rather than read from a system register here, so the refusal
/// decision is reachable from a hosted test. A check that could only be
/// exercised on real silicon is a check nobody ever sees go red.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Caps {
    /// 4 KiB granule implemented.
    pub g4: bool,
    /// 16 KiB granule implemented.
    pub g16: bool,
    /// 64 KiB granule implemented.
    pub g64: bool,
    /// The PE implements the opposite byte order at EL1.
    pub mixed_endian: bool,
    /// This kernel itself is big-endian.
    pub be_kernel: bool,
}

/// Decode `magic`-bearing bytes into a header.
///
/// `EINVAL` when the file is shorter than the header — a truncated file is not
/// "not a kernel", it is a file the question cannot be asked of, and the
/// reference answers both with the same errno.
/// # C: O(1)
pub fn decode(kernel: &[u8]) -> KResult<ImageHeader> {
    if kernel.len() < HDR_SIZE { return Err(Error::Inval); }
    Ok(ImageHeader {
        code0: le32(kernel, OFF_CODE0),
        code1: le32(kernel, OFF_CODE1),
        text_offset: le64(kernel, OFF_TEXT_OFFSET),
        image_size: le64(kernel, OFF_IMAGE_SIZE),
        flags: le64(kernel, OFF_FLAGS),
        magic: [kernel[OFF_MAGIC], kernel[OFF_MAGIC + 1],
                kernel[OFF_MAGIC + 2], kernel[OFF_MAGIC + 3]],
    })
}

/// `image_probe`: length and magic, and nothing else.
///
/// The feature checks deliberately do NOT live here. The reference probes with
/// the magic alone and refuses on endianness and granule inside the load, so a
/// machine that cannot start an otherwise valid image reports EINVAL rather
/// than falling through to "no loader recognised this file" (ENOEXEC) and
/// blaming the file.
/// # C: O(1)
pub fn probe(kernel: &[u8]) -> KResult<()> {
    let h = decode(kernel)?;
    if h.magic != IMAGE_MAGIC { return Err(Error::Inval); }
    Ok(())
}

/// The refusals the load makes after the probe: an ambiguous header, a byte
/// order this PE cannot run, a granule it does not implement.
///
/// `image_size == 0` is the pre-v3.17 header, where the field is reserved and
/// the image's extent is unknowable — there is no size to reserve and no
/// safe guess, so it is refused rather than assumed.
/// # C: O(1)
pub fn check_features(h: &ImageHeader, caps: &Caps) -> KResult<()> {
    if h.image_size == 0 { return Err(Error::Inval); }

    let be_image = h.endianness() == FLAG_BE;
    if be_image != caps.be_kernel && !caps.mixed_endian { return Err(Error::Inval); }

    let ok = match h.page_size_field() {
        FLAG_PAGE_SIZE_4K => caps.g4,
        FLAG_PAGE_SIZE_16K => caps.g16,
        FLAG_PAGE_SIZE_64K => caps.g64,
        // Unspecified: the image states no requirement, so the machine cannot
        // fail to meet one.
        _ => true,
    };
    if !ok { return Err(Error::Inval); }
    Ok(())
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3],
                        b[at + 4], b[at + 5], b[at + 6], b[at + 7]])
}

#[cfg(test)]
mod tests;
