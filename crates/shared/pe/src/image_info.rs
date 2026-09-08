// SECTION_IMAGE_INFORMATION derivation for an image-attributed section.
//
// The record a section query returns is derived from the COFF file header and
// the PE32+ optional header, plus the file's own size. Every field here is
// observable through NtQuerySection(SectionImageInformation); the encoding is
// the 64-byte 64-bit layout of that record.
use crate::parser::{Error, Image};

/// Encoded byte length of the image-information record on 64-bit.
pub const SECTION_IMAGE_INFORMATION_BYTES: usize = 64;

/// The image's section alignment is not a multiple of the page size, so it is
/// mapped as a flat file rather than section by section.
pub const IMAGE_FLAGS_MAPPED_FLAT: u8 = 0x08;
/// The image opted into a dynamic base and carries what a relocation needs.
pub const IMAGE_FLAGS_DYNAMICALLY_RELOCATED: u8 = 0x04;

const DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const FILE_RELOCS_STRIPPED: u16 = 0x0001;
const COM_DESCRIPTOR_DIRECTORY: usize = 14;

/// One image's loader-visible parameters, in the order the encoded record uses.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ImageInformation {
    pub transfer_address: u64, pub zero_bits: u32,
    pub maximum_stack_size: u64, pub committed_stack_size: u64,
    pub subsystem: u32, pub subsystem_minor: u16, pub subsystem_major: u16,
    pub os_major: u16, pub os_minor: u16,
    pub image_characteristics: u16, pub dll_characteristics: u16, pub machine: u16,
    pub contains_code: bool, pub image_flags: u8,
    pub loader_flags: u32, pub file_size: u32, pub checksum: u32,
}

impl ImageInformation {
    /// Encode the record a 64-bit section query copies out. # C: O(1)
    pub fn encode(&self) -> [u8; SECTION_IMAGE_INFORMATION_BYTES] {
        let mut out = [0u8; SECTION_IMAGE_INFORMATION_BYTES];
        out[0..8].copy_from_slice(&self.transfer_address.to_le_bytes());
        out[8..12].copy_from_slice(&self.zero_bits.to_le_bytes());
        out[16..24].copy_from_slice(&self.maximum_stack_size.to_le_bytes());
        out[24..32].copy_from_slice(&self.committed_stack_size.to_le_bytes());
        out[32..36].copy_from_slice(&self.subsystem.to_le_bytes());
        out[36..38].copy_from_slice(&self.subsystem_minor.to_le_bytes());
        out[38..40].copy_from_slice(&self.subsystem_major.to_le_bytes());
        out[40..42].copy_from_slice(&self.os_major.to_le_bytes());
        out[42..44].copy_from_slice(&self.os_minor.to_le_bytes());
        out[44..46].copy_from_slice(&self.image_characteristics.to_le_bytes());
        out[46..48].copy_from_slice(&self.dll_characteristics.to_le_bytes());
        out[48..50].copy_from_slice(&self.machine.to_le_bytes());
        out[50] = u8::from(self.contains_code);
        out[51] = self.image_flags;
        out[52..56].copy_from_slice(&self.loader_flags.to_le_bytes());
        out[56..60].copy_from_slice(&self.file_size.to_le_bytes());
        out[60..64].copy_from_slice(&self.checksum.to_le_bytes());
        out
    }
    /// Re-encode with the transfer address rebased onto a mapped view. # C: O(1)
    pub fn at_base(&self, base: u64, entry_rva: u32) -> Self {
        Self { transfer_address: base.wrapping_add(entry_rva as u64), ..*self }
    }
    /// Whether the image asked to be relocatable away from its preferred base. # C: O(1)
    pub fn dynamically_relocated(&self) -> bool { self.image_flags & IMAGE_FLAGS_DYNAMICALLY_RELOCATED != 0 }
}

/// Derive the image-information record for one parsed image. # C: O(N_sections)
pub fn image_information(image: &Image<'_>, file_size: u64) -> Result<ImageInformation, Error> {
    let raw = image.raw;
    let pe = u32at(raw, 0x3c)? as usize;
    let coff = pe.checked_add(4).ok_or(Error::Einval)?;
    let opt = coff.checked_add(20).ok_or(Error::Einval)?;
    let machine = u16at(raw, coff)?;
    let image_characteristics = u16at(raw, coff + 18)?;
    let size_of_code = u32at(raw, opt + 4)?;
    let os_major = u16at(raw, opt + 40)?; let os_minor = u16at(raw, opt + 42)?;
    let subsystem_major = u16at(raw, opt + 48)?; let subsystem_minor = u16at(raw, opt + 50)?;
    let checksum = u32at(raw, opt + 64)?;
    let subsystem = u16at(raw, opt + 68)? as u32;
    let dll_characteristics = u16at(raw, opt + 70)?;
    let maximum_stack_size = u64at(raw, opt + 72)?;
    let committed_stack_size = u64at(raw, opt + 80)?;
    let page = crate::image_view::PAGE_BYTES;
    // Code is present when the optional header says so, when there is an entry
    // point, when the alignment forces a flat mapping, or when any section
    // header carries the executable characteristic.
    let mut contains_code = size_of_code != 0 || image.entry_rva != 0
        || image.section_alignment % page != 0;
    for section in &image.sections {
        if section.characteristics.contains(crate::parser::SectionFlags::MEM_EXECUTE) { contains_code = true; }
    }
    // A directory is present only when it names both an address and an
    // extent; one half alone describes nothing the image can be read from.
    let present = |index: usize| { let dir = image.directories[index]; dir.rva != 0 && dir.size != 0 };
    let has_relocs = present(crate::parser::IMAGE_DIRECTORY_ENTRY_BASERELOC)
        && image_characteristics & FILE_RELOCS_STRIPPED == 0;
    let managed = present(COM_DESCRIPTOR_DIRECTORY);
    let mut image_flags = 0u8;
    if image.section_alignment % page != 0 { image_flags |= IMAGE_FLAGS_MAPPED_FLAT; }
    else if dll_characteristics & DLLCHARACTERISTICS_DYNAMIC_BASE != 0 && (has_relocs || contains_code) && !managed {
        image_flags |= IMAGE_FLAGS_DYNAMICALLY_RELOCATED;
    }
    Ok(ImageInformation {
        transfer_address: image.image_base.wrapping_add(image.entry_rva as u64), zero_bits: 0,
        maximum_stack_size, committed_stack_size,
        subsystem, subsystem_minor, subsystem_major, os_major, os_minor,
        image_characteristics, dll_characteristics, machine, contains_code, image_flags,
        loader_flags: u32::from(managed), file_size: file_size.min(u32::MAX as u64) as u32, checksum,
    })
}

fn u16at(b: &[u8], o: usize) -> Result<u16, Error> { Ok(u16::from_le_bytes(b.get(o..o + 2).ok_or(Error::Einval)?.try_into().map_err(|_| Error::Einval)?)) }
fn u32at(b: &[u8], o: usize) -> Result<u32, Error> { Ok(u32::from_le_bytes(b.get(o..o + 4).ok_or(Error::Einval)?.try_into().map_err(|_| Error::Einval)?)) }
fn u64at(b: &[u8], o: usize) -> Result<u64, Error> { Ok(u64::from_le_bytes(b.get(o..o + 8).ok_or(Error::Einval)?.try_into().map_err(|_| Error::Einval)?)) }
