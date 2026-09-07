// Section allocation attributes and the decisions an image-attributed section
// forces on create, map and query. The address-space work lives in the VMM and
// the image layout in the PE owner; what stays here is which status each
// answer carries, and it stays ungated so it is testable.

/// The view is an image, laid out section by section.
pub const SEC_IMAGE: u32 = 0x0100_0000;
/// The view is backed by the paging file rather than a named file.
pub const SEC_RESERVE: u32 = 0x0400_0000;
/// Pages of the view are committed when the view is created.
pub const SEC_COMMIT: u32 = 0x0800_0000;
/// The view is not cached.
pub const SEC_NOCACHE: u32 = 0x1000_0000;
/// The view is backed by large pages.
pub const SEC_LARGE_PAGES: u32 = 0x8000_0000;
/// An image view whose executable pages are not made executable.
pub const SEC_IMAGE_NO_EXECUTE: u32 = SEC_IMAGE | SEC_NOCACHE;
/// The view is backed by a file.
pub const SEC_FILE: u32 = 0x0080_0000;
/// Writes to the view are tracked.
pub const SEC_WRITECOMBINE: u32 = 0x4000_0000;

const KNOWN_ATTRIBUTES: u32 =
    SEC_FILE | SEC_IMAGE | SEC_RESERVE | SEC_COMMIT | SEC_NOCACHE | SEC_WRITECOMBINE | SEC_LARGE_PAGES;

pub const STATUS_SUCCESS: u64 = 0;
pub const STATUS_IMAGE_NOT_AT_BASE: u64 = 0x4000_0003;
pub const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
pub const STATUS_INVALID_FILE_FOR_SECTION: u64 = 0xc000_0020;
pub const STATUS_SECTION_TOO_BIG: u64 = 0xc000_0040;
pub const STATUS_SECTION_NOT_IMAGE: u64 = 0xc000_0049;
pub const STATUS_INVALID_IMAGE_FORMAT: u64 = 0xc000_007b;

/// Stack word indexes of the NtCreateSection arguments that do not fit the
/// four register words of the call ABI, in declared argument order.
pub const CREATE_SECTION_PROTECT_ARG: usize = 4;
pub const CREATE_SECTION_ALLOCATION_ATTRIBUTES_ARG: usize = 5;
pub const CREATE_SECTION_FILE_ARG: usize = 6;

/// Section information classes a query answers.
pub const SECTION_BASIC_INFORMATION: u32 = 0;
pub const SECTION_IMAGE_INFORMATION: u32 = 1;

/// Whether the caller asked for an image-shaped section. # C: O(1)
pub const fn image_requested(allocation_attributes: u32) -> bool { allocation_attributes & SEC_IMAGE != 0 }

/// Whether every bit the caller set names an allocation attribute. # C: O(1)
pub const fn attributes_admitted(allocation_attributes: u32) -> bool {
    allocation_attributes & !KNOWN_ATTRIBUTES == 0
}

/// An image section needs a file to take its image from. # C: O(1)
pub const fn image_needs_file(allocation_attributes: u32, file: u32) -> bool {
    image_requested(allocation_attributes) && file == 0
}

/// Extent one image section takes. A caller asking for the whole image passes
/// zero; asking for more than the image holds is refused. # C: O(1)
pub fn image_section_size(requested: u64, map_size: u64) -> Result<u64, u64> {
    if map_size == 0 { return Err(STATUS_INVALID_FILE_FOR_SECTION); }
    if requested == 0 { return Ok(map_size); }
    if requested > map_size { return Err(STATUS_SECTION_TOO_BIG); }
    Ok(map_size)
}

/// A view of an image that did not reach the image's preferred base is
/// reported, not refused: reporting it is what lets the loader relocate.
/// # C: O(1)
pub const fn map_view_status(at_preferred_base: bool) -> u64 {
    if at_preferred_base { STATUS_SUCCESS } else { STATUS_IMAGE_NOT_AT_BASE }
}

/// Whether a reported status left a usable view behind. # C: O(1)
pub const fn view_established(status: u64) -> bool { status & 0x8000_0000 == 0 }

/// Which record a section query must answer with, or the status refusing it.
/// # C: O(1)
pub fn query_record_bytes(class: u32, length: u32, is_image: bool) -> Result<u32, u64> {
    const BASIC_BYTES: u32 = 24;
    let bytes = match class {
        SECTION_BASIC_INFORMATION => BASIC_BYTES,
        SECTION_IMAGE_INFORMATION => pe::SECTION_IMAGE_INFORMATION_BYTES as u32,
        _ => return Err(super::nt_dispatch::STATUS_INVALID_INFO_CLASS),
    };
    if length < bytes { return Err(super::nt_dispatch::STATUS_INFO_LENGTH_MISMATCH); }
    if class == SECTION_IMAGE_INFORMATION && !is_image { return Err(STATUS_SECTION_NOT_IMAGE); }
    Ok(bytes)
}

#[cfg(test)] #[path = "tests/nt_section_image.rs"] mod tests;
