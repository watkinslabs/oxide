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
/// A view longer than the section it is taken from.
pub const STATUS_INVALID_VIEW_SIZE: u64 = 0xc000_001f;
/// A page-protection word no view can be mapped with.
pub const STATUS_INVALID_PAGE_PROTECTION: u64 = 0xc000_0045;
/// A section information class this object type answers no record for.
pub const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;

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

// Page-protection words a view may be mapped with.
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// The rights a view of one page protection needs from the section handle.
///
/// The protection the view is mapped with and the rights the handle must
/// carry are not the same set: a copy-on-write view writes only to its own
/// private pages and so needs no write right, and any executable view is read
/// as well as executed. Deriving the rights from the mapped page protection
/// instead admits a handle that was never granted them. # C: O(1)
pub const fn map_view_access(protect: u32) -> Result<u32, u64> {
    match protect {
        PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY => Ok(SECTION_MAP_READ),
        PAGE_READWRITE => Ok(SECTION_MAP_WRITE),
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY => Ok(SECTION_MAP_READ | SECTION_MAP_EXECUTE),
        PAGE_EXECUTE_READWRITE => Ok(SECTION_MAP_WRITE | SECTION_MAP_EXECUTE),
        _ => Err(STATUS_INVALID_PAGE_PROTECTION),
    }
}

/// Extent one view of a data section covers, from the caller's request and
/// what the section holds past the view's offset. A request of zero takes the
/// rest of the section; any request rounds up to a whole page, and only a
/// request longer than the section is refused. # C: O(1)
pub fn data_view_size(requested: u64, section_size: u64, offset: u64) -> Result<u64, u64> {
    let available = section_size.checked_sub(offset).ok_or(STATUS_INVALID_PARAMETER)?;
    if available == 0 { return Err(STATUS_INVALID_PARAMETER); }
    if requested > available { return Err(STATUS_INVALID_VIEW_SIZE); }
    let size = if requested == 0 { available } else { requested };
    let page = 0x1000u64;
    let rounded = size.checked_add(page - 1).ok_or(STATUS_INVALID_PARAMETER)? & !(page - 1);
    if rounded == 0 { return Err(STATUS_INVALID_PARAMETER); }
    Ok(rounded)
}

/// Which record a section query must answer with, or the status refusing it.
/// # C: O(1)
pub fn query_record_bytes(class: u32, length: u32, is_image: bool) -> Result<u32, u64> {
    // A class with no record and a record that does not fit are both refused
    // before the section is ever consulted, so neither answer can depend on
    // which section the handle names.
    let bytes = query_class_bytes(class, length)?;
    if class == SECTION_IMAGE_INFORMATION && !is_image { return Err(STATUS_SECTION_NOT_IMAGE); }
    Ok(bytes)
}

/// The half of that decision the section itself cannot change: which record a
/// class names and whether the caller's buffer holds it. Both answers precede
/// the buffer pointer and the handle, so neither depends on which section a
/// handle names nor on whether the caller supplied a buffer at all.
/// # C: O(1)
pub fn query_class_bytes(class: u32, length: u32) -> Result<u32, u64> {
    const BASIC_BYTES: u32 = 24;
    let bytes = match class {
        SECTION_BASIC_INFORMATION => BASIC_BYTES,
        SECTION_IMAGE_INFORMATION => pe::SECTION_IMAGE_INFORMATION_BYTES as u32,
        _ => return Err(STATUS_NOT_IMPLEMENTED),
    };
    if length < bytes { return Err(super::nt_dispatch::STATUS_INFO_LENGTH_MISMATCH); }
    Ok(bytes)
}

// Access rights a section object grants. The specific rights, the standard
// rights every object type carries, and the four generic rights a caller may
// ask in place of them; a generic right names the specific set the type maps
// it to, and reaches the object only in that mapped form.
pub const SECTION_QUERY: u32 = 0x0001;
pub const SECTION_MAP_WRITE: u32 = 0x0002;
pub const SECTION_MAP_READ: u32 = 0x0004;
pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
pub const SECTION_EXTEND_SIZE: u32 = 0x0010;
pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000f_0000;
pub const STANDARD_RIGHTS_READ: u32 = 0x0002_0000;
pub const STANDARD_RIGHTS_WRITE: u32 = 0x0002_0000;
pub const STANDARD_RIGHTS_EXECUTE: u32 = 0x0002_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const SECTION_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED
    | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE;
/// Every right this object type answers for.
pub const SECTION_VALID_ACCESS: u32 = SECTION_ALL_ACCESS | SYNCHRONIZE;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

/// Expand the generic rights in a requested mask into the specific rights this
/// object type maps them to. A generic bit never survives the expansion.
/// # C: O(1)
pub const fn map_access(desired: u32) -> u32 {
    let mut access = desired;
    if desired & GENERIC_READ != 0 { access |= STANDARD_RIGHTS_READ | SECTION_QUERY | SECTION_MAP_READ; }
    if desired & GENERIC_WRITE != 0 { access |= STANDARD_RIGHTS_WRITE | SECTION_MAP_WRITE; }
    if desired & GENERIC_EXECUTE != 0 { access |= STANDARD_RIGHTS_EXECUTE | SECTION_MAP_EXECUTE; }
    if desired & GENERIC_ALL != 0 { access |= SECTION_ALL_ACCESS; }
    access & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)
}

/// Whether the mapped request asks only for rights this type answers for.
/// # C: O(1)
pub const fn access_admitted(desired: u32) -> bool { map_access(desired) & !SECTION_VALID_ACCESS == 0 }

#[cfg(test)] #[path = "tests/nt_section_image.rs"] mod tests;
