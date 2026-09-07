//! PE resource-directory walk shared by the loader's resource services.
//!
//! Three directory levels — type, name, language — whose entry offsets are all
//! relative to the resource ROOT, not to the directory the entry lives in. The
//! language level is not an exact match: a caller that asks for the neutral
//! language gets a documented list of substitutes tried in order, and finally
//! the first entry in the directory. Notepad's menu resource carries no
//! neutral-language entry, so a lookup without that list finds nothing.
//!
//! Ungated so the walk is exercised by `cargo test`; the kernel service is a
//! shim over it (docs/53).

/// Ordering of a `NtService::LdrFindResource` walk. Status values are the NT
/// codes the loader services return.
pub(crate) const STATUS_SUCCESS: u64 = 0;
pub(crate) const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
pub(crate) const STATUS_RESOURCE_DATA_NOT_FOUND: u64 = 0xc000_008b;
pub(crate) const STATUS_RESOURCE_TYPE_NOT_FOUND: u64 = 0xc000_008d;
pub(crate) const STATUS_RESOURCE_NAME_NOT_FOUND: u64 = 0xc000_008f;
pub(crate) const STATUS_RESOURCE_LANG_NOT_FOUND: u64 = 0xc000_0090;

const RESOURCE_DIRECTORY_BYTES: u64 = 16;
const RESOURCE_ENTRY_BYTES: u64 = 8;
const NAMED_COUNT_OFFSET: u64 = 12;
const ID_COUNT_OFFSET: u64 = 14;
const ENTRY_OFFSET_FIELD: u64 = 4;
const DIRECTORY_BIT: u32 = 0x8000_0000;
const OFFSET_MASK: u32 = 0x7fff_ffff;
const RESOURCE_MAX_ENTRIES: u32 = 4096;
const RESOURCE_STRING_MAX: usize = 4096;
const RESOURCE_STRING_LENGTH_BYTES: u64 = 2;

const LANG_NEUTRAL: u16 = 0x00;
const LANG_ENGLISH: u16 = 0x09;
const SUBLANG_NEUTRAL: u16 = 0x00;
const SUBLANG_DEFAULT: u16 = 0x01;
const SUBLANG_SYS_DEFAULT: u16 = 0x02;
const PRIMARY_LANGID_MASK: u16 = 0x03ff;
const SUBLANG_SHIFT: u16 = 10;
const LANGUAGE_CANDIDATES: usize = 9;

/// Language id from its primary and sublanguage halves. # C: O(1)
const fn make_langid(primary: u16, sublanguage: u16) -> u16 { (sublanguage << SUBLANG_SHIFT) | primary }
/// Primary half of a language id. # C: O(1)
const fn primary_langid(language: u16) -> u16 { language & PRIMARY_LANGID_MASK }
/// Sublanguage half of a language id. # C: O(1)
const fn sublangid(language: u16) -> u16 { language >> SUBLANG_SHIFT }
/// A resource key that is an ordinal rather than a string pointer. # C: O(1)
const fn is_int_resource(key: u64) -> bool { key >> 16 == 0 }

/// Bounded reads of one image, so the walk is the same code over user memory
/// and over a hosted fixture.
pub(crate) trait ImageReader {
    /// Sixteen bits at an image address, or `None` when unreadable. # C: O(1)
    fn u16(&self, address: u64) -> Option<u16>;
    /// Thirty-two bits at an image address, or `None` when unreadable. # C: O(1)
    fn u32(&self, address: u64) -> Option<u32>;
}

/// The type, name and language a caller asks for. `ty` and `name` are either
/// ordinals or pointers to counted UTF-16 strings in the caller's memory.
pub(crate) struct ResourceQuery { pub(crate) ty: u64, pub(crate) name: u64, pub(crate) language: u16 }

/// Language ids substituted for a neutral request.
pub(crate) struct ResourceLcids {
    pub(crate) thread: u16,
    pub(crate) user: u16,
    pub(crate) user_neutral: u16,
    pub(crate) system: u16,
}

impl ResourceLcids {
    /// The en-US baseline this personality reports for the default locale and
    /// both UI languages. # C: O(1)
    pub(crate) const fn baseline() -> Self {
        const EN_US: u16 = make_langid(LANG_ENGLISH, SUBLANG_DEFAULT);
        Self { thread: EN_US, user: EN_US, user_neutral: LANG_ENGLISH, system: EN_US }
    }
}

struct LanguageList { items: [u16; LANGUAGE_CANDIDATES], count: usize }

impl LanguageList {
    const fn new() -> Self { Self { items: [0; LANGUAGE_CANDIDATES], count: 0 } }
    fn push(&mut self, language: u16) {
        if self.count == LANGUAGE_CANDIDATES { return; }
        if self.items[..self.count].contains(&language) { return; }
        self.items[self.count] = language;
        self.count += 1;
    }
    fn as_slice(&self) -> &[u16] { &self.items[..self.count] }
}

/// Walk `level` directory levels from `root`, answering the directory (or the
/// data entry when `want_directory` is false) the query names.
/// # C: O(log N) per level plus the language candidate list
pub(crate) fn find_entry<R: ImageReader>(reader: &R, root: u64, query: &ResourceQuery, lcids: &ResourceLcids, level: u32, want_directory: bool) -> Result<u64, u64> {
    if level == 0 { return Ok(root); }
    let mut remaining = level - 1;
    let type_dir = find_by_name(reader, root, root, query.ty, want_directory || remaining != 0).ok_or(STATUS_RESOURCE_TYPE_NOT_FOUND)?;
    if remaining == 0 { return Ok(type_dir); }
    remaining -= 1;
    let name_dir = find_by_name(reader, type_dir, root, query.name, want_directory || remaining != 0).ok_or(STATUS_RESOURCE_NAME_NOT_FOUND)?;
    if remaining == 0 { return Ok(name_dir); }
    remaining -= 1;
    if remaining != 0 { return Err(STATUS_INVALID_PARAMETER); }
    for language in language_candidates(query.language, lcids).as_slice() {
        if let Some(entry) = find_by_id(reader, name_dir, root, *language, want_directory) { return Ok(entry); }
    }
    if primary_langid(query.language) == LANG_NEUTRAL {
        if let Some(entry) = find_first(reader, name_dir, root, want_directory) { return Ok(entry); }
    }
    Err(STATUS_RESOURCE_LANG_NOT_FOUND)
}

/// The languages tried, in order, for one request. # C: O(1)
fn language_candidates(requested: u16, lcids: &ResourceLcids) -> LanguageList {
    let mut list = LanguageList::new();
    list.push(requested);
    list.push(make_langid(primary_langid(requested), SUBLANG_NEUTRAL));
    list.push(make_langid(LANG_NEUTRAL, SUBLANG_NEUTRAL));
    if primary_langid(requested) != LANG_NEUTRAL { return list; }
    if sublangid(requested) != SUBLANG_SYS_DEFAULT {
        list.push(lcids.thread);
        list.push(lcids.user);
        list.push(lcids.user_neutral);
    }
    list.push(lcids.system);
    list.push(primary_langid(lcids.system));
    list.push(make_langid(LANG_ENGLISH, SUBLANG_DEFAULT));
    list
}

fn entry_counts<R: ImageReader>(reader: &R, directory: u64) -> Option<(u32, u32)> {
    let named = reader.u16(directory.checked_add(NAMED_COUNT_OFFSET)?)? as u32;
    let ids = reader.u16(directory.checked_add(ID_COUNT_OFFSET)?)? as u32;
    if named.checked_add(ids)? > RESOURCE_MAX_ENTRIES { return None; }
    Some((named, ids))
}

fn entry_address(directory: u64, index: u32) -> Option<u64> {
    directory.checked_add(RESOURCE_DIRECTORY_BYTES)?.checked_add((index as u64).checked_mul(RESOURCE_ENTRY_BYTES)?)
}

/// Resolve one entry's offset against the resource root, refusing an entry
/// whose kind does not match what the caller wants.
fn resolve<R: ImageReader>(reader: &R, entry: u64, root: u64, want_directory: bool) -> Option<u64> {
    let offset = reader.u32(entry.checked_add(ENTRY_OFFSET_FIELD)?)?;
    if (offset & DIRECTORY_BIT != 0) != want_directory { return None; }
    root.checked_add((offset & OFFSET_MASK) as u64)
}

fn find_first<R: ImageReader>(reader: &R, directory: u64, root: u64, want_directory: bool) -> Option<u64> {
    let (named, ids) = entry_counts(reader, directory)?;
    for index in 0..named + ids {
        let entry = entry_address(directory, index)?;
        if let Some(found) = resolve(reader, entry, root, want_directory) { return Some(found); }
    }
    None
}

fn find_by_id<R: ImageReader>(reader: &R, directory: u64, root: u64, id: u16, want_directory: bool) -> Option<u64> {
    let (named, ids) = entry_counts(reader, directory)?;
    let mut min = named as i64;
    let mut max = min + ids as i64 - 1;
    while min <= max {
        let position = (min + max) / 2;
        let entry = entry_address(directory, position as u32)?;
        let entry_id = reader.u32(entry)? as u16;
        if entry_id == id { return resolve(reader, entry, root, want_directory); }
        if entry_id > id { max = position - 1; } else { min = position + 1; }
    }
    None
}

fn find_by_name<R: ImageReader>(reader: &R, directory: u64, root: u64, key: u64, want_directory: bool) -> Option<u64> {
    if is_int_resource(key) { return find_by_id(reader, directory, root, key as u16, want_directory); }
    let (named, _) = entry_counts(reader, directory)?;
    let key_length = wide_length(reader, key)?;
    let mut min = 0i64;
    let mut max = named as i64 - 1;
    while min <= max {
        let position = (min + max) / 2;
        let entry = entry_address(directory, position as u32)?;
        let string = root.checked_add((reader.u32(entry)? & OFFSET_MASK) as u64)?;
        let length = reader.u16(string)? as usize;
        let order = wide_compare(reader, key, string.checked_add(RESOURCE_STRING_LENGTH_BYTES)?, length)?;
        if order == 0 && key_length == length { return resolve(reader, entry, root, want_directory); }
        if order < 0 { max = position - 1; } else { min = position + 1; }
    }
    None
}

/// Characters before the terminator of a caller's UTF-16 resource name.
fn wide_length<R: ImageReader>(reader: &R, address: u64) -> Option<usize> {
    for index in 0..RESOURCE_STRING_MAX {
        if reader.u16(address.checked_add((index as u64).checked_mul(2)?)?)? == 0 { return Some(index); }
    }
    None
}

/// Compare a terminated name against a counted directory string, over at most
/// `length` characters.
fn wide_compare<R: ImageReader>(reader: &R, name: u64, string: u64, length: usize) -> Option<i64> {
    if length > RESOURCE_STRING_MAX { return None; }
    for index in 0..length {
        let step = (index as u64).checked_mul(2)?;
        let left = reader.u16(name.checked_add(step)?)?;
        let right = reader.u16(string.checked_add(step)?)?;
        if left != right { return Some(left as i64 - right as i64); }
        if left == 0 { return Some(0); }
    }
    Some(0)
}


const DOS_LFANEW_OFFSET: u64 = 0x3c;
const PE_MAGIC: u32 = 0x0000_4550;
const OPTIONAL_HEADER_OFFSET: u64 = 24;
const OPTIONAL_MAGIC_PE32_PLUS: u32 = 0x0000_020b;
const OPTIONAL_HEADER_NUMBER_DIRECTORIES_OFFSET: u64 = 108;
const OPTIONAL_HEADER_BYTES_BEFORE_DIRECTORIES: u64 = 112;
const DIRECTORY_BYTES: u64 = 8;
const DIRECTORY_COUNT: u32 = 16;
const DIRECTORY_ENTRY_RESOURCE: u32 = 2;

/// Address of an image's resource root directory. A resource directory
/// smaller than one directory header carries no entries and counts as absent.
/// # C: O(1) plus five bounded reads
pub(crate) fn resource_root<R: ImageReader>(reader: &R, module: u64) -> Option<u64> {
    let lfanew = reader.u32(module.checked_add(DOS_LFANEW_OFFSET)?)? as u64;
    let nt = module.checked_add(lfanew)?;
    if reader.u32(nt)? != PE_MAGIC { return None; }
    let optional = nt.checked_add(OPTIONAL_HEADER_OFFSET)?;
    if reader.u32(optional)? & 0xffff != OPTIONAL_MAGIC_PE32_PLUS { return None; }
    let directories = reader.u32(optional.checked_add(OPTIONAL_HEADER_NUMBER_DIRECTORIES_OFFSET)?)?.min(DIRECTORY_COUNT);
    if directories <= DIRECTORY_ENTRY_RESOURCE { return None; }
    let entry = optional.checked_add(OPTIONAL_HEADER_BYTES_BEFORE_DIRECTORIES)?
        .checked_add(DIRECTORY_BYTES.checked_mul(DIRECTORY_ENTRY_RESOURCE as u64)?)?;
    let rva = reader.u32(entry)?;
    let size = reader.u32(entry.checked_add(ENTRY_OFFSET_FIELD)?)?;
    if rva == 0 || (size as u64) < RESOURCE_DIRECTORY_BYTES { return None; }
    module.checked_add(rva as u64)
}

#[cfg(test)]
#[path = "tests/nt_resource.rs"]
mod tests;
