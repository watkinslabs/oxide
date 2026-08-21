// Fixed hibernation image wire layouts per `32b§8`.

pub const PAGE_SIZE: usize = 4096;
pub const MAP_ENTRIES: usize = PAGE_SIZE / core::mem::size_of::<u64>() - 1;
pub const HIBERNATE_SIG: [u8; 10] = *b"S1SUSPEND\0";
pub const SWAP_SIG_OLD: [u8; 10] = *b"SWAP-SPACE";
pub const SWAP_SIG_NEW: [u8; 10] = *b"SWAPSPACE2";
pub const FLAG_NOCOMPRESS: u32 = 1 << 1;
pub const FLAG_CRC32: u32 = 1 << 2;
pub const FLAG_LZ4: u32 = 1 << 4;

const FORMAT_MAGIC: [u8; 8] = *b"OXHIBIMG";
const FORMAT_VERSION: u32 = 1;
const KNOWN_FLAGS: u32 = FLAG_NOCOMPRESS | FLAG_CRC32 | FLAG_LZ4;
const BUILD_ID_BYTES: usize = 32;
const ID_BYTES: usize = 32;
const ARCH_DATA_BYTES: usize = 128;

const OFF_VERSION: usize = 8;
const OFF_PAGE_SIZE: usize = 12;
const OFF_IMAGE_PAGES: usize = 16;
const OFF_ZERO_PAGES: usize = 24;
const OFF_ARCH: usize = 32;
const OFF_CPU_COUNT: usize = 36;
const OFF_BUILD_ID: usize = 40;
const OFF_TOPOLOGY: usize = OFF_BUILD_ID + BUILD_ID_BYTES;
const OFF_CPU_ID: usize = OFF_TOPOLOGY + ID_BYTES;
const OFF_ARCH_DATA: usize = OFF_CPU_ID + ID_BYTES;
const OFF_STREAM_PAGES: usize = OFF_ARCH_DATA + ARCH_DATA_BYTES;
const OFF_HW_SIG: usize = PAGE_SIZE - 20 - 8 - 4 - 4 - 4;
const OFF_CRC32: usize = OFF_HW_SIG + 4;
const OFF_IMAGE: usize = OFF_CRC32 + 4;
const OFF_FLAGS: usize = OFF_IMAGE + 8;
pub const OFF_ORIG_SIG: usize = OFF_FLAGS + 4;
pub const OFF_SIG: usize = OFF_ORIG_SIG + 10;

pub type Page = [u8; PAGE_SIZE];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub flags: u32,
    pub checksum: u32,
    pub first_map: u64,
    pub image_pages: u64,
    pub zero_pages: u64,
    pub stream_pages: u64,
    pub arch: u32,
    pub cpu_count: u32,
    pub hardware_sig: u32,
    pub build_id: [u8; BUILD_ID_BYTES],
    pub topology_id: [u8; ID_BYTES],
    pub cpu_id: [u8; ID_BYTES],
    pub arch_data: [u8; ARCH_DATA_BYTES],
    pub original_sig: [u8; 10],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FormatError { Signature, Magic, Version, PageSize, Flags }

/// Compression selected by the persisted flag combination. # C: O(1)
pub fn compression(flags: u32) -> Result<super::image::Compression, FormatError> {
    if flags & FLAG_CRC32 == 0 || flags & !KNOWN_FLAGS != 0
        || flags & FLAG_NOCOMPRESS != 0 && flags & FLAG_LZ4 != 0
    {
        return Err(FormatError::Flags);
    }
    if flags & FLAG_NOCOMPRESS != 0 { Ok(super::image::Compression::None) }
    else if flags & FLAG_LZ4 != 0 { Ok(super::image::Compression::Lz4) }
    else { Ok(super::image::Compression::Lzo) }
}

fn put_u32(page: &mut Page, off: usize, value: u32) { page[off..off + 4].copy_from_slice(&value.to_le_bytes()); }
fn put_u64(page: &mut Page, off: usize, value: u64) { page[off..off + 8].copy_from_slice(&value.to_le_bytes()); }
fn get_u32(page: &Page, off: usize) -> u32 { u32::from_le_bytes(page[off..off + 4].try_into().unwrap()) }
fn get_u64(page: &Page, off: usize) -> u64 { u64::from_le_bytes(page[off..off + 8].try_into().unwrap()) }

/// Whether a page carries the valid-image marker. # C: O(1)
pub fn is_marked(page: &Page) -> bool { page[OFF_SIG..OFF_SIG + 10] == HIBERNATE_SIG }

/// Whether a page carries a supported swap signature. # C: O(1)
pub fn is_swap_header(page: &Page) -> bool {
    page[OFF_SIG..OFF_SIG + 10] == SWAP_SIG_OLD || page[OFF_SIG..OFF_SIG + 10] == SWAP_SIG_NEW
}

/// Overlay image metadata while preserving unrelated swap-header bytes. # C: O(1)
pub fn mark(page: &mut Page, header: &Header) -> Result<(), FormatError> {
    if !is_swap_header(page) { return Err(FormatError::Signature); }
    compression(header.flags)?;
    let original: [u8; 10] = page[OFF_SIG..OFF_SIG + 10].try_into().unwrap();
    page[..8].copy_from_slice(&FORMAT_MAGIC);
    put_u32(page, OFF_VERSION, FORMAT_VERSION);
    put_u32(page, OFF_PAGE_SIZE, PAGE_SIZE as u32);
    put_u64(page, OFF_IMAGE_PAGES, header.image_pages);
    put_u64(page, OFF_ZERO_PAGES, header.zero_pages);
    put_u64(page, OFF_STREAM_PAGES, header.stream_pages);
    put_u32(page, OFF_ARCH, header.arch);
    put_u32(page, OFF_CPU_COUNT, header.cpu_count);
    page[OFF_BUILD_ID..OFF_BUILD_ID + BUILD_ID_BYTES].copy_from_slice(&header.build_id);
    page[OFF_TOPOLOGY..OFF_TOPOLOGY + ID_BYTES].copy_from_slice(&header.topology_id);
    page[OFF_CPU_ID..OFF_CPU_ID + ID_BYTES].copy_from_slice(&header.cpu_id);
    page[OFF_ARCH_DATA..OFF_ARCH_DATA + ARCH_DATA_BYTES].copy_from_slice(&header.arch_data);
    put_u32(page, OFF_HW_SIG, header.hardware_sig);
    put_u32(page, OFF_CRC32, header.checksum);
    put_u64(page, OFF_IMAGE, header.first_map);
    put_u32(page, OFF_FLAGS, header.flags);
    page[OFF_ORIG_SIG..OFF_ORIG_SIG + 10].copy_from_slice(&original);
    page[OFF_SIG..OFF_SIG + 10].copy_from_slice(&HIBERNATE_SIG);
    Ok(())
}

/// Restore the preserved swap signature without interpreting image locators. # C: O(1)
pub fn consume(page: &mut Page) -> Result<(), FormatError> {
    if !is_marked(page) { return Err(FormatError::Signature); }
    let original: [u8; 10] = page[OFF_ORIG_SIG..OFF_ORIG_SIG + 10].try_into().unwrap();
    page[OFF_SIG..OFF_SIG + 10].copy_from_slice(&original);
    Ok(())
}

/// Decode a page which was observed with the marker before consumption. # C: O(1)
pub fn decode(page: &Page) -> Result<Header, FormatError> {
    if page[..8] != FORMAT_MAGIC { return Err(FormatError::Magic); }
    if get_u32(page, OFF_VERSION) != FORMAT_VERSION { return Err(FormatError::Version); }
    if get_u32(page, OFF_PAGE_SIZE) as usize != PAGE_SIZE { return Err(FormatError::PageSize); }
    let flags = get_u32(page, OFF_FLAGS);
    compression(flags)?;
    Ok(Header {
        flags, checksum: get_u32(page, OFF_CRC32), first_map: get_u64(page, OFF_IMAGE),
        image_pages: get_u64(page, OFF_IMAGE_PAGES), zero_pages: get_u64(page, OFF_ZERO_PAGES),
        stream_pages: get_u64(page, OFF_STREAM_PAGES),
        arch: get_u32(page, OFF_ARCH), cpu_count: get_u32(page, OFF_CPU_COUNT),
        hardware_sig: get_u32(page, OFF_HW_SIG),
        build_id: page[OFF_BUILD_ID..OFF_BUILD_ID + BUILD_ID_BYTES].try_into().unwrap(),
        topology_id: page[OFF_TOPOLOGY..OFF_TOPOLOGY + ID_BYTES].try_into().unwrap(),
        cpu_id: page[OFF_CPU_ID..OFF_CPU_ID + ID_BYTES].try_into().unwrap(),
        arch_data: page[OFF_ARCH_DATA..OFF_ARCH_DATA + ARCH_DATA_BYTES].try_into().unwrap(),
        original_sig: page[OFF_ORIG_SIG..OFF_ORIG_SIG + 10].try_into().unwrap(),
    })
}

/// Encode a forward map into caller-owned page scratch. # C: O(PAGE_SIZE)
pub fn encode_map_into(page: &mut Page, entries: &[u64], next: u64) -> Result<(), FormatError> {
    if entries.len() > MAP_ENTRIES { return Err(FormatError::Flags); }
    page.fill(0);
    for (i, value) in entries.iter().enumerate() { put_u64(page, i * 8, *value); }
    put_u64(page, MAP_ENTRIES * 8, next);
    Ok(())
}

/// Read one map locator from caller-owned page scratch. # C: O(1)
pub fn map_entry(page: &Page, index: usize) -> Option<u64> {
    (index < MAP_ENTRIES).then(|| get_u64(page, index * 8))
}

/// Read the forward map link from caller-owned page scratch. # C: O(1)
pub fn map_next(page: &Page) -> u64 { get_u64(page, MAP_ENTRIES * 8) }

#[cfg(test)]
pub fn encode_map(entries: &[u64], next: u64) -> Result<Page, FormatError> {
    let mut page = [0u8; PAGE_SIZE];
    encode_map_into(&mut page, entries, next)?;
    Ok(page)
}

#[cfg(test)]
pub fn decode_map(page: &Page) -> ([u64; MAP_ENTRIES], u64) {
    let mut entries = [0u64; MAP_ENTRIES];
    for (i, value) in entries.iter_mut().enumerate() { *value = map_entry(page, i).unwrap(); }
    (entries, map_next(page))
}

/// Extend an IEEE CRC32 with one logical page. # C: O(PAGE_SIZE)
pub fn crc32(mut crc: u32, page: &Page) -> u32 {
    crc = !crc;
    for byte in page { crc ^= *byte as u32; for _ in 0..8 { crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1))); } }
    !crc
}
