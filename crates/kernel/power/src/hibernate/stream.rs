//! Logical image information and original-PFN metadata pages (`32b§8`).

use super::format::{PAGE_SIZE, Page};

const INFO_MAGIC: [u8; 8] = *b"OXHIBINF";
const INFO_VERSION: u32 = 1;
const PFNS_PER_PAGE: usize = PAGE_SIZE / core::mem::size_of::<u64>();

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ImageInfo {
    pub copied_pages: u64,
    pub zero_pages: u64,
    pub pfn_pages: u64,
    pub stream_pages: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Magic, Version, Counts, Bounds, Duplicate }

fn put_u32(page: &mut Page, off: usize, value: u32) { page[off..off + 4].copy_from_slice(&value.to_le_bytes()); }
fn put_u64(page: &mut Page, off: usize, value: u64) { page[off..off + 8].copy_from_slice(&value.to_le_bytes()); }
fn get_u32(page: &Page, off: usize) -> u32 { u32::from_le_bytes(page[off..off + 4].try_into().unwrap()) }
fn get_u64(page: &Page, off: usize) -> u64 { u64::from_le_bytes(page[off..off + 8].try_into().unwrap()) }

fn clear(page: &mut Page) {
    // SAFETY: `page` is the caller's exclusive complete PAGE_SIZE output.
    unsafe { core::ptr::write_bytes(page.as_mut_ptr(), 0, PAGE_SIZE); }
}

/// Derive the only admitted metadata and stream counts. # C: O(1)
pub fn layout(copied_pages: u64, zero_pages: u64) -> Result<ImageInfo, Error> {
    let pfns = copied_pages.checked_add(zero_pages).ok_or(Error::Counts)?;
    if pfns == 0 { return Err(Error::Counts); }
    let pfn_pages = pfns.checked_add(PFNS_PER_PAGE as u64 - 1).ok_or(Error::Counts)?
        / PFNS_PER_PAGE as u64;
    let stream_pages = 1u64.checked_add(pfn_pages).and_then(|n| n.checked_add(copied_pages))
        .ok_or(Error::Counts)?;
    Ok(ImageInfo { copied_pages, zero_pages, pfn_pages, stream_pages })
}

/// Encode the logical stream's first page into caller-owned storage. # C: O(PAGE_SIZE)
#[inline(never)]
pub fn encode_info_into(info: ImageInfo, page: &mut Page) -> Result<(), Error> {
    if layout(info.copied_pages, info.zero_pages)? != info { return Err(Error::Counts); }
    clear(page);
    page[..8].copy_from_slice(&INFO_MAGIC);
    put_u32(page, 8, INFO_VERSION);
    put_u64(page, 16, info.copied_pages);
    put_u64(page, 24, info.zero_pages);
    put_u64(page, 32, info.pfn_pages);
    put_u64(page, 40, info.stream_pages);
    Ok(())
}

/// Decode and re-derive every image count. # C: O(1)
pub fn decode_info(page: &Page) -> Result<ImageInfo, Error> {
    if page[..8] != INFO_MAGIC { return Err(Error::Magic); }
    if get_u32(page, 8) != INFO_VERSION { return Err(Error::Version); }
    let info = ImageInfo {
        copied_pages: get_u64(page, 16), zero_pages: get_u64(page, 24),
        pfn_pages: get_u64(page, 32), stream_pages: get_u64(page, 40),
    };
    if layout(info.copied_pages, info.zero_pages)? != info { return Err(Error::Counts); }
    Ok(info)
}

/// Incremental caller-page PFN encoder; it never materializes a `Page` value.
pub struct PfnPageWriter<'a> { page: &'a mut Page, start: usize, count: usize }

impl<'a> PfnPageWriter<'a> {
    /// # C: O(1)
    pub fn new(info: ImageInfo, page_index: usize, page: &'a mut Page) -> Result<Self, Error> {
        if layout(info.copied_pages, info.zero_pages)? != info { return Err(Error::Counts); }
        if page_index as u64 >= info.pfn_pages { return Err(Error::Bounds); }
        let total = info.copied_pages.checked_add(info.zero_pages).ok_or(Error::Counts)? as usize;
        let start = page_index.checked_mul(PFNS_PER_PAGE).ok_or(Error::Bounds)?;
        clear(page);
        Ok(Self { page, start, count: core::cmp::min(PFNS_PER_PAGE, total.saturating_sub(start)) })
    }
    /// # C: O(1)
    pub const fn start(&self) -> usize { self.start }
    /// # C: O(1)
    pub const fn count(&self) -> usize { self.count }
    /// # C: O(1)
    pub fn put(&mut self, slot: usize, value: u64) -> Result<(), Error> {
        if slot >= self.count { return Err(Error::Bounds); }
        put_u64(self.page, slot * 8, value);
        Ok(())
    }
}

/// Encode one PFN page from a borrowed canonical owner into caller storage. # C: O(PFNs/page)
#[cfg(test)]
pub fn encode_pfn_page_into(info: ImageInfo, page_index: usize, page: &mut Page,
                            mut pfn: impl FnMut(usize) -> Option<u64>) -> Result<(), Error> {
    let mut writer = PfnPageWriter::new(info, page_index, page)?;
    for slot in 0..writer.count() {
        let index = writer.start() + slot;
        let Some(value) = pfn(index) else { break; };
        writer.put(slot, value)?;
    }
    Ok(())
}

#[cfg(test)]
/// # C: O(PFNS_PER_PAGE)
pub fn encode_pfns(copied: &[u64], zero: &[u64], page_index: usize) -> Result<Page, Error> {
    let info = layout(copied.len() as u64, zero.len() as u64)?;
    let mut page = [0; PAGE_SIZE];
    encode_pfn_page_into(info, page_index, &mut page, |index| {
        if index < copied.len() { Some(copied[index]) }
        else { zero.get(index - copied.len()).copied() }
    })?;
    Ok(page)
}

/// Decode the meaningful PFNs in one metadata page. # C: O(PFNs/page)
pub fn decode_pfns(page: &Page, info: ImageInfo, page_index: usize,
                   out: &mut [u64]) -> Result<usize, Error> {
    if page_index as u64 >= info.pfn_pages { return Err(Error::Bounds); }
    let total = info.copied_pages.checked_add(info.zero_pages).ok_or(Error::Counts)? as usize;
    let start = page_index.checked_mul(PFNS_PER_PAGE).ok_or(Error::Bounds)?;
    let count = core::cmp::min(PFNS_PER_PAGE, total.saturating_sub(start));
    if out.len() < count { return Err(Error::Bounds); }
    for (slot, target) in out[..count].iter_mut().enumerate() { *target = get_u64(page, slot * 8); }
    if page[count * 8..].iter().any(|byte| *byte != 0) { return Err(Error::Counts); }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn info_and_pfn_rollover_round_trip_exact_counts() {
        let copied: alloc::vec::Vec<u64> = (1..=PFNS_PER_PAGE as u64).collect();
        let zero = [900u64];
        let info = layout(copied.len() as u64, zero.len() as u64).unwrap();
        let mut page = [0; PAGE_SIZE];
        encode_info_into(info, &mut page).unwrap();
        assert_eq!(decode_info(&page), Ok(info));
        assert_eq!(info.pfn_pages, 2);
        let mut out = vec![0u64; PFNS_PER_PAGE];
        encode_pfn_page_into(info, 0, &mut page, |index| {
            if index < copied.len() { Some(copied[index]) }
            else { zero.get(index - copied.len()).copied() }
        }).unwrap();
        assert_eq!(decode_pfns(&page, info, 0, &mut out), Ok(PFNS_PER_PAGE));
        assert_eq!(out, copied);
        encode_pfn_page_into(info, 1, &mut page, |index| {
            if index < copied.len() { Some(copied[index]) }
            else { zero.get(index - copied.len()).copied() }
        }).unwrap();
        assert_eq!(decode_pfns(&page, info, 1, &mut out), Ok(1));
        assert_eq!(out[0], zero[0]);
    }

    #[test]
    fn count_mutation_is_rejected() {
        let info = layout(2, 1).unwrap();
        let mut page = [0xa5; PAGE_SIZE];
        encode_info_into(info, &mut page).unwrap();
        assert!(page[48..].iter().all(|byte| *byte == 0),
            "caller storage must be cleared in place, not replaced by a Page temporary");
        put_u64(&mut page, 40, info.stream_pages + 1);
        assert_eq!(decode_info(&page), Err(Error::Counts));
    }
}
