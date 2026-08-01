//! `SWAPSPACE2` on-disk header construction.
//!
//! Layout owned here per the constants-by-contract rule: the version/last-page/
//! bad-page words live at fixed offsets inside the first page and the magic sits
//! flush against the end of that page. `swapon(2)` rejects anything else, so
//! these offsets ARE the contract.

use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;

/// Header magic, at the tail of page 0.
const SWAP_MAGIC: &[u8] = b"SWAPSPACE2";
const PAGE_BYTES: usize = 4096;
/// 32 pages is the smallest area that leaves usable slots after the header page.
const SWAP_PAGE_COUNT: u32 = 32;
const SWAP_FILE_BYTES: u64 = PAGE_BYTES as u64 * SWAP_PAGE_COUNT as u64;
const VERSION_OFFSET: usize = 1024;
const LAST_PAGE_OFFSET: usize = VERSION_OFFSET + 4;
const BAD_PAGE_COUNT_OFFSET: usize = LAST_PAGE_OFFSET + 4;
const MAGIC_OFFSET: usize = PAGE_BYTES - SWAP_MAGIC.len();
/// `SWAPSPACE2` is version 1; version 0 is the retired `SWAP-SPACE` format.
const SWAPSPACE2_VERSION: u32 = 1;
/// Highest usable page index, i.e. count minus the header page's own slot.
const LAST_SWAP_PAGE: u32 = SWAP_PAGE_COUNT - 1;
const NO_BAD_PAGES: u32 = 0;

/// Create the file, fully initialize every page, then write the header and
/// fsync. Returns the failing step name. # C: O(SWAP_FILE_BYTES)
///
/// Every page is written rather than left as a hole: `swapon` refuses an area
/// with unwritten extents, and a sparse file is exactly what an ext4 that
/// silently drops the allocation would leave behind.
pub(crate) fn create(path: &str, mode: u32) -> Result<(), &'static str> {
    let mut file = std::fs::OpenOptions::new()
        .read(true).write(true).create_new(true).mode(mode)
        .open(path).map_err(|_| "open")?;
    file.set_len(SWAP_FILE_BYTES).map_err(|_| "ftruncate")?;

    let zero = [0u8; PAGE_BYTES];
    for _ in 0..SWAP_PAGE_COUNT { file.write_all(&zero).map_err(|_| "initialize-pages")?; }

    file.seek(SeekFrom::Start(0)).map_err(|_| "swap-header")?;
    file.write_all(&first_page()).map_err(|_| "swap-header")?;
    file.sync_all().map_err(|_| "swap-header")?;
    Ok(())
}

/// Page 0 with the version/last-page/bad-count words and the trailing magic.
fn first_page() -> [u8; PAGE_BYTES] {
    let mut page = [0u8; PAGE_BYTES];
    page[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&SWAPSPACE2_VERSION.to_ne_bytes());
    page[LAST_PAGE_OFFSET..LAST_PAGE_OFFSET + 4].copy_from_slice(&LAST_SWAP_PAGE.to_ne_bytes());
    page[BAD_PAGE_COUNT_OFFSET..BAD_PAGE_COUNT_OFFSET + 4].copy_from_slice(&NO_BAD_PAGES.to_ne_bytes());
    page[MAGIC_OFFSET..].copy_from_slice(SWAP_MAGIC);
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_sits_flush_against_the_end_of_the_first_page() {
        let page = first_page();
        assert_eq!(&page[MAGIC_OFFSET..], SWAP_MAGIC);
        assert_eq!(MAGIC_OFFSET + SWAP_MAGIC.len(), PAGE_BYTES);
    }

    #[test]
    fn header_words_land_at_the_offsets_swapon_reads() {
        let page = first_page();
        let word = |at: usize| u32::from_ne_bytes(page[at..at + 4].try_into().unwrap());
        assert_eq!(word(VERSION_OFFSET), SWAPSPACE2_VERSION);
        assert_eq!(word(LAST_PAGE_OFFSET), LAST_SWAP_PAGE);
        assert_eq!(word(BAD_PAGE_COUNT_OFFSET), NO_BAD_PAGES);
    }

    #[test]
    fn the_header_words_do_not_overlap_the_magic() {
        assert!(BAD_PAGE_COUNT_OFFSET + 4 <= MAGIC_OFFSET);
    }

    /// The area must be larger than its own header page, or there is nothing to
    /// swap into and `swapon` reports EINVAL.
    #[test]
    fn the_area_has_usable_pages_beyond_the_header() {
        assert!(LAST_SWAP_PAGE >= 1);
        assert_eq!(SWAP_FILE_BYTES, PAGE_BYTES as u64 * SWAP_PAGE_COUNT as u64);
    }
}
