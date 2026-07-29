use super::PAGE_SIZE_BYTES;

const FREE_NODE_BYTES: usize = 32;
const POISON_ID_BYTES: usize = 16;

#[cfg(all(test, feature = "debug-watchdog"))]
const NO_TEST_MISMATCH: usize = usize::MAX;
#[cfg(all(test, feature = "debug-watchdog"))]
static TEST_MISMATCH_OFFSET: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(NO_TEST_MISMATCH);

/// Identify a page that retained the poison signature at its tail, then find
/// the first body byte changed while it was free. The buddy legitimately
/// replaces the first 32 bytes with its intrusive `FreeNode`, so that header
/// is excluded from the body check.
///
/// # SAFETY: `page` points to one readable PMM-owned page.
unsafe fn first_mismatch(page: *const u8, poison: u8) -> Option<(usize, u8)> {
    let page_bytes = PAGE_SIZE_BYTES as usize;
    for off in page_bytes - POISON_ID_BYTES..page_bytes {
        // SAFETY: off lies in the final 16 bytes of the caller-owned page.
        if unsafe { core::ptr::read_volatile(page.add(off)) } != poison {
            return None;
        }
    }
    for off in FREE_NODE_BYTES..page_bytes - POISON_ID_BYTES {
        // SAFETY: off lies in the readable body of the caller-owned page.
        let byte = unsafe { core::ptr::read_volatile(page.add(off)) };
        if byte != poison {
            return Some((off, byte));
        }
    }
    None
}

/// Report a write into a 0xAA watchdog-poisoned page while it was free.
///
/// # SAFETY: `page` points to one readable PMM-owned page at physical `pa`.
#[cfg(feature = "debug-watchdog")]
pub(super) unsafe fn report_watchdog_mismatch(page: *const u8, pa: u64) {
    // SAFETY: upheld by the caller.
    if let Some((off, byte)) = unsafe { first_mismatch(page, 0xAA) } {
        #[cfg(test)]
        TEST_MISMATCH_OFFSET.store(off, core::sync::atomic::Ordering::Release);
        klog::write_raw(b"[POISON] write-while-free pa=");
        klog::write_hex_u64(pa);
        klog::write_raw(b" off=");
        klog::write_hex_u64(off as u64);
        klog::write_raw(b" val=");
        klog::write_hex_u64(byte as u64);
        klog::write_raw(b"\n");
    }
}

#[cfg(all(test, feature = "debug-watchdog"))]
pub(crate) fn take_test_mismatch() -> Option<usize> {
    let off = TEST_MISMATCH_OFFSET.swap(
        NO_TEST_MISMATCH,
        core::sync::atomic::Ordering::AcqRel,
    );
    (off != NO_TEST_MISMATCH).then_some(off)
}

/// Report a write into a 0xCC COW-debug-poisoned page while it was free.
///
/// # SAFETY: `page` points to one readable PMM-owned page at physical `pa`.
#[cfg(feature = "debug-cow")]
pub(super) unsafe fn report_cow_mismatch(page: *const u8, pa: u64) {
    // SAFETY: upheld by the caller.
    if let Some((off, byte)) = unsafe { first_mismatch(page, 0xCC) } {
        klog::write_raw(b"[POISON] frame=");
        klog::write_hex_u64(pa);
        klog::write_raw(b" dirtied-while-free off=");
        klog::write_hex_u64(off as u64);
        klog::write_raw(b" val=");
        klog::write_hex_u64(byte as u64);
        klog::write_raw(b"\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn body_scan_ignores_buddy_header_and_finds_later_write() {
        let mut page = vec![0xAA; PAGE_SIZE_BYTES as usize];
        page[..FREE_NODE_BYTES].fill(0x5C);
        // SAFETY: the Vec contains exactly one complete readable page.
        assert_eq!(unsafe { first_mismatch(page.as_ptr(), 0xAA) }, None);

        page[197] = 0x31;
        // SAFETY: the Vec contains exactly one complete readable page.
        assert_eq!(unsafe { first_mismatch(page.as_ptr(), 0xAA) }, Some((197, 0x31)));
    }

    #[test]
    fn body_scan_requires_tail_signature() {
        let mut page = vec![0xAA; PAGE_SIZE_BYTES as usize];
        page[PAGE_SIZE_BYTES as usize - 1] = 0;
        // SAFETY: the Vec contains exactly one complete readable page.
        assert_eq!(unsafe { first_mismatch(page.as_ptr(), 0xAA) }, None);
    }
}
