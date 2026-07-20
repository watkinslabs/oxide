//! `/proc/meminfo` rendering from the shared VM-owner observation.

use alloc::vec::Vec;

const KIB_BYTES: u64 = 1024;

/// # C: O(caches + swap areas + mms).
pub fn build() -> Vec<u8> {
    let s = crate::memory::snapshot();
    let page_kib = hal::PAGE_SIZE_BYTES / KIB_BYTES;
    let pages = |n: u64| n.saturating_mul(page_kib);
    let bytes = |n: u64| n / KIB_BYTES;
    let active_anon = pages(s.active_anon);
    let inactive_anon = pages(s.inactive_anon);
    let active_file = pages(s.active_file);
    let inactive_file = pages(s.inactive_file);
    let slab_reclaimable = pages(s.slab_reclaimable_pages);
    let slab_unreclaimable = pages(s.slab_unreclaimable_pages);
    let mut b = Vec::with_capacity(768);
    for &(key, value) in &[
        (b"MemTotal:        " as &[u8], pages(s.managed_pages)),
        (b"MemFree:         ", pages(s.free_pages)),
        (b"MemAvailable:    ", pages(s.available_pages())),
        (b"Cached:          ", pages(s.file_cache_pages)),
        (b"Active:          ", active_anon.saturating_add(active_file)),
        (b"Inactive:        ", inactive_anon.saturating_add(inactive_file)),
        (b"Active(anon):    ", active_anon),
        (b"Inactive(anon):  ", inactive_anon),
        (b"Active(file):    ", active_file),
        (b"Inactive(file):  ", inactive_file),
        (b"Unevictable:     ", pages(s.unevictable)),
        (b"SwapTotal:       ", pages(s.swap_total_pages)),
        (b"SwapFree:        ", pages(s.swap_free_pages)),
        (b"Dirty:           ", pages(s.dirty_file_pages)),
        (b"Writeback:       ", pages(s.writeback_file_pages)),
        (b"AnonPages:       ", pages(s.anon_pages())),
        (b"Mapped:          ", pages(s.anon_pte_mappings.saturating_add(s.file_pte_mappings))),
        (b"Shmem:           ", pages(s.shmem_pages)),
        (b"KReclaimable:    ", slab_reclaimable),
        (b"Slab:            ", slab_reclaimable.saturating_add(slab_unreclaimable)),
        (b"SReclaimable:    ", slab_reclaimable),
        (b"SUnreclaim:      ", slab_unreclaimable),
        (b"KernelStack:     ", bytes(s.kernel_stack_bytes)),
        (b"PageTables:      ", pages(s.page_table_pages)),
        (b"VmallocTotal:    ", bytes(s.vmalloc_total_bytes)),
        (b"VmallocUsed:     ", bytes(s.vmalloc_used_bytes)),
        (b"VmallocChunk:    ", bytes(s.vmalloc_largest_free_bytes)),
        (b"Percpu:          ", pages(s.percpu_pages)),
    ] {
        push(&mut b, key); push_u64(&mut b, value); push(&mut b, b" kB\n");
    }
    b
}

fn push(v: &mut Vec<u8>, b: &[u8]) { v.extend_from_slice(b); }

fn push_u64(v: &mut Vec<u8>, mut n: u64) {
    if n == 0 { v.push(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; v.push(buf[i]); }
}
