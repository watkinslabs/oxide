//! Dynamic Linux `/proc/swaps` renderer backed by the canonical PMM swap map.

use alloc::vec::Vec;

const KIB_BYTES: u64 = 1024;

/// # C: O(active swap areas)
pub fn build() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");
    let page_kib = hal::PAGE_SIZE_BYTES / KIB_BYTES;
    for area in pmm::swap::snapshot() {
        let size_kib = area.pages.saturating_mul(page_kib);
        let used_kib = area.used_pages.saturating_mul(page_kib);
        match area.backing {
            pmm::swap::SwapBacking::BlockDevice => {
                body.extend_from_slice(b"/dev/");
                body.extend_from_slice(area.display_name.as_bytes());
                body.extend_from_slice(b"\t\tpartition\t");
            }
            pmm::swap::SwapBacking::File => {
                body.extend_from_slice(area.display_name.as_bytes());
                body.extend_from_slice(b"\t\tfile\t");
            }
        }
        push_u64(&mut body, size_kib);
        body.push(b'\t');
        push_u64(&mut body, used_kib);
        body.push(b'\t');
        push_i32(&mut body, area.priority);
        body.push(b'\n');
    }
    body
}

/// # C: O(1)
pub fn make_proc_swaps() -> vfs::InodeRef {
    crate::dyn_file::make_gen_file(crate::ids::SWAPS, build)
}

fn push_i32(body: &mut Vec<u8>, value: i32) {
    if value < 0 { body.push(b'-'); }
    push_u64(body, value.unsigned_abs() as u64);
}

fn push_u64(body: &mut Vec<u8>, mut value: u64) {
    if value == 0 { body.push(b'0'); return; }
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    while value != 0 {
        digits[count] = b'0' + (value % 10) as u8;
        value /= 10;
        count += 1;
    }
    while count != 0 { count -= 1; body.push(digits[count]); }
}
