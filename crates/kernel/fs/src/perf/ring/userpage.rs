// `struct perf_event_mmap_page` — the ring's control page (page 0 of the
// mapping), written by the kernel and read by userspace.
//
// Pure byte layout over a `&mut [u8]` so the offsets ARE the ABI and are
// hosted-testable; `buffer.rs` supplies a slice over the real frame and owns
// the memory barriers that surround these writes.

use super::super::uapi::mmap_page as off;

/// The control page is exactly one page.
pub const PAGE_BYTES: usize = super::sizing::PAGE_BYTES as usize;

fn put_u32(p: &mut [u8], at: usize, v: u32) { p[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
fn put_u64(p: &mut [u8], at: usize, v: u64) { p[at..at + 8].copy_from_slice(&v.to_le_bytes()); }
fn get_u32(p: &[u8], at: usize) -> u32 { u32::from_le_bytes([p[at], p[at+1], p[at+2], p[at+3]]) }
fn get_u64(p: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8]; b.copy_from_slice(&p[at..at + 8]); u64::from_le_bytes(b)
}

/// `perf_event_init_userpage` — the fields fixed for the buffer's lifetime.
///
/// `cap_bit0_is_deprecated` is the one capability oxide sets: it tells new
/// userspace that bit 0 is meaningless. `cap_user_rdpmc` and `cap_user_time`
/// stay clear because there is no hardware PMU to read and no published
/// TSC-to-ns conversion, so userspace must use `read(2)` and the record's own
/// `PERF_SAMPLE_TIME` field. # C: O(1)
pub fn init(page: &mut [u8], data_size: u64) {
    for b in page.iter_mut() { *b = 0; }
    put_u32(page, off::OFF_VERSION, off::VERSION);
    put_u32(page, off::OFF_COMPAT_VERSION, off::VERSION);
    put_u64(page, off::OFF_CAPABILITIES, off::CAP_BIT0_IS_DEPRECATED);
    put_u32(page, off::OFF_SIZE, off::HEADER_SIZE);
    put_u64(page, off::OFF_DATA_OFFSET, PAGE_BYTES as u64);
    put_u64(page, off::OFF_DATA_SIZE, data_size);
}

/// `perf_event_update_userpage` — the seqlocked counter snapshot userspace
/// reads without a syscall. `index` stays 0 (no rdpmc-readable hardware
/// counter), which is exactly the case in which the reference leaves `offset`
/// as the full count rather than subtracting `hw.prev_count`.
///
/// The caller must issue a compiler/store barrier between each step; this
/// function performs the writes in the reference's order and the caller
/// interleaves the fences. # C: O(1)
pub fn update(page: &mut [u8], count: u64, time_enabled: u64, time_running: u64) {
    let seq = get_u32(page, off::OFF_LOCK);
    put_u32(page, off::OFF_LOCK, seq.wrapping_add(1));
    put_u32(page, off::OFF_INDEX, 0);
    put_u64(page, off::OFF_OFFSET, count);
    put_u64(page, off::OFF_TIME_ENABLED, time_enabled);
    put_u64(page, off::OFF_TIME_RUNNING, time_running);
    put_u32(page, off::OFF_LOCK, seq.wrapping_add(2));
}

/// The published counter snapshot: `(offset, time_enabled, time_running)`.
/// # C: O(1)
pub fn snapshot(page: &[u8]) -> (u64, u64, u64) {
    (get_u64(page, off::OFF_OFFSET),
     get_u64(page, off::OFF_TIME_ENABLED),
     get_u64(page, off::OFF_TIME_RUNNING))
}

/// Publish the producer head. The caller issues the write barrier (B, pairing
/// with userspace's read barrier C) BEFORE this store, so the record bytes are
/// visible before the head that advertises them. # C: O(1)
pub fn set_data_head(page: &mut [u8], head: u64) { put_u64(page, off::OFF_DATA_HEAD, head); }

/// The consumer's published tail. Plain load — the reference's `READ_ONCE`;
/// the branch it feeds is the control dependency (A) that orders the record
/// stores after it. # C: O(1)
pub fn data_tail(page: &[u8]) -> u64 { get_u64(page, off::OFF_DATA_TAIL) }

/// # C: O(1)
pub fn data_head(page: &[u8]) -> u64 { get_u64(page, off::OFF_DATA_HEAD) }

/// # C: O(1)
pub fn seq(page: &[u8]) -> u32 { get_u32(page, off::OFF_LOCK) }

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn page() -> alloc::vec::Vec<u8> { vec![0u8; PAGE_BYTES] }

    #[test]
    fn init_writes_the_reference_field_offsets() {
        let mut p = page();
        p[7] = 0xAA; // pre-existing garbage must be cleared
        init(&mut p, 8 * PAGE_BYTES as u64);
        assert_eq!(get_u32(&p, 0), 0, "version");
        assert_eq!(get_u32(&p, 4), 0, "compat_version");
        assert_eq!(get_u64(&p, 40), 2, "capabilities: only cap_bit0_is_deprecated");
        assert_eq!(get_u32(&p, 72), 96, "size == offsetof(__reserved)");
        assert_eq!(get_u64(&p, 1040), PAGE_BYTES as u64, "data_offset");
        assert_eq!(get_u64(&p, 1048), 8 * PAGE_BYTES as u64, "data_size");
        assert_eq!(get_u64(&p, 1024), 0, "data_head");
        assert_eq!(get_u64(&p, 1032), 0, "data_tail");
    }

    #[test]
    fn update_brackets_the_snapshot_in_an_even_odd_even_seqlock() {
        let mut p = page();
        init(&mut p, PAGE_BYTES as u64);
        assert_eq!(seq(&p), 0);
        update(&mut p, 7, 100, 90);
        assert_eq!(seq(&p), 2, "one complete update leaves the lock even");
        assert_eq!(get_u32(&p, 12), 0, "index: no rdpmc-readable counter");
        assert_eq!(get_u64(&p, 16), 7, "offset == count");
        assert_eq!(get_u64(&p, 24), 100);
        assert_eq!(get_u64(&p, 32), 90);
        update(&mut p, 9, 200, 180);
        assert_eq!(seq(&p), 4);
        assert_eq!(get_u64(&p, 16), 9);
    }

    #[test]
    fn head_and_tail_round_trip_at_their_own_offsets() {
        let mut p = page();
        init(&mut p, PAGE_BYTES as u64);
        set_data_head(&mut p, 0x1234_5678_9abc);
        assert_eq!(data_head(&p), 0x1234_5678_9abc);
        assert_eq!(data_tail(&p), 0, "the kernel never writes data_tail");
        // Userspace publishes its tail in place.
        p[1032..1040].copy_from_slice(&4096u64.to_le_bytes());
        assert_eq!(data_tail(&p), 4096);
        assert_eq!(data_head(&p), 0x1234_5678_9abc, "tail store must not alias head");
    }
}
