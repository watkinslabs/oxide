// F158: /proc/meminfo body builder. Extracted from procfs.rs to
// keep that file under the 1000-line cap. Linux-conformant field
// set: MemTotal/Free/Available track the live PMM, AnonPages /
// Mapped follow allocated PMM pages, swap/pagecache/slab/hugetlb
// fields stub to 0 (v1 has no swap, no pagecache, no slab
// accounting, no huge-tlb pool).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// # C: O(1) — fixed field set.
pub fn build() -> Vec<u8> {
    let mut b = Vec::with_capacity(1024);
    let (f, a) = pmm_kb_stats();
    let t = f + a;
    let r = |b: &mut Vec<u8>, k: &[u8], v: u64| {
        push(b, k); push_u64(b, v); push(b, b" kB\n");
    };
    for &(k, v) in &[
        (b"MemTotal:        " as &[u8], t),(b"MemFree:         ", f),(b"MemAvailable:    ", f),
        (b"Buffers:         ", 0),(b"Cached:          ", 0),(b"SwapCached:      ", 0),
        (b"Active:          ", a),(b"Inactive:        ", 0),
        (b"Active(anon):    ", a),(b"Inactive(anon):  ", 0),
        (b"Active(file):    ", 0),(b"Inactive(file):  ", 0),
        (b"Unevictable:     ", 0),(b"Mlocked:         ", 0),
        (b"SwapTotal:       ", 0),(b"SwapFree:        ", 0),
        (b"Dirty:           ", 0),(b"Writeback:       ", 0),
        (b"AnonPages:       ", a),(b"Mapped:          ", a),(b"Shmem:           ", 0),
        (b"KReclaimable:    ", 0),(b"Slab:            ", 0),
        (b"SReclaimable:    ", 0),(b"SUnreclaim:      ", 0),
        (b"KernelStack:     ", 64),(b"PageTables:      ", 0),
        (b"NFS_Unstable:    ", 0),(b"Bounce:          ", 0),(b"WritebackTmp:    ", 0),
        (b"CommitLimit:     ", t),(b"Committed_AS:    ", a),
        (b"VmallocTotal:    ", 0),(b"VmallocUsed:     ", 0),(b"VmallocChunk:    ", 0),
        (b"Percpu:          ", 0),(b"HardwareCorrupted:", 0),
        (b"AnonHugePages:   ", 0),(b"ShmemHugePages:  ", 0),(b"ShmemPmdMapped:  ", 0),
        (b"FileHugePages:   ", 0),(b"FilePmdMapped:   ", 0),
        (b"HugePages_Total: ", 0),(b"HugePages_Free:  ", 0),
        (b"HugePages_Rsvd:  ", 0),(b"HugePages_Surp:  ", 0),
        (b"Hugepagesize:    ", 2048),(b"Hugetlb:         ", 0),
        (b"DirectMap4k:     ", t),(b"DirectMap2M:     ", 0),(b"DirectMap1G:     ", 0),
    ] { r(&mut b, k, v); }
    b
}

fn pmm_kb_stats() -> (u64, u64) {
    match pmm_setup::pmm_static() {
        Some(p) => (p.free_pages() * 4, p.allocated_pages() * 4),
        None    => (0, 0),
    }
}

fn push(v: &mut Vec<u8>, b: &[u8]) { v.extend_from_slice(b); }

fn push_u64(v: &mut Vec<u8>, mut n: u64) {
    if n == 0 { v.push(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; v.push(buf[i]); }
}
