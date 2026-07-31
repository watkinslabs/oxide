// The `Vm*` / `Rss*` block of `/proc/<pid>/status` and the seven fields of
// `/proc/<pid>/statm`. Both read the SAME per-mm counters `ru_maxrss` reads,
// so the three can never disagree about one process's residency.
//
// Pure: the caller collects the numbers from the live address space and this
// module decides the row set, the order, the units and the classification.

use alloc::vec::Vec;

use crate::status_render::format::{push, push_dec};

/// Every number the memory rows need, in PAGES (residency) or BYTES
/// (virtual extents), exactly as the address space accounts them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemStatus {
    /// Sum of every mapped VMA (Linux `total_vm`), bytes.
    pub total_vm_bytes:  u64,
    /// `VM_LOCKED` extent (Linux `locked_vm`), bytes.
    pub locked_vm_bytes: u64,
    /// Executable, non-writable, non-stack extent (Linux `exec_vm`), bytes.
    pub exec_vm_bytes:   u64,
    /// Private writable non-stack extent (Linux `data_vm`), bytes.
    pub data_vm_bytes:   u64,
    /// Stack extent (Linux `stack_vm`), bytes.
    pub stack_vm_bytes:  u64,
    /// Every page-table frame this mm owns, bytes.
    pub pgtable_bytes:   u64,
    /// Resident anonymous pages (`MM_ANONPAGES`).
    pub rss_anon_pages:  u64,
    /// Resident file pages (`MM_FILEPAGES`).
    pub rss_file_pages:  u64,
    /// Resident shared pages (`MM_SHMEMPAGES`).
    pub rss_shmem_pages: u64,
    /// Non-resident swap entries (`MM_SWAPENTS`).
    pub swap_pages:      u64,
    /// Peak of `rss_pages()`, already folded with the live total.
    pub hiwater_rss_pages: u64,
}

const BYTES_PER_KIB: u64 = 1024;
/// `VmExe`/`VmLib`/`VmPTE` are printed right-aligned in an 8-wide field.
const NARROW_FIELD_WIDTH: usize = 8;

impl MemStatus {
    /// Linux `get_mm_rss` — anonymous + file + shared resident pages. Swap
    /// entries are not resident and are excluded. # C: O(1)
    pub const fn rss_pages(&self) -> u64 {
        self.rss_anon_pages + self.rss_file_pages + self.rss_shmem_pages
    }

    /// `VmPeak`. Linux latches `hiwater_vm` only when about to LOWER
    /// `total_vm`, so a reader must report the larger of the two; with no
    /// shrink yet recorded the live total is the peak. # C: O(1)
    pub const fn peak_vm_bytes(&self) -> u64 { self.total_vm_bytes }

    /// `VmHWM`, folded against the live total for the same reason the peak
    /// virtual size is. # C: O(1)
    pub const fn hiwater_rss(&self) -> u64 {
        let live = self.rss_pages();
        if self.hiwater_rss_pages > live { self.hiwater_rss_pages } else { live }
    }
}

const fn kib_of_pages(p: u64) -> u64 { p.saturating_mul(4096 / BYTES_PER_KIB) }
const fn kib_of_bytes(b: u64) -> u64 { b / BYTES_PER_KIB }

/// The `/proc/<pid>/status` memory block, in Linux's row order. Emitted only
/// for a task that has an mm — a kernel thread prints none of these rows.
/// # C: O(1)
pub fn render_status_rows(m: &MemStatus) -> Vec<u8> {
    let mut o = Vec::with_capacity(320);
    row(&mut o, b"VmPeak:\t", kib_of_bytes(m.peak_vm_bytes()));
    row(&mut o, b"VmSize:\t", kib_of_bytes(m.total_vm_bytes));
    row(&mut o, b"VmLck:\t",  kib_of_bytes(m.locked_vm_bytes));
    // Linux `pinned_vm` counts long-term GUP pins; nothing pins user pages
    // that way here, so this is a true zero rather than a missing source.
    row(&mut o, b"VmPin:\t",  0);
    row(&mut o, b"VmHWM:\t",  kib_of_pages(m.hiwater_rss()));
    row(&mut o, b"VmRSS:\t",  kib_of_pages(m.rss_pages()));
    row(&mut o, b"RssAnon:\t",  kib_of_pages(m.rss_anon_pages));
    row(&mut o, b"RssFile:\t",  kib_of_pages(m.rss_file_pages));
    row(&mut o, b"RssShmem:\t", kib_of_pages(m.rss_shmem_pages));
    row(&mut o, b"VmData:\t", kib_of_bytes(m.data_vm_bytes));
    row(&mut o, b"VmStk:\t",  kib_of_bytes(m.stack_vm_bytes));
    wide_row(&mut o, b"VmExe:\t", kib_of_bytes(m.exec_vm_bytes));
    // Linux splits the executable extent into the main binary's text and
    // everything else; without a start_code/end_code range recorded per mm the
    // whole extent is text and none of it is library.
    wide_row(&mut o, b"VmLib:\t", 0);
    wide_row(&mut o, b"VmPTE:\t", kib_of_bytes(m.pgtable_bytes));
    row(&mut o, b"VmSwap:\t", kib_of_pages(m.swap_pages));
    o
}

fn row(o: &mut Vec<u8>, label: &[u8], kib: u64) {
    push(o, label); push_dec(o, kib); push(o, b" kB\n");
}

fn wide_row(o: &mut Vec<u8>, label: &[u8], kib: u64) {
    push(o, label);
    let start = o.len();
    push_dec(o, kib);
    let pad = NARROW_FIELD_WIDTH.saturating_sub(o.len() - start);
    for _ in 0..pad { o.insert(start, b' '); }
    push(o, b" kB\n");
}

/// `/proc/<pid>/statm`: `size resident shared text lib data dt`, all in PAGES.
/// `lib` and `dt` have been hardwired zero since Linux 2.6; `shared` is the
/// file+shmem residency, and `text` the executable extent. # C: O(1)
pub fn render_statm(m: &MemStatus) -> Vec<u8> {
    let shared = m.rss_file_pages + m.rss_shmem_pages;
    let pages = |b: u64| b / 4096;
    let mut o = Vec::with_capacity(64);
    for (i, v) in [
        pages(m.total_vm_bytes),
        shared + m.rss_anon_pages,
        shared,
        pages(m.exec_vm_bytes),
        0,
        pages(m.data_vm_bytes + m.stack_vm_bytes),
        0,
    ].iter().enumerate() {
        if i != 0 { o.push(b' '); }
        push_dec(&mut o, *v);
    }
    o.push(b'\n');
    o
}

/// Linux `vm_stat_account`'s three-way classification of one VMA's extent.
/// Exactly one bucket, tested in this order: executable code is
/// exec-and-not-writable-and-not-stack; a growable region is stack; a private
/// writable region is data. Anything else (a shared file mapping, a read-only
/// data mapping) lands in none of them and only counts toward `total_vm`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmClass { Exec, Stack, Data, Other }

/// `# C: O(1)`
pub const fn classify(exec: bool, write: bool, stack: bool, shared: bool) -> VmClass {
    if exec && !write && !stack { VmClass::Exec }
    else if stack               { VmClass::Stack }
    else if write && !shared    { VmClass::Data }
    else                        { VmClass::Other }
}

#[cfg(test)]
mod tests;
