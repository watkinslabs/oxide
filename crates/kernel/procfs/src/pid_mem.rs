// `/proc/<pid>/status` + `/proc/<pid>/statm` value COLLECTION for the memory
// rows. Reads the live address space's own counters — the SAME ones
// `getrusage`'s `ru_maxrss` reads — and hands them to `crate::mem_render`,
// which owns every decision about row set, order and units.
//
// Residency comes from the per-mm PTE counters, never from a walk of the VMA
// tree: mapped extent is not resident set, and reporting the former as `VmRSS`
// told every reader a freshly-mmap'd process had already faulted the whole
// mapping in.
#![cfg(any(target_os = "oxide-kernel", test))]

use alloc::vec::Vec;

use crate::mem_render::{classify, render_statm, render_status_rows, MemStatus, VmClass};

/// Snapshot one task's memory accounting. `None` for a task with no address
/// space (a kernel thread), which is exactly when Linux prints no `Vm*` rows.
/// # C: O(N_vmas); # Lk: mm_pin, vma read
pub fn mem_status(task: &sched::Task) -> Option<MemStatus> {
    // A foreign task's mm can be replaced by a concurrent execve/exit on
    // another CPU; `clone_mm` pins it for this read.
    let mm = task.clone_mm()?;
    let a = mm.accounting_snapshot();
    let rss = a.rss_pages();
    let mut m = MemStatus {
        locked_vm_bytes:   a.locked_virtual_bytes,
        pgtable_bytes:     a.page_table_frames * vmm::rss::PAGE_BYTES,
        rss_anon_pages:    rss.anon,
        rss_file_pages:    rss.file,
        rss_shmem_pages:   rss.shmem,
        swap_pages:        rss.swapents,
        hiwater_rss_pages: a.hiwater_rss_pages,
        hugetlb_pages:     rss.hugetlb,
        ..MemStatus::default()
    };
    for vma in mm.snapshot_vmas() {
        let bytes = vma.end.as_u64() - vma.start.as_u64();
        m.total_vm_bytes += bytes;
        let p = vma.prot;
        match classify(
            p.contains(vmm::VmaProt::EXEC),
            p.contains(vmm::VmaProt::WRITE),
            vma.flags.contains(vmm::VmaFlags::GROWSDOWN),
            vma.flags.contains(vmm::VmaFlags::SHARED),
        ) {
            VmClass::Exec  => m.exec_vm_bytes  += bytes,
            VmClass::Stack => m.stack_vm_bytes += bytes,
            VmClass::Data  => m.data_vm_bytes  += bytes,
            VmClass::Other => {}
        }
    }
    Some(m)
}

/// The `Vm*`/`Rss*` block for `/proc/<pid>/status`; empty for a kernel thread.
/// # C: O(N_vmas)
pub fn status_rows(task: &sched::Task) -> Vec<u8> {
    match mem_status(task) { Some(m) => render_status_rows(&m), None => Vec::new() }
}

/// `/proc/<pid>/statm`. Linux prints seven zeroes for a task with no mm.
/// # C: O(N_vmas)
pub fn statm_body(task: &sched::Task) -> Vec<u8> {
    render_statm(&mem_status(task).unwrap_or_default())
}
