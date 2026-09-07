//! Address-space backend for the process heap: reservations and commits go to
//! the NT virtual-memory owner, block bodies through the user-copy routines.

use ntheap::HeapBackend;
use vmm::{AddressSpace, VmaProt};

/// Bytes filled per user-copy call when a body has to be cleared.
const FILL_CHUNK: usize = 512;

/// One process address space presented to the allocator.
pub struct MmBackend<'a> { pub as_: &'a AddressSpace }

fn protection() -> VmaProt { VmaProt::READ | VmaProt::WRITE }

/// Bounded trace of the heap's address-space operations: a heap that costs
/// mappings per allocation shows up here as a stream instead of a handful.
fn trace_region(op: &'static [u8], base: u64, size: usize) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static BUDGET: AtomicU32 = AtomicU32::new(0);
    if BUDGET.fetch_add(1, Ordering::Relaxed) >= TRACE_BUDGET { return; }
    klog::write_raw(b"[WINDOWS-HEAP] op="); klog::write_raw(op);
    klog::write_raw(b" base="); klog::write_hex_u64(base);
    klog::write_raw(b" size="); klog::write_hex_u64(size as u64); klog::write_raw(b"\n");
}

/// Trace lines the heap may emit before it goes quiet.
const TRACE_BUDGET: u32 = 256;

impl HeapBackend for MmBackend<'_> {
    /// # C: O(log N_vmas)
    fn reserve(&mut self, size: usize) -> Option<u64> {
        let base = elf_load::nt_memory::allocate(self.as_, None, size, protection(), false).ok().map(|allocation| allocation.base.as_u64());
        if let Some(base) = base { trace_region(b"reserve", base, size); }
        base
    }
    /// # C: O(log N_vmas)
    fn commit(&mut self, base: u64, size: usize) -> bool {
        let Some(base) = hal::UserVirtAddr::new(base) else { return false; };
        elf_load::nt_memory::allocate_or_commit(self.as_, Some(base), size, protection()).is_ok()
    }
    /// # C: O(pages)
    fn release(&mut self, base: u64, size: usize) -> bool {
        // A region is committed a granule at a time, so its extent spans
        // several VMAs; the release path that zaps page tables takes the whole
        // range at once rather than one recorded allocation.
        let Some(address) = hal::UserVirtAddr::new(base) else { return false; };
        trace_region(b"release", base, size);
        elf_load::nt_unmap::unmap_range(self.as_, address, size).is_ok()
    }
    /// # C: O(len)
    fn read(&self, addr: u64, out: &mut [u8]) -> bool { uaccess::copy_from_user(out, addr).is_ok() }
    /// # C: O(len)
    fn write(&mut self, addr: u64, data: &[u8]) -> bool { uaccess::copy_to_user(addr, data).is_ok() }
    /// # C: O(len)
    fn fill(&mut self, addr: u64, len: usize, byte: u8) -> bool {
        let filler = [byte; FILL_CHUNK];
        let mut done = 0;
        while done < len {
            let step = FILL_CHUNK.min(len - done);
            if uaccess::copy_to_user(addr + done as u64, &filler[..step]).is_err() { return false; }
            done += step;
        }
        true
    }
}
