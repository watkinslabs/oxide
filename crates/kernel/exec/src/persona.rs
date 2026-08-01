// The persona-driven tail of the ELF load: SVr4 page-0 emulation.
//
// NOT target-gated. The execve slots that call this are
// `#[cfg(target_os = "oxide-kernel")]`, so a test written there never compiles;
// keeping the mapping here lets a hosted test drive it against a real
// `AddressSpace` and assert what actually landed at VA 0.
//
// The persona TEST is `sched::personality::mmap_page_zero`, taken by the
// caller — this crate owns the mapping, not the bit.

use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};

/// VA of the emulated page. Not a "0 is obviously zero" literal: it is the
/// SVr4 contract — the one address whose readability some pre-Linux binaries
/// depend on — and the loader must never place anything else there.
pub const PAGE_ZERO_VA: u64 = 0;

/// Protections SVr4 gave page 0, and the ones Linux reproduces:
/// `PROT_READ | PROT_EXEC`. Notably NOT writable — the emulation exists so a
/// null dereference READS zeroes, not so it can be scribbled on.
pub const PAGE_ZERO_PROT: VmaProt = VmaProt::READ.union(VmaProt::EXEC);

/// Linux `load_elf_binary`'s SVr4 emulation, run after every PT_LOAD and after
/// the interpreter — so a segment can never be displaced by it — for a task
/// whose persona carries `MMAP_PAGE_ZERO`:
///
/// ```text
/// error = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
///                 MAP_FIXED | MAP_PRIVATE, 0);
/// retval = do_mseal(0, PAGE_SIZE, 0);
/// ```
///
/// Both results are deliberately unchecked upstream: a system that refuses low
/// mappings simply gets no page 0 and the exec proceeds. The seal is what stops
/// the process from later turning the emulation page into a writable — or
/// unmapped-and-reused — null-pointer target; it is applied here for the same
/// reason, and a failed mapping just makes the seal a no-op.
///
/// Returns whether page 0 is mapped afterwards.
/// # C: O(log N_vmas)
pub fn map_page_zero(as_: &AddressSpace) -> bool {
    let Some(zero) = UserVirtAddr::new(PAGE_ZERO_VA) else { return false };
    let mapped = as_.mmap(
        Some(zero),
        hal::PAGE_SIZE_BYTES as usize,
        PAGE_ZERO_PROT,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
        true,
    ).is_ok();
    if let Some(end) = UserVirtAddr::new(PAGE_ZERO_VA + hal::PAGE_SIZE_BYTES) {
        let _ = as_.mseal_range(zero, end);
    }
    mapped
}
