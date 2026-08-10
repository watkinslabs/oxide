// The EFI memory map, kept past the firmware.
//
// The firmware's own map buffer is boot-services memory: it is not promised to
// exist after `ExitBootServices`, and the pages it sits in are handed back as
// free RAM. A kernel started later — this one's successor after a relocation —
// still needs that map, because on firmware that describes itself with ACPI it
// is the ONLY statement of where memory is. So the bytes are copied here, into
// a page-aligned block inside the kernel image, whose extent the boot memmap
// already carves out of usable RAM.
//
// The address recorded is the block's own, taken while the firmware's flat map
// is live, so it is physical — the form the property that names it must carry
// and the form the next kernel reads it in.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Bytes of map retained. The firmware's map on this machine is a few KiB; a
/// map longer than this is not retained at all rather than truncated, because
/// half a memory map describes a machine with holes that are not there.
pub const EFI_MMAP_MAX: usize = 16384;

#[repr(C, align(4096))]
struct MemMap(UnsafeCell<[u8; EFI_MMAP_MAX]>);
// SAFETY: written once by the boot CPU inside `efi_stub_setup`, before any
// other context exists; every later access is a read of a finished copy.
unsafe impl Sync for MemMap {}
static MMAP: MemMap = MemMap(UnsafeCell::new([0; EFI_MMAP_MAX]));

/// Physical address of the retained copy; 0 = nothing retained.
static MMAP_PA: AtomicU64 = AtomicU64::new(0);
/// Bytes of map at `MMAP_PA`.
static MMAP_SIZE: AtomicU32 = AtomicU32::new(0);
/// Bytes per descriptor, as the firmware reported it.
static DESC_SIZE: AtomicU32 = AtomicU32::new(0);
/// Descriptor layout version, as the firmware reported it.
static DESC_VER: AtomicU32 = AtomicU32::new(0);

/// Copy `len` bytes of firmware memory map from `src` into the retained block,
/// recording the stride and version that decode it.
///
/// Nothing is recorded unless the whole map fits and the descriptor stride is
/// self-consistent — a stride of zero, or one longer than the map, cannot be
/// walked, and a reader handed either would take the first descriptor's bytes
/// as the whole machine.
///
/// Called once per `GetMemoryMap` attempt, so the LAST attempt before
/// `ExitBootServices` succeeds is the copy that survives: an earlier attempt's
/// map is the one the firmware then declared stale.
///
/// # SAFETY: `src` must point to `len` readable bytes of the firmware's map,
/// and the caller must be the boot CPU inside the EFI stub, where nothing else
/// can observe the block.
/// # C: O(len)
pub unsafe fn retain(src: *const u8, len: u64, desc_size: u64, desc_ver: u32) {
    if len == 0 || len > EFI_MMAP_MAX as u64 { return; }
    if desc_size == 0 || desc_size > len { return; }
    // SAFETY: boot-path single writer; no other context exists to observe it.
    let dst = unsafe { &mut *MMAP.0.get() };
    let mut i = 0usize;
    while i < len as usize {
        // SAFETY: caller guarantees `src` covers `len` readable bytes and the
        // loop stays below it; `dst` is at least `EFI_MMAP_MAX` >= `len`.
        dst[i] = unsafe { *src.add(i) };
        i += 1;
    }
    MMAP_SIZE.store(len as u32, Ordering::Release);
    DESC_SIZE.store(desc_size as u32, Ordering::Release);
    DESC_VER.store(desc_ver, Ordering::Release);
    MMAP_PA.store(dst.as_ptr() as u64, Ordering::Release);
}

/// The retained map as `(pa, size, desc_size, desc_ver)`, or `None` when this
/// boot retained none.
/// # C: O(1)
pub fn retained() -> Option<(u64, u32, u32, u32)> {
    let pa = MMAP_PA.load(Ordering::Acquire);
    let size = MMAP_SIZE.load(Ordering::Acquire);
    if pa == 0 || size == 0 { return None; }
    Some((pa, size, DESC_SIZE.load(Ordering::Acquire), DESC_VER.load(Ordering::Acquire)))
}
