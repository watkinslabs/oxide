use core::sync::atomic::{AtomicU64, Ordering};

use crate::{VmaFlags, VmaProt};

/// VMA lifecycle notification consumed by the perf sideband owner.
///
/// The callback runs synchronously while the VMA operation still owns the
/// mmap write lock, just like Linux's `perf_event_mmap(vma)`. `name` is only
/// borrowed for the duration of the call and must not be retained.
pub type MmapEventHook = fn(u64, u64, u64, VmaProt, VmaFlags, &[u8], u64, u64);

static MMAP_EVENT_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the one owner of VMA mapping notifications.
pub fn set_mmap_event_hook(hook: MmapEventHook) {
    MMAP_EVENT_HOOK.store(hook as usize as u64, Ordering::Release);
}

pub(crate) fn notify(
    addr: u64, len: u64, pgoff: u64, prot: VmaProt, flags: VmaFlags,
    name: &[u8], dev: u64, ino: u64,
) {
    let raw = MMAP_EVENT_HOOK.load(Ordering::Acquire);
    if raw == 0 { return; }
    // SAFETY: the slot is written only by set_mmap_event_hook with this exact
    // function-pointer type, and the callback is invoked synchronously.
    let hook: MmapEventHook = unsafe { core::mem::transmute_copy(&raw) };
    hook(addr, len, pgoff, prot, flags, name, dev, ino);
}

