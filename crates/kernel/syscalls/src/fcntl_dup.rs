use alloc::sync::Arc;

use vfs::{FdTable, File, KResult};

/// Duplicate one descriptor after retaining its open-file description. # C: O(fd words)
pub(crate) fn duplicate_fd(
    fdt: &FdTable,
    fd: i32,
    min: i32,
    cloexec: bool,
    limit: usize,
) -> KResult<i32> {
    let file = pin_duplicate_source(fdt, fd)?;
    #[cfg(test)]
    run_post_pin_hook();
    publish_duplicate(fdt, &file, min, cloexec, limit)
}

#[cfg(test)]
static POST_PIN_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
/// Install the one-shot post-pin duplication schedule hook. # C: O(1)
pub(crate) fn set_post_pin_hook(hook: Option<fn()>) {
    POST_PIN_HOOK.store(hook.map_or(0, |f| f as usize), core::sync::atomic::Ordering::Release);
}

#[cfg(test)]
fn run_post_pin_hook() {
    let ptr = POST_PIN_HOOK.swap(0, core::sync::atomic::Ordering::AcqRel);
    if ptr != 0 {
        // SAFETY: set_post_pin_hook stores only fn() pointers and swap grants sole use.
        let hook: fn() = unsafe { core::mem::transmute(ptr) };
        hook();
    }
}

/// Retain the source open-file description once for F_DUPFD*. # C: O(1)
pub(crate) fn pin_duplicate_source(fdt: &FdTable, fd: i32) -> KResult<Arc<File>> {
    fdt.get(fd)
}

/// Publish a duplicate of the retained source with descriptor flags atomically. # C: O(fd words)
pub(crate) fn publish_duplicate(
    fdt: &FdTable,
    file: &Arc<File>,
    min: i32,
    cloexec: bool,
    limit: usize,
) -> KResult<i32> {
    fdt.dup_file_min_limit(file, min, cloexec, limit)
}
