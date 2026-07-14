use sync::{FdTable as HookLock, Spinlock};

static FILE_REF_DROP_HOOK: Spinlock<Option<fn()>, HookLock> = Spinlock::new(None);

/// Install the callback run after an fd-table `Arc<File>` reference is dropped.
/// # C: O(1)
pub fn set_file_ref_drop_hook(hook: fn()) { *FILE_REF_DROP_HOOK.lock() = Some(hook); }

/// Notify the installed owner after the reference count is already decremented.
/// # C: callback-dependent
pub(crate) fn fire_file_ref_drop_hook() {
    let hook = *FILE_REF_DROP_HOOK.lock();
    if let Some(hook) = hook { hook(); }
}
