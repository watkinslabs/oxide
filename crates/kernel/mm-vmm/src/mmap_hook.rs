use core::sync::atomic::{AtomicPtr, Ordering};

static MMAP_ADDR_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub fn set_mmap_addr_hook(hook: fn(u64) -> bool) {
    MMAP_ADDR_HOOK.store(hook as *mut (), Ordering::Release);
}

pub(crate) fn admit_mmap_addr(addr: u64) -> bool {
    let raw = MMAP_ADDR_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return true; }
    // SAFETY: only `set_mmap_addr_hook` stores function pointers with this
    // exact signature, and the pointer remains installed for kernel lifetime.
    let hook: fn(u64) -> bool = unsafe { core::mem::transmute(raw) };
    hook(addr)
}
