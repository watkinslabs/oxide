// Linux async-domain KPI built on the canonical module workqueue.

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::{ffi::c_void, ptr, sync::atomic::{AtomicU64, Ordering}};
use sync::{Modules as ModulesLockClass, Spinlock};

const ASYNC_COOKIE_MAX: u64 = u64::MAX;
static NEXT_COOKIE: AtomicU64 = AtomicU64::new(1);
static PENDING: Spinlock<Vec<usize>, ModulesLockClass> = Spinlock::new(Vec::new());
#[cfg(target_os = "oxide-kernel")]
static ASYNC_WAIT: sched::live::WaitList = sched::live::WaitList::new();

#[repr(C)]
pub struct LinuxAsyncDomain { pending: [*mut c_void; 2], registered: u32 }

struct AsyncEntry {
    func: extern "C" fn(*mut u8, u64),
    data: *mut u8,
    cookie: u64,
    domain: *mut LinuxAsyncDomain,
}

/// Register Linux asynchronous callback and completion exports.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("async_schedule_node_domain", async_schedule_node_domain as *const () as usize),
        ("async_synchronize_full_domain", async_synchronize_full_domain as *const () as usize),
        ("async_synchronize_full", async_synchronize_full as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn async_schedule_node_domain(func: Option<extern "C" fn(*mut u8, u64)>, data: *mut u8, node: i32, domain: *mut LinuxAsyncDomain) -> u64 {
    let Some(func) = func else { return 0; };
    let cookie = NEXT_COOKIE.fetch_add(1, Ordering::AcqRel);
    let entry = Box::new(AsyncEntry { func, data, cookie, domain });
    let raw = Box::into_raw(entry);
    PENDING.lock().push(raw as usize);
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = node;
    #[cfg(target_os = "oxide-kernel")]
    let queued = if node < 0 { sched::live::workqueue::queue_work(run_entry, raw as usize) } else { sched::live::workqueue::queue_work_on(node as usize, run_entry, raw as usize) };
    #[cfg(not(target_os = "oxide-kernel"))]
    let queued = false;
    if !queued { run_entry(raw as usize); }
    cookie
}

extern "C" fn async_synchronize_full() { async_synchronize_full_domain(ptr::null_mut()); }

extern "C" fn async_synchronize_full_domain(domain: *mut LinuxAsyncDomain) {
    #[cfg(target_os = "oxide-kernel")]
    // SAFETY: process-context synchronization sleeps only until run_entry removes every matching pending record and wakes this list.
    unsafe { let _ = sched::live::wait_event_uninterruptible(&ASYNC_WAIT, || !pending_before(domain, ASYNC_COOKIE_MAX)); }
    #[cfg(not(target_os = "oxide-kernel"))]
    while pending_before(domain, ASYNC_COOKIE_MAX) { core::hint::spin_loop(); }
}

fn run_entry(raw: usize) {
    let entry = raw as *mut AsyncEntry;
    // SAFETY: entry was allocated by async_schedule_node_domain and is retained by PENDING until this callback removes it.
    unsafe { ((*entry).func)((*entry).data, (*entry).cookie); }
    let mut pending = PENDING.lock();
    pending.retain(|raw| *raw != entry as usize);
    drop(pending);
    // SAFETY: the entry was removed from the sole pending owner after its callback completed.
    unsafe { drop(Box::from_raw(entry)); }
    #[cfg(target_os = "oxide-kernel")]
    ASYNC_WAIT.wake_all();
}

fn pending_before(domain: *mut LinuxAsyncDomain, cookie: u64) -> bool {
    PENDING.lock().iter().copied().any(|raw| {
        let entry = raw as *const AsyncEntry;
        // SAFETY: every PENDING entry remains allocated until run_entry removes it after callback completion.
        unsafe { (*entry).cookie < cookie && ((*entry).domain == domain || (domain.is_null() && domain_is_registered((*entry).domain))) }
    })
}

fn domain_is_registered(domain: *mut LinuxAsyncDomain) -> bool {
    if domain.is_null() { return true; }
    // SAFETY: domain is caller-owned async_domain storage whose registered bit is immutable while queued work exists.
    unsafe { (*domain).registered & 1 != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};
    static OBSERVED_COOKIE: AtomicU64 = AtomicU64::new(0);
    extern "C" fn callback(_data: *mut u8, cookie: u64) { OBSERVED_COOKIE.store(cookie, Ordering::SeqCst); }
    #[test] fn schedule_returns_and_delivers_a_monotonic_cookie() { let _m = crate::test_serial::claim(); let first = async_schedule_node_domain(Some(callback), ptr::null_mut(), -1, ptr::null_mut()); let second = async_schedule_node_domain(Some(callback), ptr::null_mut(), -1, ptr::null_mut()); async_synchronize_full(); assert!(second > first); assert_eq!(OBSERVED_COOKIE.load(Ordering::SeqCst), second); }
}
