//! Address-space user and structural reference lifecycle.
//!
//! `mm_users` counts task-owned uses. `Arc<AddressSpace>` is the structural
//! `mm_count`: observers and lazy-TLB residency may keep the allocation/root
//! alive after the last user has synchronously or asynchronously run the
//! sleepable VMA and leaf teardown.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::{accounting, unregister_live_address_space, AddressSpace};

type Teardown = unsafe extern "C" fn(u64);

fn callback(raw: u64) -> Option<Teardown> {
    if raw == 0 { return None; }
    // SAFETY: `set_lifecycle` stores only a `Teardown` function pointer cast
    // through usize, and both supported targets fit usize in u64.
    Some(unsafe { core::mem::transmute(raw as usize) })
}

impl AddressSpace {
    /// Install the sleepable last-user walker and atomic-safe final-root drop.
    /// Fresh boot-anchor address spaces deliberately install neither.
    /// # C: O(1)
    pub fn set_lifecycle(&self, exit_mmap: Teardown, mmdrop: Teardown) {
        self.exit_mmap.store((exit_mmap as usize) as u64, Ordering::Release);
        self.teardown.store((mmdrop as usize) as u64, Ordering::Release);
    }

    /// Acquire one task-owned address-space use. Structural observers clone
    /// the `Arc` instead and therefore do not delay last-user teardown.
    /// # C: O(1)
    pub fn mmget(&self) {
        hal::kassert!(!self.exit_done.load(Ordering::Acquire), "mmget resurrected dead address space");
        let prior = self.mm_users.fetch_add(1, Ordering::AcqRel);
        hal::kassert!(prior != u32::MAX, "address-space user count overflow");
    }

    fn put_user(&self) -> bool {
        let prior = self.mm_users.fetch_sub(1, Ordering::AcqRel);
        hal::kassert!(prior != 0, "address-space user count underflow");
        prior == 1
    }

    /// Linux-shaped `mmput`: release one task-owned use and run last-user
    /// teardown in the caller's sleepable process context.
    /// # Ctx: process
    /// # Sleeps: yes
    /// # C: O(VMAs + page tables) on the last user
    pub fn mmput(mm: Arc<Self>) {
        if mm.put_user() { mm.finish_mmput(); }
    }

    /// Linux-shaped `mmput_async` decision. A non-final use is consumed here;
    /// the last use is returned intact for a process-context drainer.
    /// # Ctx: any
    /// # C: O(1)
    pub fn mmput_async(mm: Arc<Self>) -> Option<Arc<Self>> {
        if mm.put_user() { Some(mm) } else { None }
    }

    /// Complete the last-user half selected by `mmput_async`.
    /// # Ctx: process
    /// # Sleeps: yes
    /// # C: O(VMAs + page tables)
    pub fn finish_mmput(&self) {
        let first = self.exit_done.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok();
        hal::kassert!(first, "address-space last-user teardown repeated");
        unregister_live_address_space(self.root_pa);
        if let Some(exit) = callback(self.exit_mmap.load(Ordering::Acquire)) {
            // SAFETY: the last task user is gone; structural `Arc` pins retain
            // this mm and its root while the installed walker removes leaves.
            unsafe { exit(self.root_pa); }
        }
        // Run vm_ops close and backing destruction only after every leaf is
        // gone, with no mmap lock held across a potentially sleeping Drop.
        let tree = {
            let mut vmas = self.vmas.write();
            core::mem::take(&mut *vmas)
        };
        drop(tree);
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        self.debug_lifetime_event(b"drop-enter");
        let users = self.mm_users.load(Ordering::Acquire);
        hal::kassert!(users == 0, "address space dropped with task users");
        // An unpublished construction can fail before a Task acquires its
        // first user. That process-context path still owns its cleanup here.
        if !self.exit_done.load(Ordering::Acquire) { self.finish_mmput(); }
        unregister_live_address_space(self.root_pa);
        #[cfg(feature = "debug-swap")]
        {
            klog::write_raw(b"[AS-DROP] root=");
            klog::write_hex_u64(self.root_pa);
            klog::write_raw(b" cpumask=");
            klog::write_hex_u64(self.cpumask.load(Ordering::Acquire).low_word());
            klog::write_raw(b" vmas=0\n");
        }
        if let Some(drop_root) = callback(self.teardown.load(Ordering::Acquire)) {
            // SAFETY: final structural reference is gone, so no CPU or observer
            // can reach this root; the callback releases only the root frame.
            unsafe { drop_root(self.root_pa); }
        }
        accounting::unregister_page_table_owner(self.root_pa);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static EXIT: AtomicUsize = AtomicUsize::new(0);
    static ROOT: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn exit(_: u64) { EXIT.fetch_add(1, Ordering::AcqRel); }
    unsafe extern "C" fn root(_: u64) { ROOT.fetch_add(1, Ordering::AcqRel); }

    fn reset() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        EXIT.store(0, Ordering::Release);
        ROOT.store(0, Ordering::Release);
        guard
    }

    #[test]
    fn last_user_teardown_precedes_final_structural_drop() {
        let _guard = reset();
        let mm = AddressSpace::new(0).expect("address space");
        mm.set_lifecycle(exit, root);
        mm.mmget();
        let observer = Arc::clone(&mm);
        let final_user = AddressSpace::mmput_async(mm).expect("last user schedules teardown");
        assert_eq!(EXIT.load(Ordering::Acquire), 0, "async put ran sleepable teardown inline");
        final_user.finish_mmput();
        assert_eq!(EXIT.load(Ordering::Acquire), 1);
        drop(final_user);
        assert_eq!(ROOT.load(Ordering::Acquire), 0, "observer is an mm_count pin");
        drop(observer);
        assert_eq!(ROOT.load(Ordering::Acquire), 1);
    }

    #[test]
    fn only_the_last_task_user_requests_async_work() {
        let _guard = reset();
        let mm = AddressSpace::new(0).expect("address space");
        mm.set_lifecycle(exit, root);
        mm.mmget();
        mm.mmget();
        assert!(AddressSpace::mmput_async(Arc::clone(&mm)).is_none());
        let final_user = AddressSpace::mmput_async(mm).expect("second task was last user");
        final_user.finish_mmput();
        drop(final_user);
        assert_eq!(EXIT.load(Ordering::Acquire), 1);
        assert_eq!(ROOT.load(Ordering::Acquire), 1);
    }
}
