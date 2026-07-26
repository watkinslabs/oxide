use ::core::sync::atomic::Ordering;

use vfs::VfsError;

use super::{TtyDriver, TtyStruct};
use crate::wait::TtyWait;

impl<D: TtyDriver, W: TtyWait> TtyStruct<D, W> {
    /// Current open reference count (Linux `tty_struct::count`).
    /// # C: O(1)
    pub fn open_count(&self) -> u32 {
        self.open_count.load(Ordering::Acquire)
    }

    /// True iff TIOCEXCL exclusive reopen mode is set.
    /// # C: O(1)
    pub fn exclusive(&self) -> bool {
        self.exclusive.load(Ordering::Acquire)
    }

    /// TIOCEXCL/TIOCNXCL state mutation.
    /// # C: O(1)
    pub fn set_exclusive(&self, on: bool) {
        self.exclusive.store(on, Ordering::Release);
    }

    /// Open reference with Linux `TTY_EXCLUSIVE` admission. Existing
    /// exclusive ttys reject non-CAP_SYS_ADMIN reopens with EBUSY.
    /// # C: O(1)
    pub fn open_with_cap_sys_admin(&self, cap_sys_admin: bool) -> Result<u32, VfsError> {
        if self.exclusive() && self.open_count() != 0 && !cap_sys_admin {
            return Err(VfsError::Ebusy);
        }
        Ok(self.open())
    }

    /// Open reference: bump count; fire `driver.open()` on 0->1 only.
    /// # C: O(1)
    pub fn open(&self) -> u32 {
        let prev = self.open_count.fetch_add(1, Ordering::AcqRel);
        if prev == 0 { self.inner.lock_irqsave::<W::Irq>().driver.open(); }
        prev + 1
    }

    /// Release reference: drop count; fire `driver.close()` on 1->0 only.
    /// # C: O(1)
    pub fn close(&self) -> u32 {
        let prev = self.open_count.load(Ordering::Acquire);
        if prev == 0 { return 0; }
        let now = self.open_count.fetch_sub(1, Ordering::AcqRel) - 1;
        if now == 0 { self.inner.lock_irqsave::<W::Irq>().driver.close(); }
        now
    }
}
