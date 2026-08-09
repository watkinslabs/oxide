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

    /// Open reference: bump count; fire `driver.open()` on 0->1 only, and
    /// clear any latched hangup — Linux `tty_open` ends with
    /// `clear_bit(TTY_HUPPED, &tty->flags)` on EVERY successful open,
    /// so a `vhangup(2)` revokes the open file
    /// descriptors without permanently killing the device. oxide's ttys are
    /// long-lived singletons; without this a single hangup on `/dev/console`
    /// would wedge the console for every later `login`.
    ///
    /// Clearing it is safe ONLY because a hangup also retires every
    /// description open across it: the tty's flag says "the LINE works again",
    /// never "the old session's descriptors work again"
    /// (`crate::hangup::revoke`).
    /// # C: O(1)
    pub fn open(&self) -> u32 {
        self.open_inner().0
    }

    /// `tty_open` for a description that wants to be revocable: same open, but
    /// returns the hangup generation to record on the `struct file`
    /// (`vfs::File::set_revoke_gen`). Clearing the tty's hung-up flag and
    /// reading the generation happen under ONE port-lock hold, so an open
    /// racing `hangup` samples either the pre- or the post-hangup generation
    /// and never a value that would let a revoked description look live.
    /// # C: O(1)
    pub fn open_revocable(&self, cap_sys_admin: bool) -> Result<u64, VfsError> {
        if self.exclusive() && self.open_count() != 0 && !cap_sys_admin {
            return Err(VfsError::Ebusy);
        }
        Ok(self.open_inner().1)
    }

    /// The shared open body: count, driver 0→1 edge, `clear_bit(TTY_HUPPED)`,
    /// and the generation this open is bound to. # C: O(1)
    fn open_inner(&self) -> (u32, u64) {
        let prev = self.open_count.fetch_add(1, Ordering::AcqRel);
        let gen = {
            let mut g = self.inner.lock_irqsave::<W::Irq>();
            g.ldisc.clear_hangup();
            if prev == 0 { g.driver.open(); }
            self.hup_gen.load(Ordering::Acquire)
        };
        (prev + 1, gen)
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
