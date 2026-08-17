//! Getting this filesystem's `/sys/fs` surfaces published, and withdrawn.
//!
//! The reference claims its subsystem directory in module init and publishes a
//! mount's half when that mount's superblock is set up. There is no module
//! init here and this crate must not name a `/sys` type, so the integrator
//! that owns both installs a publisher, and every mount announces itself
//! through it.
//!
//! The order the boot takes is the reason a mount can be announced BEFORE a
//! publisher exists: the root filesystem is mounted while the machine is still
//! coming up, and the filesystem registrations that install the publisher run
//! afterwards. A mount announced early is remembered and published when the
//! publisher arrives — otherwise the one filesystem every system has would be
//! the one with no reports.
//!
//! Withdrawal is the mirror. Unmount arrives at this filesystem's own
//! superblock operations, which cannot name a pseudo-filesystem either, so the
//! integrator leaves the withdrawal here on the way in and unmount runs it on
//! the way out. Without it a directory reporting on an unreachable volume
//! outlives the volume.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as LockClass};

use crate::rootfs::RootfsState;

/// Publishes one mount's attributes.
pub type Publisher = fn(&Arc<RootfsState>);

/// Withdraws one mount's published attributes, given its directory name.
pub type Withdraw = fn(&str);

static PUBLISH:  Spinlock<Option<Publisher>, LockClass> = Spinlock::new(None);
static WITHDRAW: Spinlock<Option<Withdraw>, LockClass> = Spinlock::new(None);
/// Mounts that came up before a publisher existed. Weak, so a mount that is
/// gone by the time one arrives is not resurrected to publish reports about a
/// volume nobody can reach.
static PENDING: Spinlock<Vec<Weak<RootfsState>>, LockClass> = Spinlock::new(Vec::new());

/// Announce a mount. Publishes now if a publisher is installed, and is
/// remembered until one is otherwise. # C: O(attributes)
pub fn note_mounted(st: &Arc<RootfsState>) {
    let f = *PUBLISH.lock();
    match f {
        Some(f) => f(st),
        None => PENDING.lock().push(Arc::downgrade(st)),
    }
}

/// Install the publisher and publish everything mounted before it. Called
/// once, where the surfaces are published from. # C: O(pending mounts)
pub fn set_publisher(f: Publisher) {
    *PUBLISH.lock() = Some(f);
    let pending: Vec<Weak<RootfsState>> = core::mem::take(&mut *PENDING.lock());
    for w in pending { if let Some(st) = w.upgrade() { f(&st); } }
}

/// Install the withdrawal. # C: O(1)
pub fn set_withdraw(f: Withdraw) { *WITHDRAW.lock() = Some(f); }

/// Withdraw one mount's entries. Does nothing when nothing was published,
/// which is the state of every mount in a build that publishes no surfaces.
/// # C: cost of the withdrawal
pub fn run_withdraw(dev: &str) {
    let f = *WITHDRAW.lock();
    if let Some(f) = f { f(dev); }
}

#[cfg(test)]
#[path = "tests/surfaces.rs"]
mod tests;
