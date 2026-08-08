// `commit=` — the periodic journal commit.
//
// The reference gives every journal a thread that sleeps until the running
// transaction is `commit=` seconds old and then commits it, so a machine that
// crashes loses at most that much work whether or not anything called `sync`.
// Nothing here has a per-journal thread, so one periodic timer walks the live
// mounts and commits the ones whose interval has elapsed. The interval stays
// per mount, exactly as the journal's own commit interval is.
//
// Module manifest:
// - due: the "which transaction is old enough" decision, with no registry and
//   no clock behind it.

pub mod due;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::Mount;

/// Every mount whose journal this timer commits. `Weak`, so registering does
/// not keep a filesystem alive past its unmount; dead entries are pruned by the
/// walk that finds them.
static MOUNTS: sync::Spinlock<Vec<Registered>, sync::Superblock> =
    sync::Spinlock::new(Vec::new());

/// One registered mount and when this timer last committed its journal.
struct Registered {
    mount: Weak<Mount>,
    /// Monotonic timestamp of the last periodic commit. `None` until the first
    /// tick sees it — the registration path has no clock of its own, and a
    /// mount that has never been ticked has nothing old enough to commit.
    last_ns: Option<u64>,
}

/// Register `mount`'s journal for periodic commits. Idempotent per mount.
/// # C: O(N_mounts)
pub fn register(mount: &Arc<Mount>) {
    let mut g = MOUNTS.lock();
    if g.iter().any(|r| Weak::as_ptr(&r.mount) == Arc::as_ptr(mount)) { return; }
    g.push(Registered { mount: Arc::downgrade(mount), last_ns: None });
}

/// Commit every registered journal whose `commit=` interval has elapsed.
///
/// `now_ns` is the timer subsystem's own monotonic time, which is why this
/// takes it rather than reading a clock: it is the same time base every other
/// periodic in the kernel is paced by.
/// # C: O(N_mounts) + O(dirty) per due mount
pub fn tick(now_ns: u64) {
    let due: Vec<Arc<Mount>> = {
        let mut g = MOUNTS.lock();
        g.retain(|r| r.mount.strong_count() > 0);
        let mut due = Vec::new();
        for r in g.iter_mut() {
            let Some(m) = r.mount.upgrade() else { continue };
            match r.last_ns {
                // First sighting: start this mount's interval now rather than
                // committing a transaction whose age is unknown.
                None => r.last_ns = Some(now_ns),
                Some(last) if due::is_due(last, now_ns, m.behaviour().commit_secs) => {
                    // Stamped whether or not the commit below succeeds: a
                    // persistently failing device would otherwise turn every
                    // tick into another attempt.
                    r.last_ns = Some(now_ns);
                    due.push(m);
                }
                Some(_) => {}
            }
        }
        due
    };
    // Outside the registry lock: a commit sleeps on device I/O, and holding a
    // spinlock across that would park every other mount's registration behind
    // this one's disk.
    for m in due { let _ = m.commit_batch(); }
}

/// Register the periodic commit with the timer subsystem. Called by the mount
/// path, so a kernel that never mounts an ext4 filesystem never arms it.
/// Idempotent. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn arm() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::AcqRel) { return; }
    timer::register_periodic(due::TICK_PERIOD_NS, tick);
}

/// Hosted: there is no timer subsystem to arm, and the decision the tick would
/// make is driven directly. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn arm() {}

#[cfg(test)]
mod tests;
