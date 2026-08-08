// `commit=` — the periodic journal commit.
//
// The reference gives every journal a thread that sleeps until the running
// transaction is `commit=` seconds old and then commits it, so a machine that
// crashes loses at most that much work whether or not anything called `sync`.
// Nothing here has a per-journal thread, so one periodic timer walks the live
// mounts and commits the ones whose interval has elapsed. The interval stays
// per mount, exactly as the journal's own commit interval is.
//
// The same walk also paces `init_itable=`: lazy inode-table initialisation is
// the reference's other per-filesystem background job, and giving it a second
// registry of live mounts would be a second answer to "which filesystems are
// mounted" — free to disagree with this one.
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
    /// Lazy inode-table initialisation state: when the last group finished,
    /// how long that group earned as a pause, and which group to look from
    /// next. `None` timestamp = no group done yet, so the next may start at
    /// once.
    itable: ItableProgress,
}

/// How far lazy inode-table initialisation has got on one mount.
#[derive(Clone, Copy, Default)]
struct ItableProgress {
    /// When the group being measured started. The periodic tick is the finest
    /// clock this job has, so a group's cost is measured as the ticks it
    /// spanned: one for a group that finished inside a tick, more for one that
    /// ran long. That measurement is what the option multiplies.
    started_ns: Option<u64>,
    last_ns: Option<u64>,
    wait_ns: u64,
    next_group: u32,
    /// Every group has been initialised; nothing left to walk.
    done: bool,
}

/// Register `mount`'s journal for periodic commits. Idempotent per mount.
/// # C: O(N_mounts)
pub fn register(mount: &Arc<Mount>) {
    let mut g = MOUNTS.lock();
    if g.iter().any(|r| Weak::as_ptr(&r.mount) == Arc::as_ptr(mount)) { return; }
    g.push(Registered { mount: Arc::downgrade(mount), last_ns: None,
                        itable: ItableProgress::default() });
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
    run_itable_init(now_ns);
}

/// Advance lazy inode-table initialisation by at most ONE group per mount per
/// tick. A group is a large write; the pause `init_itable=` names is what keeps
/// the whole job from being a device-wide stall, and doing several groups in
/// one tick would spend the pause before earning it.
/// # C: O(N_mounts) + O(itable bytes) per due mount
fn run_itable_init(now_ns: u64) {
    let due: Vec<(Arc<Mount>, u32)> = {
        let mut g = MOUNTS.lock();
        let mut due = Vec::new();
        for r in g.iter_mut() {
            let Some(m) = r.mount.upgrade() else { continue };
            if r.itable.done { continue; }
            // `noinit_itable` is what turns the job off entirely.
            let Some(mult) = m.behaviour().li_wait_mult else { continue };
            // Close out the previous group's measurement before asking whether
            // another is due: the pause a group earned is not known until the
            // tick that observes it finished.
            if let Some(started) = r.itable.started_ns.take() {
                r.itable.wait_ns = crate::itable_init::decide::wait_after_group_ns(
                    now_ns.saturating_sub(started), mult);
                r.itable.last_ns = Some(started);
            }
            if !crate::itable_init::decide::is_due(r.itable.last_ns, r.itable.wait_ns, now_ns) {
                continue;
            }
            r.itable.started_ns = Some(now_ns);
            due.push((m, r.itable.next_group));
        }
        due
    };
    for (m, from) in due {
        let outcome = m.init_next_inode_table(from);
        let mut g = MOUNTS.lock();
        let Some(r) = g.iter_mut().find(|r| Weak::as_ptr(&r.mount) == Arc::as_ptr(&m)) else { continue };
        match outcome {
            // Nothing left to initialise: stop walking this mount's groups
            // rather than re-reading every descriptor on every tick.
            Ok(None) => { r.itable.done = true; r.itable.started_ns = None; }
            Ok(Some(n)) => r.itable.next_group = n.saturating_add(1),
            // A group that could not be initialised is skipped, not retried
            // forever: the rest of the filesystem's groups still want doing.
            Err(_) => r.itable.next_group = from.saturating_add(1),
        }
    }
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
