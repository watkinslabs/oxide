// epoll surface per Linux 2.6.0. v1: EpollInode holds an interest
// list (Vec<EpollEntry>) under a Spinlock. epoll_ctl mutates;
// epoll_wait scans entries, reports any whose fd is still open as
// ready (level-triggered) and returns up to maxevents records.
// Real readiness predicates land when the wait infrastructure is
// in place; v1 keeps libuv / tokio happy past the create+ctl boundary.





use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, default_inode_ops, mk_mode};

#[path = "epoll/scan.rs"]
mod scan;
#[path = "epoll/syscalls.rs"]
mod syscalls;
pub use syscalls::{sys_epoll_create, sys_epoll_create1, sys_epoll_ctl, sys_epoll_pwait, sys_epoll_pwait2, sys_epoll_wait};

// Park / wake plumbing lives in `sched::live` so net/IPC layers
// (which don't depend on `fs`) can trigger epoll wakeups without a
// circular crate edge. See `sched::live::EPOLL_GLOBAL_WAIT` and
// `sched::live::notify_epoll_waiters`.

const EPOLL_INO_BASE: Ino = 0x7400_0000;
const EPOLL_INO_MASK: Ino = 0x00FF_FFFF;

/// DIAG bound: cap on `[epoll-lvl]` lines so the busy-loop trace can't flood.
/// Gated behind the off-by-default `debug-epoll` feature (NOT `debug-boot`),
/// so it ships only when explicitly diagnosing a level-triggered epoll spin.
#[cfg(feature = "debug-epoll")]
pub(super) static EPOLL_DIAG_N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub(super) const EPOLL_CTL_ADD: i32 = 1;
pub(super) const EPOLL_CTL_DEL: i32 = 2;
pub(super) const EPOLL_CTL_MOD: i32 = 3;

#[cfg(target_arch = "x86_64")]
pub(super) const EPOLL_EVENT_SIZE: usize = 12;
#[cfg(target_arch = "aarch64")]
pub(super) const EPOLL_EVENT_SIZE: usize = 16;

#[cfg(target_arch = "x86_64")]
pub(super) const EPOLL_DATA_OFF: usize = 4;
#[cfg(target_arch = "aarch64")]
pub(super) const EPOLL_DATA_OFF: usize = 8;

#[derive(Clone)]
pub struct EpollEntry {
    pub fd: i32,
    /// Unique per-epitem subscription id (Linux registers a wait-queue callback
    /// per epitem, NOT per epoll instance). Keying the inode's `PollSubscribers`
    /// on this — not `ep.id` — is what lets ONE epoll watch several fds that
    /// share a `PollSubscribers` source without one ADD replacing another's
    /// registration, and lets a `DEL` of one such fd not orphan the others'
    /// wake (the missing-wake that stalled socket-activated userdbd).
    pub sub_id: u32,
    pub events: u32,
    pub data: u64,
    /// EPOLLET edge tracking: ready bits already edge-delivered and still
    /// ready. A level-ready fd (e.g. /proc/self/mountinfo, always POLLIN)
    /// registered with EPOLLET must fire only on a not-ready→ready edge,
    /// once — not every scan. Without this, systemd's sd-event (which uses
    /// EPOLLET) busy-looped epoll_pwait forever on always-ready fds.
    pub et_seen: u32,
    /// Weak ref to the watched inode, captured at ADD, so EpollInode::poll()
    /// (nested-epoll readiness) can scan entries WITHOUT an fd_table — a
    /// nested epoll fd is POLLIN-readable only when one of its entries would
    /// fire. Without poll(), EpollInode used the default always-ready poll →
    /// any parent epoll (e.g. Go's netpoller watching a fsnotify watcher
    /// epoll) spun forever.
    pub inode: Option<alloc::sync::Weak<vfs::Inode>>,
    /// Watched fd's PollSubscribers generation at the last report. A later scan
    /// seeing a higher gen knows a real readiness event fired since — a fresh
    /// EPOLLET edge — even if et_seen still holds the bit (userspace drained with
    /// no intervening scan). Fixes EPOLLET losing an edge on accept/read.
    pub last_gen: u64,
    /// GLOBAL_EPOLL_GEN at the last report — covers readiness delivered via the
    /// global broadcast fallback (wake_peer_subs when the peer end-subs slot is
    /// empty), which does NOT bump the per-inode gen.
    pub last_ggen: u64,
}

/// EPOLLET — edge-triggered (Linux `EPOLLET` = 1<<31).
pub(super) const EPOLLET: u32 = 0x8000_0000;

/// Per-inode epoll state (Linux `i_private`).
pub struct EpollData {
    pub id:      u32,
    pub entries: Spinlock<Vec<EpollEntry>, TaskListClass>,
    /// F181: per-EpollData WaitList (Arc'd so subscribers can hold
    /// Weak). epoll_wait parks here; F181-aware event sites wake
    /// only the EpollData that subscribed via `epoll_ctl(ADD)`.
    /// Kernel-only — hosted tests don't run the scheduler.
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: Arc<sched::live::WaitList>,
}

static EPOLLS: Spinlock<Vec<Arc<EpollData>>, TaskListClass>
    = Spinlock::new(Vec::new());

/// F181: broadcast wake registered with sched at boot via
/// `install_epoll_broadcast`. Walks every live EpollData and
/// wakes its per-instance waitlist. Kernel-only — hosted tests
/// don't run epoll_wait.
/// # C: O(N_epoll_instances)
/// Global readiness-event generation, bumped on every GLOBAL epoll broadcast
/// (`broadcast_wake_all_epolls`, i.e. the `wake_peer_subs` fallback / any keyless
/// wake). An EPOLLET entry whose per-inode PollSubscribers gen did NOT advance
/// (the readiness event was delivered via the global fallback, not a targeted
/// notify) still learns an edge fired if THIS counter advanced since its last
/// report — closing the last EPOLLET lost-edge path (intermittent: dbus-broker
/// occasionally never reads polkit's AUTH when the connected-socket wake took the
/// fallback, so polkit's RequestName never completes → 45s Type=dbus timeout).
pub static GLOBAL_EPOLL_GEN: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "oxide-kernel")]
pub fn broadcast_wake_all_epolls() {
    GLOBAL_EPOLL_GEN.fetch_add(1, Ordering::AcqRel);
    let snapshot: Vec<Arc<EpollData>> = EPOLLS.lock().iter().cloned().collect();
    for ep in snapshot { ep.waiters.wake_all(); }
}

/// Bump ONLY the global epoll generation (no lock, no waitlist wake) — the
/// switch-tail-safe half of the broadcast, driven by `sched::live::bump_epoll_gen`
/// when a zombie enters `ZOMBIES` after its exit-time notify already consumed a
/// gen edge. The next `epoll_wait` safety-net rescan re-evaluates and reaps.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn bump_global_epoll_gen() {
    GLOBAL_EPOLL_GEN.fetch_add(1, Ordering::AcqRel);
}

/// One-shot boot wiring: tell sched how to broadcast epoll wakes
/// without taking a fs dependency.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn install_epoll_broadcast() {
    sched::live::set_epoll_broadcast_hook(broadcast_wake_all_epolls);
    sched::live::set_epoll_gen_bump_hook(bump_global_epoll_gen);
}
static NEXT_EPOLL_ID: AtomicU32 = AtomicU32::new(0);
/// Monotonic per-epitem subscription id source (see `EpollEntry::sub_id`).
pub(super) static NEXT_SUB_ID: AtomicU32 = AtomicU32::new(1);

/// `make_epoll_inode()` — a CharDev pseudo-inode; registered in the global
/// table so epoll_ctl/wait reach its state by id. # C: O(1)
pub fn make_epoll_inode() -> InodeRef {
    let id = NEXT_EPOLL_ID.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(EpollData {
        id,
        entries: Spinlock::new(Vec::new()),
        #[cfg(target_os = "oxide-kernel")]
        waiters: Arc::new(sched::live::WaitList::new()),
    });
    {
        let mut g = EPOLLS.lock();
        if g.len() <= id as usize { g.resize_with(id as usize + 1, || Arc::clone(&data)); }
        else { g[id as usize] = Arc::clone(&data); }
    }
    InodeBuilder::new(EPOLL_INO_BASE | (id as Ino & EPOLL_INO_MASK),
        mk_mode(FileType::CharDev, 0), default_inode_ops(), Arc::new(EpollFileOps))
        .private(data)
        .build()
}

/// `i_fop` for an epoll inode. # C: O(1)
struct EpollFileOps;
impl FileOps for EpollFileOps {
    fn read(&self, _inode: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Einval) }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
    /// A nested epoll fd is POLLIN-readable iff one of its entries WOULD fire
    /// (mirrors scan_once, read-only). Without this the default always-ready
    /// poll made any PARENT epoll watching this one (e.g. Go's netpoller over
    /// an fsnotify watcher epoll) spin in epoll_pwait forever. # C: O(N_entries)
    fn poll(&self, inode: &Inode) -> u32 {
        let d = match inode.private::<EpollData>() { Some(d) => d, None => return 0 };
        let list = d.entries.lock();
        for e in list.iter() {
            let inode = match e.inode.as_ref().and_then(|w| w.upgrade()) {
                Some(i) => i, None => continue,
            };
            let ready = inode.poll() & e.events;
            let fires = if e.events & EPOLLET != 0 {
                (ready & !e.et_seen) != 0
            } else {
                ready != 0
            };
            if fires { return vfs::POLL_IN; }
        }
        0
    }
}

/// F181: EpollData is the wake-callback recipient registered by
/// per-fd subscribers. `notify` wakes its WaitList directly —
/// no fan-out, no global broadcast.
#[cfg(target_os = "oxide-kernel")]
impl vfs::EpollNotify for EpollData {
    fn notify(&self) { self.waiters.wake_all(); }
}

/// # C: O(1)
pub(super) fn epoll_inode_of(file: &alloc::sync::Arc<vfs::File>) -> Option<Arc<EpollData>> {
    let ino = file.inode().ino();
    if (ino & 0xFF00_0000) != EPOLL_INO_BASE { return None; }
    let id = (ino & EPOLL_INO_MASK) as usize;
    EPOLLS.lock().get(id).cloned()
}
