// Linux-style epoll interest and ready lists. Each EpItem owns one
// source callback; callbacks queue that item, while epoll_wait drains
// the ready list and requeues level-triggered items that remain ready.





use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{File, FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, default_inode_ops, mk_mode};

#[path = "epoll/scan.rs"]
mod scan;
#[path = "epoll/syscalls.rs"]
mod syscalls;
pub use syscalls::{sys_epoll_create, sys_epoll_create1, sys_epoll_ctl, sys_epoll_pwait, sys_epoll_pwait2, sys_epoll_wait};

mod ids {
    use vfs::Ino;
    pub(crate) const INO_BASE: Ino = 0x7400_0000;
    pub(crate) const INO_MASK: Ino = 0x00FF_FFFF;
}

// Park / wake plumbing lives in `sched::live` so net/IPC layers
// (which don't depend on `fs`) can trigger epoll wakeups without a
// circular crate edge. See `sched::live::EPOLL_GLOBAL_WAIT` and
// `sched::live::notify_epoll_waiters`.

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

pub struct EpItem {
    pub fd: i32,
    /// Unique per-epitem subscription id (Linux registers a wait-queue callback
    /// per epitem, NOT per epoll instance). Keying the inode's `PollSubscribers`
    /// on this — not `ep.id` — is what lets ONE epoll watch several fds that
    /// share a `PollSubscribers` source without one ADD replacing another's
    /// registration, and lets a `DEL` of one such fd not orphan the others'
    /// wake (the missing-wake that stalled socket-activated userdbd).
    pub sub_id: u32,
    /// Watched open file description captured at ADD. Linux epoll keys an
    /// interest to the file description, not to a later fd-number lookup in the
    /// caller's table; fd reuse after ADD must not retarget the interest.
    pub file: Weak<File>,
    pub poll_source: Option<Arc<vfs::PollSubscribers>>,
    pub state: Spinlock<EpItemState, TaskListClass>,
    pub queued: AtomicBool,
    /// `debug-displaystack` records only interests created by Mutter.  The
    /// owner is captured at ADD time because a source callback runs in the
    /// publisher's task, not the epoll waiter's task.
    #[cfg(all(target_os = "oxide-kernel", feature = "debug-displaystack"))]
    display_owner: bool,
    ep: alloc::sync::Weak<EpollData>,
    callback: Arc<EpItemNotify>,
}

pub struct EpItemState {
    pub events: u32,
    pub data:   u64,
    pub active: bool,
    pub armed:  bool,
}

struct EpItemNotify { item: alloc::sync::Weak<EpItem> }

impl vfs::EpollNotify for EpItemNotify {
    fn notify(&self) {
        if let Some(item) = self.item.upgrade() {
            #[cfg(feature = "debug-displaystack")]
            {
                #[cfg(target_os = "oxide-kernel")]
                if item.display_owner {
                    klog::write_raw(b"[EP-NOTIFY fd=");
                    klog::write_dec_u64(item.fd as u64);
                    if let Some(file) = item.file.upgrade() {
                        klog::write_raw(b" ino=");
                        klog::write_hex_u64(file.inode().ino());
                    }
                    klog::write_raw(b"]\n");
                }
            }
            EpItem::queue(&item, true);
        }
    }
}

impl vfs::FileEpollLink for EpItemNotify {
    fn release(&self) {
        if let Some(item) = self.item.upgrade() { EpItem::detach(&item); }
    }
}

impl EpItem {
    /// Allocate one interest object and its source-specific callback. # C: O(1)
    pub(super) fn new(ep: &Arc<EpollData>, fd: i32, sub_id: u32, events: u32, data: u64, file: Arc<File>, poll_source: Option<Arc<vfs::PollSubscribers>>) -> Arc<Self> {
        let weak_ep = Arc::downgrade(ep);
        #[cfg(all(target_os = "oxide-kernel", feature = "debug-displaystack"))]
        // SAFETY: current task owns its exe_path mutation; this scheduler
        // context snapshots the immutable path solely for debug filtering.
        let display_owner = sched::live::current()
            .and_then(|task| unsafe { (*task.exe_path.get()).as_ref().map(|path| {
                path.contains("gnome-shell") || path.contains("mutter")
            }) })
            .unwrap_or(false);
        Arc::new_cyclic(|item| Self {
            fd, sub_id, file: Arc::downgrade(&file), poll_source,
            state: Spinlock::new(EpItemState { events, data, active: true, armed: true }),
            queued: AtomicBool::new(false),
            #[cfg(all(target_os = "oxide-kernel", feature = "debug-displaystack"))]
            display_owner,
            ep: weak_ep,
            callback: Arc::new(EpItemNotify { item: item.clone() }),
        })
    }

    /// Weak callback registered under this epitem's subscription id. # C: O(1)
    pub(super) fn callback(&self) -> alloc::sync::Weak<dyn vfs::EpollNotify> {
        Arc::downgrade(&(self.callback.clone() as Arc<dyn vfs::EpollNotify>))
    }

    /// Weak backlink registered on the watched open file description. # C: O(1)
    pub(super) fn file_link(&self) -> alloc::sync::Weak<dyn vfs::FileEpollLink> {
        Arc::downgrade(&(self.callback.clone() as Arc<dyn vfs::FileEpollLink>))
    }

    /// True when `file` is this interest's original open description. # C: O(1)
    pub(super) fn file_is(&self, file: &Arc<File>) -> bool {
        Weak::ptr_eq(&self.file, &Arc::downgrade(file))
    }

    /// Effective Linux readiness, including unrequested ERR/HUP. # C: backend
    pub(super) fn ready(&self, events: u32) -> u32 {
        let Some(file) = self.file.upgrade() else { return 0; };
        let raw = file.poll();
        (raw & events) | (raw & (vfs::POLL_ERR | vfs::POLL_HUP))
    }

    /// Put this epitem on its epoll ready list at most once. # C: O(1)
    pub(super) fn queue(item: &Arc<Self>, wake: bool) {
        let state = item.state.lock();
        if !state.active || !state.armed { return; }
        if item.queued.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
        let Some(ep) = item.ep.upgrade() else { item.queued.store(false, Ordering::Release); return; };
        ep.ready.lock().push_back(Arc::clone(item));
        drop(state);
        if wake {
            ep.poll_subs.notify_mask(vfs::POLL_IN);
            #[cfg(target_os = "oxide-kernel")]
            ep.waiters.wake_all();
        }
    }


    /// Idempotently unlink an interest from source, watched file, and epoll
    /// lists. Used by DEL, epoll release, and watched-file final fput.
    /// # C: O(N_entries + N_ready + N_file_links)
    pub(super) fn detach(item: &Arc<Self>) {
        {
            let mut state = item.state.lock();
            if !state.active { return; }
            state.active = false;
            state.armed = false;
        }
        if let Some(subs) = item.poll_source.as_ref() { subs.unsubscribe(item.sub_id); }
        if let Some(file) = item.file.upgrade() { file.epoll_unlink(item.sub_id); }
        if let Some(ep) = item.ep.upgrade() {
            ep.entries.lock().retain(|entry| !Arc::ptr_eq(entry, item));
            ep.ready.lock().retain(|entry| !Arc::ptr_eq(entry, item));
        }
        item.queued.store(false, Ordering::Release);
    }
}

/// EPOLLET — edge-triggered (Linux `EPOLLET` = 1<<31).
pub(super) const EPOLLET: u32 = 0x8000_0000;
pub(super) const EPOLLONESHOT: u32 = 0x4000_0000;
pub(super) const EPOLLWAKEUP: u32 = 0x2000_0000;
pub(super) const EPOLLEXCLUSIVE: u32 = 0x1000_0000;

/// Per-inode epoll state (Linux `i_private`).
pub struct EpollData {
    pub id:      u32,
    pub entries: Spinlock<Vec<Arc<EpItem>>, TaskListClass>,
    pub ready:   Spinlock<VecDeque<Arc<EpItem>>, TaskListClass>,
    poll_subs:   Arc<vfs::PollSubscribers>,
    /// F181: per-EpollData WaitList (Arc'd so subscribers can hold
    /// Weak). epoll_wait parks here; F181-aware event sites wake
    /// only the EpollData that subscribed via `epoll_ctl(ADD)`.
    /// Kernel-only — hosted tests don't run the scheduler.
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: Arc<sched::live::WaitList>,
}

impl EpollData {
    /// Queue currently-ready level interests after a keyless/global rescan. ET
    /// entries are excluded because only their own source callback creates a
    /// post-ADD edge. # C: O(N_entries)
    pub(super) fn rescan_levels(&self) {
        let entries = self.entries.lock().clone();
        for item in entries {
            let state = item.state.lock();
            let queue = state.active && state.armed
                && state.events & EPOLLET == 0 && item.ready(state.events) != 0;
            drop(state);
            if queue { EpItem::queue(&item, false); }
        }
    }

    /// Earliest monotonic deadline at which a timer-backed interest can become
    /// ready without a source callback. # C: O(N_entries)
    pub(super) fn next_poll_deadline(&self) -> Option<u64> {
        self.entries.lock().iter().filter_map(|item| {
            let state = item.state.lock();
            if !state.active || !state.armed { return None; }
            item.file.upgrade().and_then(|file| file.poll_deadline_ns())
        }).min()
    }

    /// Materialize timer expiry as a ready-list edge. This is the timer-backed
    /// equivalent of a source callback and therefore includes EPOLLET items.
    /// # C: O(N_entries)
    pub(super) fn queue_expired_deadlines(&self, now_ns: u64) {
        let entries = self.entries.lock().clone();
        for item in entries {
            let state = item.state.lock();
            let expired = state.active && state.armed
                && item.file.upgrade().and_then(|file| file.poll_deadline_ns()).is_some_and(|d| d <= now_ns)
                && item.ready(state.events) != 0;
            drop(state);
            if expired { EpItem::queue(&item, false); }
        }
    }

    #[cfg(target_os = "oxide-kernel")]
    /// Install the current task on the wait list while holding the ready lock.
    /// # Safety: caller is current in process context and yields immediately on true.
    /// # C: O(1)
    /// # Lk: EpollData.ready then WaitList.waiters
    pub(super) unsafe fn prepare_park(&self, observed_global: u64, deadline_ns: u64) -> bool {
        let ready = self.ready.lock();
        if !ready.is_empty() || GLOBAL_EPOLL_GEN.load(Ordering::Acquire) != observed_global { return false; }
        // SAFETY: caller is current in process context; ready lock serializes callback/global wake against park preparation.
        unsafe { self.waiters.park_with_deadline(deadline_ns); }
        drop(ready);
        true
    }

    #[cfg(target_os = "oxide-kernel")]
    fn wake_rescan(&self) {
        let ready = self.ready.lock();
        self.waiters.wake_all();
        drop(ready);
    }
}

static EPOLLS: Spinlock<Vec<Option<Arc<EpollData>>>, TaskListClass>
    = Spinlock::new(Vec::new());

/// F181: broadcast wake registered with sched at boot via
/// `install_epoll_broadcast`. Walks every live EpollData and
/// wakes its per-instance waitlist. Kernel-only — hosted tests
/// don't run epoll_wait.
/// # C: O(N_epoll_instances)
/// Diagnostic generation for global wake/rescan requests. This is deliberately
/// not part of EPOLLET edge identity: a keyless wake says only that epoll
/// instances should rescan, not that every watched file became ready again.
/// Real edge-producing objects must notify their own `PollSubscribers`.
pub static GLOBAL_EPOLL_GEN: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "oxide-kernel")]
pub fn broadcast_wake_all_epolls() {
    GLOBAL_EPOLL_GEN.fetch_add(1, Ordering::AcqRel);
    let snapshot: Vec<Arc<EpollData>> = EPOLLS.lock().iter().filter_map(|e| e.as_ref().cloned()).collect();
    for ep in snapshot { ep.wake_rescan(); }
}

/// Bump only the global rescan sequence without manufacturing an epitem edge.
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
/// Monotonic per-epitem subscription id source (see `EpItem::sub_id`).
pub(super) static NEXT_SUB_ID: AtomicU32 = AtomicU32::new(1);

/// `make_epoll_inode()` — a CharDev pseudo-inode; registered in the global
/// table so epoll_ctl/wait reach its state by id. # C: O(1)
pub fn make_epoll_inode() -> InodeRef {
    let id = NEXT_EPOLL_ID.fetch_add(1, Ordering::Relaxed);
    let poll_subs = Arc::new(vfs::PollSubscribers::new());
    let data = Arc::new(EpollData {
        id,
        entries: Spinlock::new(Vec::new()),
        ready: Spinlock::new(VecDeque::new()),
        poll_subs: Arc::clone(&poll_subs),
        #[cfg(target_os = "oxide-kernel")]
        waiters: Arc::new(sched::live::WaitList::new()),
    });
    {
        let mut g = EPOLLS.lock();
        if g.len() <= id as usize { g.resize_with(id as usize + 1, || None); }
        g[id as usize] = Some(Arc::clone(&data));
    }
    InodeBuilder::new(ids::INO_BASE | (id as Ino & ids::INO_MASK),
        mk_mode(FileType::CharDev, 0), default_inode_ops(), Arc::new(EpollFileOps))
        .poll_subs_arc(poll_subs)
        .private(data)
        .build()
}

/// `i_fop` for an epoll inode. # C: O(1)
struct EpollFileOps;
impl FileOps for EpollFileOps {
    fn read(&self, _inode: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Einval) }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
    /// Linux `eventpoll_release_file`: closing an epoll fd removes every epitem,
    /// unregisters callbacks from watched wait queues, and drops the pinned file
    /// descriptions. # C: O(N_entries)
    fn on_release_file(&self, file: &File) {
        let Some(ep) = epoll_data_of_inode(file.inode()) else { return; };
        let drained: Vec<Arc<EpItem>> = {
            let mut list = ep.entries.lock();
            list.drain(..).collect()
        };
        for e in drained.iter() { EpItem::detach(e); }
        {
            let mut g = EPOLLS.lock();
            if let Some(slot) = g.get_mut(ep.id as usize) { *slot = None; }
        }
        #[cfg(target_os = "oxide-kernel")]
        ep.waiters.wake_all();
        drop(drained);
    }
    /// A nested epoll fd is readable while its ready list contains an active,
    /// currently-ready item. # C: O(N_ready)
    fn poll(&self, inode: &Inode) -> u32 {
        let d = match inode.private::<EpollData>() { Some(d) => d, None => return 0 };
        let ready = d.ready.lock().clone();
        for item in ready {
            let state = item.state.lock();
            if state.active && state.armed { return vfs::POLL_IN; }
        }
        0
    }
}

/// # C: O(1)
pub(super) fn epoll_inode_of(file: &alloc::sync::Arc<vfs::File>) -> Option<Arc<EpollData>> {
    epoll_data_of_inode(file.inode())
}

fn epoll_data_of_inode(inode: &vfs::InodeRef) -> Option<Arc<EpollData>> {
    let ino = inode.ino();
    if (ino & !ids::INO_MASK) != ids::INO_BASE { return None; }
    let id = (ino & ids::INO_MASK) as usize;
    EPOLLS.lock().get(id).and_then(|e| e.as_ref().cloned())
}
