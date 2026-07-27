// The FUSE channel — `struct fuse_conn` (`fs/fuse/fuse_i.h`). One `FuseConn` is
// shared by the `/dev/fuse` open File (the daemon's channel) and the mounted
// superblock. It is the request/reply broker:
//
//   * a KERNEL VFS op calls [`FuseConn::new_request`] → the encoded request is
//     pushed to the `pending` FIFO and a `RequestSlot` is filed in `slots` by
//     its `unique` id; the daemon reading `/dev/fuse` is woken.
//   * the daemon's `read(/dev/fuse)` dequeues the next pending message
//     ([`FuseConn::dequeue`]); its `write(/dev/fuse)` submits a reply
//     ([`FuseConn::submit_reply`]) which matches the slot by `unique`, stores the
//     reply body, marks the slot done, and wakes the blocked caller.
//   * the blocked caller (in [`FuseConn::wait_reply`], live-scheduler only) parks
//     on `reply_wait` until its slot completes, aborts, or a signal fires.
//
// A daemon close aborts the connection ([`FuseConn::abort`]): every pending slot
// is completed with `-ENOTCONN` and all waiters woken (Linux `fuse_abort_conn`).

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use alloc::sync::Weak;
use sync::{Spinlock, Tty as FuseClass};
use vfs::{Inode, InodeRef, PollSubscribers};

use super::proto;
use super::FUSE_WIRE_ENOTCONN;

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;

/// Hosted-test stand-in: the live `WaitList` only exists under the scheduler.
/// Hosted unit tests exercise the codec + queue/slot state machine and NEVER the
/// park/schedule block, so these bodies are unreachable there (mirrors the
/// `fs::pipe` hosted stand-in). # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) struct WaitList;
#[cfg(not(target_os = "oxide-kernel"))]
impl WaitList {
    pub(crate) const fn new() -> Self { Self }
    pub(crate) fn wake_all(&self) {}
    pub(crate) fn wake_one(&self) {}
    /// # SAFETY: never invoked hosted; see type doc.
    pub(crate) unsafe fn park(&self) { unreachable!("park under hosted") }
}

/// Negotiated INIT parameters (Linux `fuse_conn` version/flags/max_write).
/// `done` flips true when the daemon's `FUSE_INIT` reply is decoded. # C: O(1)
#[derive(Clone, Copy, Debug, Default)]
pub struct InitState {
    /// INIT handshake completed (daemon replied with a compatible version).
    pub done: bool,
    /// The daemon rejected our major (incompatible) — mount is unusable.
    pub failed: bool,
    /// Negotiated protocol major (always [`proto::FUSE_KERNEL_VERSION`]).
    pub major: u32,
    /// Negotiated protocol minor (min of ours and the daemon's).
    pub minor: u32,
    /// Feature flags the daemon and kernel both advertised.
    pub flags: u32,
    /// Daemon's `max_write` — the largest write payload it accepts.
    pub max_write: u32,
}

/// One in-flight request awaiting its reply — Linux `struct fuse_req`. Filed in
/// [`FuseConn::slots`] by `unique` from `new_request` until `submit_reply` (or
/// `abort`) completes it. # C: O(1)
/// NO `FR_INTERRUPTED` FLAG / FUSE_INTERRUPT SUPPORT HERE — AND THE REQUEST
/// WAIT DEPENDS ON THAT. Linux `request_wait_answer` (`fs/fuse/dev.c:696-730`)
/// waits in TWO phases: an interruptible one (`dev.c:705`), then — if a signal
/// arrives — it sets `FR_INTERRUPTED`, queues a FUSE_INTERRUPT request to the
/// daemon, and waits again KILLABLY (`dev.c:721`). So an ordinary signal does
/// NOT abandon a FUSE request; only a fatal one does, and the daemon is told.
///
/// This kernel has only the first phase, so any deliverable signal abandons the
/// request outright and the daemon is never notified. If you add
/// FR_INTERRUPTED / FUSE_INTERRUPT, the wait in `request_wait` must grow the
/// second killable phase with it — the ERESTARTSYS return there is correct for
/// both shapes, so nothing else will flag the omission.
pub struct RequestSlot {
    /// `req->in.h.unique` — the id matching a reply to this request.
    pub unique: u64,
    /// `req->in.h.opcode` — retained so the reply decoder knows the op (e.g. a
    /// `FUSE_INIT` reply updates the connection's negotiated params).
    pub opcode: u32,
    /// Completion flag: `submit_reply`/`abort` set it, `wait_reply` polls it.
    pub done: AtomicBool,
    /// Reply's `fuse_out_header.error` — `0` on success, a NEGATIVE errno on a
    /// daemon-reported failure or `-ENOTCONN` on abort. # consumers: wait_reply.
    pub error: AtomicI32,
    /// Reply body (bytes AFTER the 16-byte `fuse_out_header`). # consumers: op decode.
    pub reply: Spinlock<Vec<u8>, FuseClass>,
}

impl RequestSlot {
    fn new(unique: u64, opcode: u32) -> Arc<Self> {
        Arc::new(Self {
            unique, opcode,
            done: AtomicBool::new(false),
            error: AtomicI32::new(0),
            reply: Spinlock::new(Vec::new()),
        })
    }
}

/// `struct fuse_conn` — the shared channel state between `/dev/fuse` and a mount.
pub struct FuseConn {
    /// Monotonic `unique` id source (Linux `fc->reqctr`); starts at 1 (0 is the
    /// "no reply expected" sentinel in the protocol).
    unique_ctr: AtomicU64,
    /// `fc->pending` — encoded kernel→daemon request messages awaiting a
    /// `read(/dev/fuse)`. Each is a full `fuse_in_header`+body byte buffer.
    pending: Spinlock<VecDeque<Vec<u8>>, FuseClass>,
    /// `unique -> RequestSlot` for every request awaiting a reply (Linux
    /// `fc->processing`). A reply with an unknown `unique` is dropped.
    slots: Spinlock<BTreeMap<u64, Arc<RequestSlot>>, FuseClass>,
    /// Tasks blocked in `read(/dev/fuse)` on an empty `pending` queue.
    daemon_wait: WaitList,
    /// Tasks blocked in `wait_reply` for their slot to complete.
    reply_wait: WaitList,
    /// `fc->connected == 0` — the daemon closed the fd; all waiters get
    /// `-ENOTCONN` and every future op fails fast.
    aborted: AtomicBool,
    /// Negotiated INIT state (version/flags/max_write).
    init: Spinlock<InitState, FuseClass>,
    /// The `/dev/fuse` inode's poll subscriber set — notified on every enqueue
    /// (a request became readable) and on abort so an epoll'ing daemon wakes.
    poll_subs: Arc<PollSubscribers>,
    /// `nodeid -> inode` identity map (Linux `fc->inodes` hash). LOOKUP reuses a
    /// live inode for a repeated nodeid so the VFS sees one object per node;
    /// `Weak` so an evicted inode does not pin the entry. # consumers: lookup.
    node_inodes: Spinlock<BTreeMap<u64, Weak<Inode>>, FuseClass>,
}

impl FuseConn {
    /// Build a fresh channel bound to the `/dev/fuse` inode's poll set. # C: O(1)
    pub fn new(poll_subs: Arc<PollSubscribers>) -> Arc<Self> {
        Arc::new(Self {
            unique_ctr: AtomicU64::new(1),
            pending: Spinlock::new(VecDeque::new()),
            slots: Spinlock::new(BTreeMap::new()),
            daemon_wait: WaitList::new(),
            reply_wait: WaitList::new(),
            aborted: AtomicBool::new(false),
            init: Spinlock::new(InitState::default()),
            poll_subs,
            node_inodes: Spinlock::new(BTreeMap::new()),
        })
    }

    /// Reuse the live inode already cached for `nodeid`, if any (Linux
    /// `fuse_iget` hit). # C: O(log N_nodes)
    pub fn cached_inode(&self, nodeid: u64) -> Option<InodeRef> {
        self.node_inodes.lock().get(&nodeid).and_then(Weak::upgrade)
    }

    /// File `inode` under `nodeid` for future lookups to reuse. # C: O(log N_nodes)
    pub fn cache_inode(&self, nodeid: u64, inode: &InodeRef) {
        self.node_inodes.lock().insert(nodeid, Arc::downgrade(inode));
    }

    /// Drop a nodeid mapping (FUSE_FORGET / evict). # C: O(log N_nodes)
    pub fn forget_inode(&self, nodeid: u64) { self.node_inodes.lock().remove(&nodeid); }

    /// Snapshot the negotiated INIT state. # C: O(1)
    pub fn init_state(&self) -> InitState { *self.init.lock() }

    /// `true` once the daemon closed the channel (`fuse_abort_conn`). # C: O(1)
    pub fn is_aborted(&self) -> bool { self.aborted.load(Ordering::Acquire) }

    /// Encode a request (`fuse_in_header` + `body`) for `opcode` on `nodeid`,
    /// file it in `slots`, push it to the daemon's `pending` queue, and wake a
    /// reader. Returns the slot the caller later waits on. The header `uid/gid/
    /// pid` are the daemon-facing caller identity (0 here; the syscall layer may
    /// stamp the real caller). # C: O(log N_inflight)
    pub fn new_request(&self, opcode: u32, nodeid: u64, body: &[u8]) -> Arc<RequestSlot> {
        let unique = self.unique_ctr.fetch_add(1, Ordering::Relaxed);
        let hdr = proto::InHeader {
            len: (proto::FUSE_IN_HEADER_SIZE + body.len()) as u32,
            opcode, unique, nodeid, uid: 0, gid: 0, pid: 0,
        };
        let mut msg = Vec::with_capacity(hdr.len as usize);
        hdr.encode(&mut msg);
        msg.extend_from_slice(body);
        let slot = RequestSlot::new(unique, opcode);
        self.slots.lock().insert(unique, slot.clone());
        self.pending.lock().push_back(msg);
        self.daemon_wait.wake_one();
        self.poll_subs.notify();
        slot
    }

    /// Issue a request and BLOCK for its reply (Linux `fuse_simple_request`) —
    /// the one-shot combinator every synchronous VFS op uses. LIVE-SCHEDULER
    /// ONLY (the wait parks). # C: O(body) + park
    pub fn call(&self, opcode: u32, nodeid: u64, body: &[u8]) -> Result<Vec<u8>, vfs::VfsError> {
        let slot = self.new_request(opcode, nodeid, body);
        self.wait_reply(&slot)
    }

    /// `read(/dev/fuse)` core — copy the next pending request into `buf`. `Ok(0)`
    /// means "no request queued" (the daemon-read wrapper decides to park or
    /// return EAGAIN). `Err(Enodev)` once aborted (Linux `fuse_dev_do_read` on a
    /// dead conn). `Err(Einval)` if `buf` cannot hold the whole message (the
    /// daemon must size its buffer to `max_write + header`). # C: O(msg)
    pub fn dequeue(&self, buf: &mut [u8]) -> Result<usize, vfs::VfsError> {
        if self.is_aborted() { return Err(vfs::VfsError::Enodev); }
        let mut q = self.pending.lock();
        let msg = match q.front() {
            Some(m) => m,
            None => return Ok(0),
        };
        if msg.len() > buf.len() { return Err(vfs::VfsError::Einval); }
        let n = msg.len();
        buf[..n].copy_from_slice(msg);
        q.pop_front();
        Ok(n)
    }

    /// `true` when a request is queued (or the conn aborted) — the `/dev/fuse`
    /// POLLIN predicate. # C: O(1)
    pub fn has_pending(&self) -> bool {
        self.is_aborted() || !self.pending.lock().is_empty()
    }

    /// `write(/dev/fuse)` core — parse a `fuse_out_header` reply, match its
    /// `unique` to a filed slot, store the reply body, complete the slot, and
    /// wake its waiter. An unknown `unique` is DROPPED (Linux ignores a reply to
    /// an already-completed/interrupted request). A `FUSE_INIT` reply also
    /// updates the connection's negotiated params. Returns the number of bytes
    /// consumed (the daemon's whole write). # C: O(log N_inflight)
    pub fn submit_reply(&self, buf: &[u8]) -> Result<usize, vfs::VfsError> {
        let oh = proto::OutHeader::decode(buf).ok_or(vfs::VfsError::Einval)?;
        if (oh.len as usize) < proto::FUSE_OUT_HEADER_SIZE || oh.len as usize > buf.len() {
            return Err(vfs::VfsError::Einval);
        }
        let body = &buf[proto::FUSE_OUT_HEADER_SIZE..oh.len as usize];
        let slot = self.slots.lock().remove(&oh.unique);
        let slot = match slot { Some(s) => s, None => return Ok(buf.len()) };
        if slot.opcode == proto::FUSE_INIT && oh.error == 0 {
            self.apply_init_reply(body);
        }
        *slot.reply.lock() = body.to_vec();
        slot.error.store(oh.error, Ordering::Release);
        slot.done.store(true, Ordering::Release);
        self.reply_wait.wake_all();
        Ok(buf.len())
    }

    /// Decode a `FUSE_INIT` reply body and publish the negotiated version/flags/
    /// max_write. A daemon major other than [`proto::FUSE_KERNEL_VERSION`] marks
    /// the connection `failed` (Linux `fuse_send_init` reply check). # C: O(1)
    fn apply_init_reply(&self, body: &[u8]) {
        let mut st = self.init.lock();
        match proto::InitOut::decode(body) {
            Some(o) if o.major == proto::FUSE_KERNEL_VERSION => {
                st.done = true;
                st.failed = false;
                st.major = o.major;
                st.minor = o.minor.min(proto::FUSE_KERNEL_MINOR_VERSION);
                st.flags = o.flags;
                st.max_write = o.max_write;
            }
            _ => { st.done = true; st.failed = true; }
        }
    }

    /// Queue the mandatory `FUSE_INIT` handshake (nodeid 0). NON-BLOCKING: the
    /// reply is processed asynchronously by `submit_reply` (blocking here would
    /// deadlock a single-threaded daemon still inside the `mount(2)` call). The
    /// negotiated result lands in [`Self::init_state`]. # C: O(1)
    pub fn send_init(&self) {
        let init = proto::InitIn {
            major: proto::FUSE_KERNEL_VERSION,
            minor: proto::FUSE_KERNEL_MINOR_VERSION,
            max_readahead: super::FUSE_MAX_READAHEAD,
            flags: proto::FUSE_ASYNC_READ | proto::FUSE_BIG_WRITES | proto::FUSE_DO_READDIRPLUS,
        };
        let mut body = Vec::with_capacity(proto::FUSE_INIT_IN_SIZE);
        init.encode(&mut body);
        let _ = self.new_request(proto::FUSE_INIT, 0, &body);
    }

    /// Abort the connection (Linux `fuse_abort_conn`) — the daemon closed the
    /// `/dev/fuse` fd. Complete every filed slot with `-ENOTCONN`, drop pending
    /// requests, and wake all waiters (blocked callers + a parked daemon reader +
    /// epoll). Idempotent. # C: O(N_inflight)
    pub fn abort(&self) {
        if self.aborted.swap(true, Ordering::AcqRel) { return; }
        let slots: Vec<Arc<RequestSlot>> = {
            let mut g = self.slots.lock();
            let v: Vec<Arc<RequestSlot>> = g.values().cloned().collect();
            g.clear();
            v
        };
        for s in slots {
            s.error.store(FUSE_WIRE_ENOTCONN, Ordering::Release);
            s.done.store(true, Ordering::Release);
        }
        self.pending.lock().clear();
        self.reply_wait.wake_all();
        self.daemon_wait.wake_all();
        self.poll_subs.notify();
    }

    /// Block the calling task until `slot` completes, the connection aborts, or a
    /// signal is deliverable. Returns the reply body on success, a typed error on
    /// a daemon errno / abort / signal. LIVE-SCHEDULER ONLY — the hosted stand-in
    /// never reaches the park (tests drive `submit_reply` and inspect the slot).
    /// # C: O(body) + park
    pub fn wait_reply(&self, slot: &Arc<RequestSlot>) -> Result<Vec<u8>, vfs::VfsError> {
        loop {
            if slot.done.load(Ordering::Acquire) {
                let err = slot.error.load(Ordering::Acquire);
                if err != 0 { return Err(wire_err_to_vfs(err)); }
                return Ok(slot.reply.lock().clone());
            }
            if self.is_aborted() { return Err(vfs::VfsError::Enotconn); }
            #[cfg(target_os = "oxide-kernel")]
            {
                if sched::live::deliverable_signals_self() != 0 {
                    // Drop the slot so a late reply is ignored (Linux interrupt).
                    self.slots.lock().remove(&slot.unique);
                    // Linux `request_wait_answer` (`fs/fuse/dev.c:705`):
                    // `wait_event_interruptible` -> -ERESTARTSYS.
                    //
                    // GAP: Linux then runs a SECOND, killable phase
                    // (`dev.c:721`) after setting FR_INTERRUPTED and queueing
                    // a FUSE INTERRUPT request, so a non-fatal signal does not
                    // abandon the request outright. This kernel aborts on the
                    // first phase. Tracked in the plan; the return code is
                    // correct either way.
                    return Err(vfs::VfsError::Erestartsys);
                }
                // SAFETY: running task; preempt-off; park marks Sleeping + bumps the Arc before schedule; a reply/abort wake will resume us.
                unsafe { self.reply_wait.park(); }
                // SAFETY: process ctx; runqueue installed; preempt-off; Sleeping so schedule won't re-enqueue until a reply/abort wake fires.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(vfs::VfsError::Eagain);
        }
    }

    /// Park the daemon's `read(/dev/fuse)` when no request is queued (live only).
    /// # C: O(1) + park
    #[cfg(target_os = "oxide-kernel")]
    pub fn park_daemon(&self) {
        // SAFETY: running task; preempt-off; park marks Sleeping + bumps the Arc before schedule; an enqueue/abort wake will resume us.
        unsafe { self.daemon_wait.park(); }
        // SAFETY: process ctx; runqueue installed; preempt-off; Sleeping so schedule won't re-enqueue until an enqueue/abort wake fires.
        unsafe { sched::live::schedule::schedule(); }
    }
}

/// Map a NEGATIVE wire errno (`fuse_out_header.error`) back to a [`vfs::VfsError`]
/// for the VFS caller. Unknown codes collapse to `Eio`. # C: O(1)
fn wire_err_to_vfs(neg: i32) -> vfs::VfsError {
    use vfs::VfsError::*;
    match -neg {
        1 => Eperm, 2 => Enoent, 5 => Eio, 9 => Ebadf, 13 => Eacces, 17 => Eexist,
        20 => Enotdir, 21 => Eisdir, 22 => Einval, 38 => Enosys, 95 => Eopnotsupp,
        107 => Enotconn, _ => Eio,
    }
}
