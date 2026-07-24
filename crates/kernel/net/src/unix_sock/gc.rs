use alloc::{collections::BTreeMap, sync::{Arc, Weak}, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use sync::{SocketTable as GcLockClass, Spinlock};
use vfs;

static GC: Spinlock<GcState, GcLockClass> = Spinlock::new(GcState { next: 1, nodes: Vec::new(), batches: Vec::new(), links: Vec::new() });
static INFLIGHT: AtomicUsize = AtomicUsize::new(0);
static HOOK_SET: AtomicBool = AtomicBool::new(false);
const COLLECT_IDLE: u8 = 0;
const COLLECT_RUNNING: u8 = 1;
const COLLECT_PENDING: u8 = 2;
static COLLECT_STATE: AtomicU8 = AtomicU8::new(COLLECT_IDLE);

struct GcState {
    next: u64,
    nodes: Vec<Weak<GcNodeInner>>,
    batches: Vec<Weak<GcBatch>>,
    links: Vec<Weak<GcLinkInner>>,
}

struct GcNodeInner {
    id: u64,
    file: Spinlock<Option<Weak<vfs::File>>, GcLockClass>,
    pins: AtomicUsize,
}

/// Stable identity of one AF_UNIX receive queue.
#[derive(Clone)]
pub struct GcNode(Arc<GcNodeInner>);

/// Temporary root used while a listener owns an unaccepted endpoint.
pub struct GcPin(GcNode);

struct GcLinkInner { from: u64, to: u64 }

/// Reachability edge owned by a kernel AF_UNIX queue.
pub struct GcLink { _inner: Arc<GcLinkInner> }

struct GcBatch {
    receiver: AtomicU64,
    targets: Vec<Option<u64>>,
    edges: usize,
    files: Spinlock<Vec<Arc<vfs::File>>, GcLockClass>,
    registered: AtomicBool,
}

/// One canonical SCM_RIGHTS control-message batch.
pub struct GcRights(Arc<GcBatch>);

/// Collect after a receive-side file transfer has dropped its temporary roots.
pub struct GcTransferGuard;

impl GcNode {
    /// Allocate one stable receive-queue identity. # C: O(1)
    pub fn new() -> Self {
        let mut gc = GC.lock();
        let id = gc.next;
        gc.next = gc.next.wrapping_add(1).max(1);
        let node = Arc::new(GcNodeInner { id, file: Spinlock::new(None), pins: AtomicUsize::new(0) });
        gc.nodes.push(Arc::downgrade(&node));
        Self(node)
    }

    /// Keep this receiver reachable across a state transition. # C: O(1)
    pub fn pin(&self) -> GcPin {
        self.0.pins.fetch_add(1, Ordering::AcqRel);
        GcPin(self.clone())
    }

    /// Numeric identity for diagnostics and deterministic tests. # C: O(1)
    pub fn id(&self) -> u64 { self.0.id }

    #[cfg(test)]
    pub(crate) fn is_bound_to(&self, file: &Arc<vfs::File>) -> bool {
        self.0.file.lock().as_ref().and_then(Weak::upgrade)
            .is_some_and(|bound| Arc::ptr_eq(&bound, file))
    }

    /// Represent kernel ownership of another receive queue. # C: O(1)
    pub fn link(&self, target: &GcNode) -> GcLink {
        let link = Arc::new(GcLinkInner { from: self.id(), to: target.id() });
        GC.lock().links.push(Arc::downgrade(&link));
        GcLink { _inner: link }
    }
}

impl Drop for GcPin {
    fn drop(&mut self) { self.0.0.pins.fetch_sub(1, Ordering::AcqRel); }
}

impl GcRights {
    /// Build a batch whose files are not AF_UNIX graph edges. # C: O(files)
    pub fn from_files(files: Vec<Arc<vfs::File>>) -> Self {
        let targets = (0..files.len()).map(|_| None).collect();
        Self::new_inner(files, targets)
    }

    /// Build one aligned file/AF_UNIX-target batch. # C: O(files)
    pub fn new(files: Vec<Arc<vfs::File>>, targets: Vec<Option<GcNode>>) -> Result<Self, ()> {
        if files.len() != targets.len() { return Err(()); }
        Ok(Self::new_inner(files, targets.into_iter().map(|n| n.map(|n| n.id())).collect()))
    }

    fn new_inner(files: Vec<Arc<vfs::File>>, targets: Vec<Option<u64>>) -> Self {
        let edges = targets.iter().filter(|target| target.is_some()).count();
        Self(Arc::new(GcBatch {
            receiver: AtomicU64::new(0), targets, edges, files: Spinlock::new(files),
            registered: AtomicBool::new(false),
        }))
    }

    /// Register this batch at exactly one receive queue. # C: O(1)
    pub(crate) fn register(&self, receiver: &GcNode) {
        if self.0.registered.swap(true, Ordering::AcqRel) { return; }
        self.0.receiver.store(receiver.id(), Ordering::Release);
        if self.0.edges == 0 || self.0.files.lock().is_empty() { return; }
        INFLIGHT.fetch_add(self.0.edges, Ordering::AcqRel);
        GC.lock().batches.push(Arc::downgrade(&self.0));
    }

    /// Move every file out of this batch as one unit. # C: O(1)
    pub fn take_files(&self) -> Vec<Arc<vfs::File>> {
        let _gc = GC.lock();
        let files = core::mem::take(&mut *self.0.files.lock());
        if self.0.registered.load(Ordering::Acquire) && !files.is_empty() {
            INFLIGHT.fetch_sub(self.0.edges, Ordering::AcqRel);
        }
        files
    }

    /// Clone file references without consuming this queued rights batch. # C: O(files)
    pub fn clone_files(&self) -> Vec<Arc<vfs::File>> { self.0.files.lock().clone() }

    /// Whether this batch has already been consumed or collected. # C: O(1)
    pub fn is_empty(&self) -> bool { self.0.files.lock().is_empty() }

    /// Number of descriptors still held by this batch. # C: O(1)
    pub fn len(&self) -> usize { self.0.files.lock().len() }
}

impl Drop for GcBatch {
    fn drop(&mut self) {
        let n = self.files.lock().len();
        if self.registered.load(Ordering::Acquire) && n != 0 && self.edges != 0 { INFLIGHT.fetch_sub(self.edges, Ordering::AcqRel); }
    }
}

/// Bind a socket open-file description to its receive queue and install GC. # C: O(1)
pub fn register_file(file: &Arc<vfs::File>, receiver: &GcNode) {
    *receiver.0.file.lock() = Some(Arc::downgrade(file));
    if HOOK_SET.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        vfs::set_file_ref_drop_hook(collect);
    }
}

/// Bind an AF_UNIX socket file to the receiver in its current socket kind. # C: O(1)
// Operates on `crate::sock::InetSocket`; shares the `sock` module's cfg gate so a
// plain host build (no `hosted`/`test`, not the kernel target) still compiles.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn bind_file(file: &Arc<vfs::File>, sock: &crate::sock::InetSocket) -> bool {
    use crate::sock::SockKind;
    let receiver = match &*sock.kind.lock() {
        SockKind::UnixUnbound(pair, end) => Some(pair.gc_node(*end)),
        SockKind::Unix(pair, end) => Some(pair.gc_node(*end)),
        SockKind::UnixMsgPair(pair, end) => Some(pair.gc_node(*end)),
        SockKind::UnixDgram(queue) => Some(queue.gc_node()),
        SockKind::UnixListener(listener) => Some(listener.gc_node()),
        _ => None,
    };
    if let Some(receiver) = receiver { register_file(file, &receiver); true } else { false }
}

/// Classify each passed file against the canonical AF_UNIX file bindings. # C: O(files * sockets)
pub fn classify_files(files: Vec<Arc<vfs::File>>) -> GcRights {
    let bindings: Vec<(usize, GcNode)> = {
        let gc = GC.lock();
        gc.nodes.iter().filter_map(Weak::upgrade).filter_map(|node| {
            let ptr = node.file.lock().as_ref().map(|file| file.as_ptr() as usize)?;
            Some((ptr, GcNode(node)))
        }).collect()
    };
    let targets: Vec<Option<u64>> = files.iter().map(|file| {
        let ptr = Arc::as_ptr(file) as usize;
        let bound = bindings.iter().find(|(bound, _)| *bound == ptr).map(|(_, node)| node.id());
        #[cfg(target_os = "oxide-kernel")]
        let bound = bound.or_else(|| {
            let socket = file.inode().i_private().clone().downcast::<crate::sock::InetSocket>().ok()?;
            (socket.family.load(Ordering::Acquire) == crate::sock::AF_UNIX).then_some(0)
        });
        bound
    }).collect();
    GcRights::new_inner(files, targets)
}

/// Start a receive-side transfer scope. Declare before the received files. # C: O(1)
pub fn transfer_guard() -> GcTransferGuard { GcTransferGuard }

impl Drop for GcTransferGuard {
    fn drop(&mut self) { collect(); }
}

/// Run one serialized AF_UNIX SCM_RIGHTS collection pass. # C: O(nodes + rights edges squared)
pub fn collect() {
    // One state word linearizes ownership and nested requests; the no-op RMW validates stale PENDING loads.
    loop {
        let state = COLLECT_STATE.load(Ordering::Acquire);
        #[cfg(test)]
        super::gc_test_support::pause_after_observing_running(state);
        match state {
            COLLECT_IDLE => {
                if COLLECT_STATE.compare_exchange(COLLECT_IDLE, COLLECT_RUNNING,
                    Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    #[cfg(test)]
                    super::gc_test_support::note_idle_acquire();
                    break;
                }
            }
            COLLECT_RUNNING => {
                if COLLECT_STATE.compare_exchange(COLLECT_RUNNING, COLLECT_PENDING,
                    Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    #[cfg(test)]
                    super::gc_test_support::note_pending_request();
                    return;
                }
            }
            COLLECT_PENDING => {
                if COLLECT_STATE.compare_exchange(COLLECT_PENDING, COLLECT_PENDING,
                    Ordering::AcqRel, Ordering::Acquire).is_ok() { return; }
            }
            _ => return,
        }
    }
    collect_owned();
}

fn collect_owned() {
    loop {
        collect_once();
        #[cfg(test)]
        super::gc_test_support::pause_after_pass();
        if COLLECT_STATE.compare_exchange(COLLECT_RUNNING, COLLECT_IDLE,
            Ordering::AcqRel, Ordering::Acquire).is_ok() { return; }
        if COLLECT_STATE.compare_exchange(COLLECT_PENDING, COLLECT_RUNNING,
            Ordering::AcqRel, Ordering::Acquire).is_ok() { continue; }
    }
}

#[cfg(test)]
/// Attempt to reserve collector ownership for a hosted schedule. # C: O(1)
pub(crate) fn test_try_reserve_collection() -> bool {
    COLLECT_STATE.compare_exchange(COLLECT_IDLE, COLLECT_RUNNING,
        Ordering::AcqRel, Ordering::Acquire).is_ok()
}

#[cfg(test)]
/// Run a collector whose ownership was reserved by test support. # C: O(collection)
pub(crate) fn test_collect_reserved() {
    collect_owned();
}

#[cfg(test)]
/// Recover collector ownership after a hosted owner unwinds. # C: O(collection)
pub(crate) fn test_recover_collection_after_unwind() {
    COLLECT_STATE.store(COLLECT_IDLE, Ordering::Release);
    collect();
}

fn collect_once() {
    if INFLIGHT.load(Ordering::Acquire) == 0 { return; }
    let mut drop_later: Vec<Vec<Arc<vfs::File>>> = Vec::new();
    {
        let mut gc = GC.lock();
        let nodes: Vec<Arc<GcNodeInner>> = gc.nodes.iter().filter_map(Weak::upgrade).collect();
        let batches: Vec<Arc<GcBatch>> = gc.batches.iter().filter_map(Weak::upgrade)
            .filter(|b| !b.files.lock().is_empty()).collect();
        let links: Vec<Arc<GcLinkInner>> = gc.links.iter().filter_map(Weak::upgrade).collect();
        gc.nodes.retain(|n| n.strong_count() != 0);
        gc.batches.retain(|b| b.strong_count() != 0);
        gc.links.retain(|link| link.strong_count() != 0);

        let mut multiplicity: BTreeMap<usize, usize> = BTreeMap::new();
        for batch in &batches {
            let files = batch.files.lock();
            for (i, file) in files.iter().enumerate() {
                if batch.targets.get(i).and_then(|t| *t).is_some() {
                    *multiplicity.entry(Arc::as_ptr(file) as usize).or_insert(0) += 1;
                }
            }
        }

        let bindings: Vec<(u64, usize)> = nodes.iter().filter_map(|node| {
            let file = node.file.lock();
            let file = file.as_ref()?;
            (file.strong_count() != 0).then_some((node.id, file.as_ptr() as usize))
        }).collect();
        let mut marked: BTreeMap<u64, ()> = BTreeMap::new();
        for node in &nodes {
            if node.pins.load(Ordering::Acquire) != 0 { marked.insert(node.id, ()); continue; }
            let file = node.file.lock();
            let Some(file) = file.as_ref() else { continue; };
            let ptr = file.as_ptr() as usize;
            let queued = multiplicity.get(&ptr).copied().unwrap_or(0);
            if file.strong_count() > queued {
                for (id, bound) in &bindings { if *bound == ptr { marked.insert(*id, ()); } }
            }
        }

        loop {
            let mut changed = false;
            for link in &links {
                if marked.contains_key(&link.from) && marked.insert(link.to, ()).is_none() { changed = true; }
            }
            for batch in &batches {
                let receiver = batch.receiver.load(Ordering::Acquire);
                if !marked.contains_key(&receiver) { continue; }
                let files = batch.files.lock();
                for (target, file) in batch.targets.iter().zip(files.iter()) {
                    if target.is_none() { continue; }
                    let ptr = Arc::as_ptr(file) as usize;
                    for (id, bound) in &bindings {
                        if *bound == ptr && marked.insert(*id, ()).is_none() { changed = true; }
                    }
                }
            }
            if !changed { break; }
        }

        for batch in batches {
            let receiver = batch.receiver.load(Ordering::Acquire);
            let has_edge = batch.targets.iter().any(Option::is_some);
            if has_edge && !marked.contains_key(&receiver) {
                let files = core::mem::take(&mut *batch.files.lock());
                if !files.is_empty() {
                    INFLIGHT.fetch_sub(batch.edges, Ordering::AcqRel);
                    drop_later.push(files);
                }
            }
        }
    }
    drop(drop_later);
}

/// Current queued descriptor multiplicity. # C: O(1)
pub fn inflight_rights() -> usize { INFLIGHT.load(Ordering::Acquire) }
