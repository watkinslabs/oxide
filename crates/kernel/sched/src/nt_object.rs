//! Process-local NT object references and handle lifetime.
//!
//! The table is deliberately separate from Linux's `FdTable`: an NT handle is
//! an opaque process-local reference with an access mask, generation check,
//! and object lifetime independent of POSIX descriptor flags.
extern crate alloc;
#[path = "nt_object/namespace.rs"]
mod namespace;
pub use namespace::{create_event, create_semaphore, directory_entries, directory_path, lookup_directory, lookup_object, make_temporary, object_name, publish_mutant, publish_named_pipe, publish_section, publish_symbolic_link, publish_timer, release_temporary, NamedObjectState};
#[path = "nt_object/mutant.rs"]
mod mutant;
pub use mutant::NtMutant;
#[path = "nt_object/file_share.rs"]
#[allow(dead_code)]
mod file_share;
pub use file_share::NtFileShare;
#[path = "nt_object/file_delete.rs"]
mod file_delete;
pub use file_delete::NtDeleteOnClose;
#[path = "nt_object/timer.rs"]
mod timer;
pub use timer::NtTimer;
#[path = "nt_object/completion.rs"]
mod completion;
pub use completion::{NtCompletionPacket, NtCompletionPort};
#[path = "nt_object/token.rs"]
mod token;
pub use token::{NtToken, NtTokenGroup, NtTokenPrivilege};
#[path = "nt_object/job.rs"]
mod job;
pub use job::{NtJob, NtJobLimits};
#[path = "nt_object/pipe.rs"]
mod pipe;
pub use pipe::{NtPipe, NtPipeConfig, NtPipeEndpoint, NtPipeIo, NtPipeListen, NtPipePeek, NtPipeSide, NtPipeWait};
use alloc::{string::String, sync::Arc};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};
use crate::Task;
use crate::live::WaitList;

const HANDLE_INDEX_BITS: u32 = 16;
const HANDLE_INDEX_MASK: u32 = (1 << HANDLE_INDEX_BITS) - 1;
const FIRST_INDEX: usize = 1;
const INVALID_HANDLE: u32 = u32::MAX;
/// NT kernel object kinds exposed to the native runtime.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NtObjectType {
    Process,
    Thread,
    File,
    Directory,
    Section,
    SymbolicLink,
    Event,
    Semaphore,
    Mutant,
    Timer,
    CompletionPort,
    Token,
    Key,
    Job,
    NamedPipe,
}
/// Stable identity and type of one native object.
pub struct NtObject {
    kind: NtObjectType,
    id: u64,
    event: Option<Arc<NtEvent>>,
    semaphore: Option<Arc<NtSemaphore>>,
    mutant: Option<Arc<NtMutant>>,
    timer: Option<Arc<NtTimer>>,
    completion: Option<Arc<NtCompletionPort>>,
    token: Option<Arc<NtToken>>,
    job: Option<Arc<NtJob>>,
    pipe: Option<Arc<NtPipe>>,
    pipe_endpoint: Option<Arc<NtPipeEndpoint>>,
    file: Option<Arc<vfs::File>>,
    section: Option<Arc<NtSection>>,
    symbolic_link: Option<Arc<NtSymbolicLink>>,
    task: Option<Arc<Task>>,
    #[allow(dead_code)]
    file_share: Option<Arc<NtFileShare>>,
    #[allow(dead_code)]
    delete_on_close: Option<Arc<NtDeleteOnClose>>,
    file_completion: Spinlock<Option<(Arc<NtCompletionPort>, u64)>, TaskListClass>,
}
/// Immutable byte backing for an anonymous NT section. Writable views use the
/// VMM's normal private fault path until shared section-page ownership exists.
pub struct NtSection {
    bytes: Arc<[u8]>,
    size: usize,
    file: Option<Arc<vfs::File>>,
}
/// Target text carried by one NT symbolic-link object. # C: O(1)
pub struct NtSymbolicLink { target: String }
impl NtSymbolicLink {
    /// Construct one immutable symbolic-link target. # C: O(1)
    pub fn new(target: String) -> Arc<Self> { Arc::new(Self { target }) }
    /// Return the link target. # C: O(1)
    pub fn target(&self) -> &str { &self.target }
}
impl NtSection {
    /// Construct a zero-filled section backing. # C: O(size)
    pub fn new(size: usize) -> Option<Arc<Self>> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).ok()?;
        bytes.resize(size, 0);
        Some(Arc::new(Self { bytes: bytes.into(), size, file: None }))
    }
    /// Construct a file-backed section retaining the VFS open description. # C: O(1)
    pub fn from_file(file: Arc<vfs::File>, size: usize) -> Arc<Self> {
        Arc::new(Self { bytes: Arc::from(&[][..]), size, file: Some(file) })
    }
    /// Return the section's byte backing for a VMA. # C: O(1)
    pub fn bytes(&self) -> Arc<[u8]> { self.bytes.clone() }
    /// Return the section extent. # C: O(1)
    pub fn size(&self) -> usize { self.size }
    /// Return the retained file description, if this is file-backed. # C: O(1)
    pub fn file(&self) -> Option<Arc<vfs::File>> { self.file.clone() }
}
impl NtObject {
    /// Create one immutable native object identity. # C: O(1)
    pub fn new(kind: NtObjectType, id: u64) -> Arc<Self> {
        Arc::new(Self { kind, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create an event-backed native object. # C: O(1)
    pub fn new_event(id: u64, manual_reset: bool, initial_state: bool) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Event, id,
            event: Some(Arc::new(NtEvent::new(manual_reset, initial_state))), semaphore: None, mutant: None, timer: None, completion: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a counting semaphore object. # C: O(1)
    pub fn new_semaphore(id: u64, initial: i64, maximum: i64) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Semaphore, id, event: None,
            semaphore: Some(Arc::new(NtSemaphore::new(initial as u32, maximum as u32))), mutant: None, timer: None, completion: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a thread-owned NT mutant. # C: O(1)
    pub fn new_mutant(id: u64, owner: Option<u64>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Mutant, id, event: None, semaphore: None,
            mutant: Some(Arc::new(NtMutant::new(owner))), timer: None, completion: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a waitable NT timer object. # C: O(1)
    pub fn new_timer(id: u64, manual_reset: bool) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Timer, id, event: None, semaphore: None,
            mutant: None, timer: Some(Arc::new(NtTimer::new(manual_reset))), completion: None, token: None, file: None,
            section: None, symbolic_link: None, task: None, job: None, pipe: None, pipe_endpoint: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a file object retaining the canonical VFS open description. # C: O(1)
    pub fn new_file(id: u64, file: Arc<vfs::File>) -> Arc<Self> {
        let delete = NtDeleteOnClose::new(file.as_ref(), false);
        Self::new_file_with_share(id, file, None, delete)
    }
    /// Create a file object retaining its Windows sharing claim. # C: O(1)
    pub fn new_file_with_share(id: u64, file: Arc<vfs::File>, file_share: Option<Arc<NtFileShare>>, delete_on_close: Option<Arc<NtDeleteOnClose>>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::File, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: Some(file), section: None, symbolic_link: None, task: None, file_share, delete_on_close, file_completion: Spinlock::new(None) })
    }
    /// Create an anonymous section object. # C: O(1)
    pub fn new_section(id: u64, section: Arc<NtSection>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Section, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, section: Some(section), symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create one symbolic-link object identity. # C: O(1)
    pub fn new_symbolic_link(id: u64, target: String) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::SymbolicLink, id, event: None, semaphore: None, mutant: None, timer: None,
            completion: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, section: None, symbolic_link: Some(NtSymbolicLink::new(target)),
            task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a process object backed by the canonical scheduler task. # C: O(1)
    pub fn new_process(id: u64, task: Arc<Task>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Process, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, section: None, symbolic_link: None, task: Some(task), file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a thread object backed by the canonical scheduler task. # C: O(1)
    pub fn new_thread(id: u64, task: Arc<Task>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Thread, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, section: None, symbolic_link: None, task: Some(task), file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Return the object's NT type. # C: O(1)
    pub fn kind(&self) -> NtObjectType { self.kind }
    /// Return the subsystem-owned stable identity. # C: O(1)
    pub fn id(&self) -> u64 { self.id }
    /// Return the event primitive carried by an event object. # C: O(1)
    pub fn event(&self) -> Option<Arc<NtEvent>> { self.event.clone() }
    /// Return the semaphore primitive carried by a semaphore object. # C: O(1)
    pub fn semaphore(&self) -> Option<Arc<NtSemaphore>> { self.semaphore.clone() }

    /// Return the thread-owned mutant primitive. # C: O(1)
    pub fn mutant(&self) -> Option<Arc<NtMutant>> { self.mutant.clone() }

    /// Return the timer primitive carried by a timer object. # C: O(1)
    pub fn timer(&self) -> Option<Arc<NtTimer>> { self.timer.clone() }
    pub fn job(&self) -> Option<Arc<NtJob>> { self.job.clone() }
    pub fn pipe(&self) -> Option<Arc<NtPipe>> { self.pipe.clone() }
    pub fn pipe_endpoint(&self) -> Option<Arc<NtPipeEndpoint>> { self.pipe_endpoint.clone() }

    pub fn completion(&self) -> Option<Arc<NtCompletionPort>> { self.completion.clone() }
    pub fn new_token(id: u64, uid: u32, gid: u32) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Token, id, event: None, semaphore: None, mutant: None,
            timer: None, completion: None, token: Some(Arc::new(NtToken::new(uid, gid))), job: None, pipe: None, pipe_endpoint: None, file: None,
            section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    pub fn token(&self) -> Option<Arc<NtToken>> { self.token.clone() }
    pub fn duplicate_token(id: u64, token: Arc<NtToken>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Token, id, event: None, semaphore: None, mutant: None,
            timer: None, completion: None, token: Some(token), job: None, pipe: None, pipe_endpoint: None, file: None, section: None, symbolic_link: None,
            task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }

    /// Return the next timer deadline, or `None` for non-timer objects. # C: O(1)
    pub fn timer_deadline(&self) -> Option<u64> { self.timer.as_ref().map(|timer| timer.due_ns()) }

    /// Test whether this object currently satisfies a wait. # C: O(1)
    pub fn is_signaled(&self) -> bool {
        self.is_signaled_for(0)
    }

    /// Test wait readiness for the calling NT thread. # C: O(1)
    pub fn is_signaled_for(&self, tid: u64) -> bool {
        self.is_signaled_at(tid, 0)
    }

    /// Timer-aware readiness probe. `now_ns == 0` is reserved for callers
    /// that only inspect non-timer objects. # C: O(1)
    pub fn is_signaled_at(&self, tid: u64, now_ns: u64) -> bool {
        self.event.as_ref().map_or_else(|| self.semaphore.as_ref().map_or_else(|| self.mutant.as_ref().map_or_else(|| self.timer.as_ref().map_or(false, |t| now_ns != 0 && t.is_signaled_at(now_ns)), |m| m.is_signaled_for(tid)), |s| s.is_signaled()), |e| e.is_signaled())
    }

    /// Consume one wait signal from this object. # C: O(1)
    pub fn try_wait(&self) -> bool {
        self.try_wait_for(0)
    }

    /// Consume one wait signal for the calling NT thread. # C: O(1)
    pub fn try_wait_for(&self, tid: u64) -> bool {
        self.try_wait_at(tid, 0)
    }

    /// Consume readiness, including a timer due at `now_ns`. # C: O(1)
    pub fn try_wait_at(&self, tid: u64, now_ns: u64) -> bool {
        self.event.as_ref().map_or_else(|| self.semaphore.as_ref().map_or_else(|| self.mutant.as_ref().map_or_else(|| self.timer.as_ref().map_or(false, |t| now_ns != 0 && t.try_wait_at(now_ns)), |m| m.try_acquire(tid)), |s| s.try_wait()), |e| e.try_wait())
    }

    /// Return the canonical VFS open description carried by a file object. # C: O(1)
    pub fn file(&self) -> Option<Arc<vfs::File>> { self.file.clone() }
    pub fn set_file_completion(&self, port: Arc<NtCompletionPort>, key: u64) -> bool {
        if self.kind != NtObjectType::File && self.kind != NtObjectType::NamedPipe { return false; }
        *self.file_completion.lock() = Some((port, key)); true
    }
    pub fn file_completion(&self) -> Option<(Arc<NtCompletionPort>, u64)> { self.file_completion.lock().clone() }

    /// Return shared pending-delete state for a file object. # C: O(1)
    pub fn delete_on_close(&self) -> Option<Arc<NtDeleteOnClose>> { self.delete_on_close.clone() }

    /// Return the section backing for a section object. # C: O(1)
    pub fn section(&self) -> Option<Arc<NtSection>> { self.section.clone() }
    /// Return the symbolic-link target owner. # C: O(1)
    pub fn symbolic_link(&self) -> Option<Arc<NtSymbolicLink>> { self.symbolic_link.clone() }

    /// Return the scheduler task carried by a process or thread object. # C: O(1)
    pub fn task(&self) -> Option<Arc<Task>> { self.task.clone() }
}
/// Native event state backed by the scheduler's wait primitive.
pub struct NtEvent {
    manual_reset: bool,
    signaled: core::sync::atomic::AtomicBool,
    pulse_epoch: core::sync::atomic::AtomicU64,
    pulse_claimed: core::sync::atomic::AtomicU64,
    waiters: WaitList,
}

/// Native counting semaphore state backed by the scheduler wait primitive.
pub struct NtSemaphore {
    count: core::sync::atomic::AtomicU32,
    maximum: u32,
    waiters: WaitList,
}

impl NtSemaphore {
    fn new(initial: u32, maximum: u32) -> Self {
        Self { count: core::sync::atomic::AtomicU32::new(initial), maximum, waiters: WaitList::new() }
    }

    /// Consume one permit without sleeping. # C: O(1)
    pub fn try_wait(&self) -> bool {
        let mut current = self.count.load(Ordering::Acquire);
        while current != 0 {
            match self.count.compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(next) => current = next,
            }
        }
        false
    }

    /// Read whether at least one permit is available. # C: O(1)
    pub fn is_signaled(&self) -> bool { self.count.load(Ordering::Acquire) != 0 }

    /// Return current and maximum permit counts for NT queries. # C: O(1)
    pub fn counts(&self) -> (u32, u32) { (self.count.load(Ordering::Acquire), self.maximum) }

    /// Release permits and return the previous count, or `None` on overflow. # C: O(1)
    pub fn release(&self, count: u32) -> Option<u32> {
        if count == 0 { return None; }
        let mut current = self.count.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(count)?;
            if next > self.maximum { return None; }
            match self.count.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => { self.waiters.wake_all(); return Some(current); }
                Err(value) => current = value,
            }
        }
    }

    /// Wait for and consume one permit. # C: O(N_wakeups)
    pub unsafe fn wait(&self, deadline_ns: u64, now: impl Fn() -> u64) -> crate::WaitOutcome {
        // SAFETY: caller supplies process context and this predicate owns no external lock.
        unsafe { crate::live::wait_event_interruptible_until(&self.waiters, deadline_ns, now, || self.try_wait()) }
    }
}

impl NtEvent {
    fn new(manual_reset: bool, initial_state: bool) -> Self {
        Self { manual_reset, signaled: core::sync::atomic::AtomicBool::new(initial_state),
            pulse_epoch: core::sync::atomic::AtomicU64::new(0),
            pulse_claimed: core::sync::atomic::AtomicU64::new(0), waiters: WaitList::new() }
    }

    /// Set the event and wake eligible waiters. # C: O(N_waiters)
    pub fn set(&self) {
        self.signaled.store(true, Ordering::Release);
        if self.manual_reset { self.waiters.wake_all(); } else { self.waiters.wake_one(); }
    }

    /// Reset the event so future waits block. # C: O(1)
    pub fn reset(&self) { self.signaled.store(false, Ordering::Release); }

    /// Publish one transient signal and wake the eligible existing waiters.
    /// # C: O(N_waiters)
    pub fn pulse(&self) -> bool {
        let previous = self.signaled.swap(true, Ordering::AcqRel);
        let epoch = self.pulse_epoch.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        self.pulse_claimed.store(epoch.wrapping_sub(1), Ordering::Release);
        if self.manual_reset { self.waiters.wake_all(); } else { self.waiters.wake_one(); }
        self.signaled.store(false, Ordering::Release);
        previous
    }

    /// Capture the pulse epoch before entering a wait. # C: O(1)
    pub fn pulse_epoch(&self) -> u64 { self.pulse_epoch.load(Ordering::Acquire) }

    /// Consume a pulse observed after `epoch`; manual events grant it to each
    /// waiter, while synchronization events grant it to one waiter globally.
    /// # C: O(1)
    pub fn try_pulse_since(&self, epoch: &mut u64) -> bool {
        let current = self.pulse_epoch.load(Ordering::Acquire);
        if current == *epoch { return false; }
        if self.manual_reset {
            *epoch = current;
            return true;
        }
        if self.pulse_claimed.compare_exchange(current.wrapping_sub(1), current,
            Ordering::AcqRel, Ordering::Acquire).is_ok() {
            *epoch = current;
            return true;
        }
        *epoch = current;
        false
    }

    /// Consume one signal if available; manual-reset events remain signaled. # C: O(1)
    pub fn try_wait(&self) -> bool {
        if self.manual_reset { return self.signaled.load(Ordering::Acquire); }
        self.signaled.compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Read the signal state without consuming it. # C: O(1)
    pub fn is_signaled(&self) -> bool { self.signaled.load(Ordering::Acquire) }

    /// Return whether this event remains signaled after a wait. # C: O(1)
    pub fn is_manual_reset(&self) -> bool { self.manual_reset }

    /// Wait using the scheduler's interruptible predicate protocol. # C: O(N_wakeups)
    /// # SAFETY: caller is process context on a running task with no event
    /// lock held; the scheduler wait loop may block and reacquires no caller lock.
    pub unsafe fn wait(&self, deadline_ns: u64, now: impl Fn() -> u64) -> crate::WaitOutcome {
        let mut pulse_epoch = self.pulse_epoch();
        // SAFETY: forwarded to the scheduler predicate loop under the same
        // process-context and lock-ordering contract.
        unsafe { crate::live::wait_event_interruptible_until(&self.waiters, deadline_ns, now,
            || self.try_wait() || self.try_pulse_since(&mut pulse_epoch)) }
    }
}

/// Opaque process-local NT handle.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct NtHandle(u32);

impl NtHandle {
    /// The invalid native handle sentinel. # C: O(1)
    pub const fn invalid() -> Self { Self(INVALID_HANDLE) }

    /// Return the ABI representation of this handle. # C: O(1)
    pub const fn raw(self) -> u32 { self.0 }

    /// Construct a handle from its native ABI representation. # C: O(1)
    pub const fn from_raw(raw: u32) -> Self { Self(raw) }

    fn new(index: usize, generation: u16) -> Option<Self> {
        if index > HANDLE_INDEX_MASK as usize || index == 0 || generation == 0 { return None; }
        Some(Self(((generation as u32) << HANDLE_INDEX_BITS) | index as u32))
    }

    fn parts(self) -> Option<(usize, u16)> {
        if self.0 == INVALID_HANDLE { return None; }
        let index = (self.0 & HANDLE_INDEX_MASK) as usize;
        let generation = (self.0 >> HANDLE_INDEX_BITS) as u16;
        if index == 0 || generation == 0 { None } else { Some((index, generation)) }
    }
}

#[derive(Default)]
struct Entry {
    object: Option<Arc<NtObject>>,
    access: u32,
    flags: u32,
    generation: u16,
}

/// Process-local native handle table.
pub struct NtHandleTable {
    entries: Spinlock<Vec<Entry>, TaskListClass>,
    next_object_id: AtomicU64,
    waiters: WaitList,
}

impl NtHandleTable {
    /// Create an empty process handle table. # C: O(1)
    pub fn new() -> Self {
        Self { entries: Spinlock::new(Vec::new()), next_object_id: AtomicU64::new(1), waiters: WaitList::new() }
    }

    /// Allocate a fresh stable object identity from this process. # C: O(1)
    pub fn new_object(&self, kind: NtObjectType) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new(kind, id)
    }

    /// Resolve a named NT directory in the canonical object namespace and
    /// install a process-local handle for it. # C: O(N_namespace + N_handles)
    pub fn open_directory(&self, path: &str, access: u32) -> Option<NtHandle> {
        let object = lookup_directory(path)?;
        self.insert(object, access)
    }

    /// Allocate an event object with a process-local identity. # C: O(1)
    pub fn new_event(&self, manual_reset: bool, initial_state: bool) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_event(id, manual_reset, initial_state)
    }

    /// Allocate a counting semaphore with a stable native object identity. # C: O(1)
    pub fn new_semaphore(&self, initial: i64, maximum: i64) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_semaphore(id, initial, maximum)
    }

    /// Allocate a thread-owned or unowned mutant with a stable identity. # C: O(1)
    pub fn new_mutant(&self, owner: Option<u64>) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_mutant(id, owner)
    }

    /// Allocate one job object with object-owned mutable limit state. # C: O(1)
    pub fn new_job(&self) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        Arc::new(NtObject { kind: NtObjectType::Job, id, event: None, semaphore: None, mutant: None,
            timer: None, completion: None, token: None, job: Some(Arc::new(NtJob::new())), pipe: None, pipe_endpoint: None, file: None,
            section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None,
            file_completion: Spinlock::new(None) })
    }

    /// Allocate one named-pipe object with scheduler-owned configuration. # C: O(1)
    pub fn new_named_pipe(&self, config: NtPipeConfig) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        Arc::new(NtObject { kind: NtObjectType::NamedPipe, id, event: None, semaphore: None,
            mutant: None, timer: None, completion: None, token: None, job: None,
            pipe: Some(Arc::new(NtPipe::new(config))), pipe_endpoint: None, file: None, section: None,
            symbolic_link: None, task: None, file_share: None, delete_on_close: None,
            file_completion: Spinlock::new(None) })
    }

    pub fn new_named_pipe_endpoint(&self, pipe: Arc<NtPipe>, side: NtPipeSide) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        let endpoint = Arc::new(pipe.endpoint_with_instance(side));
        Arc::new(NtObject { kind: NtObjectType::NamedPipe, id, event: None, semaphore: None,
            mutant: None, timer: None, completion: None, token: None, job: None,
            pipe: Some(pipe), pipe_endpoint: Some(endpoint), file: None, section: None,
            symbolic_link: None, task: None, file_share: None, delete_on_close: None,
            file_completion: Spinlock::new(None) })
    }

    /// Allocate a waitable NT timer with a stable identity. # C: O(1)
    pub fn new_timer(&self, manual_reset: bool) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_timer(id, manual_reset)
    }

    pub fn new_completion_port(&self, concurrency: u32) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        Arc::new(NtObject { kind: NtObjectType::CompletionPort, id, event: None, semaphore: None,
            mutant: None, timer: None, completion: Some(Arc::new(NtCompletionPort::new(concurrency))), token: None, job: None,
            file: None, section: None, symbolic_link: None, task: None, pipe: None, pipe_endpoint: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }

    pub fn new_token(&self, uid: u32, gid: u32) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_token(id, uid, gid)
    }

    /// Allocate a registry-key object identity for the NT registry owner. # C: O(1)
    pub fn new_key(&self) -> Arc<NtObject> {
        self.new_object(NtObjectType::Key)
    }
    pub fn duplicate_token(&self, token: Arc<NtToken>) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::duplicate_token(id, token)
    }

    /// Wrap one VFS open description in a process-local NT object. # C: O(1)
    pub fn new_file(&self, file: Arc<vfs::File>) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_file(id, file)
    }

    /// Wrap a VFS open description with a claimed Windows sharing mode. # C: O(1)
    pub fn new_file_with_share(&self, file: Arc<vfs::File>, share: Arc<NtFileShare>) -> Arc<NtObject> {
        self.new_file_with_share_and_delete(file, share, false)
    }

    /// Wrap a VFS file with sharing and final-close deletion state. # C: O(1)
    pub fn new_file_with_share_and_delete(&self, file: Arc<vfs::File>, share: Arc<NtFileShare>, delete: bool) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        let delete_state = NtDeleteOnClose::new(file.as_ref(), delete);
        NtObject::new_file_with_share(id, file, Some(share), delete_state)
    }

    /// Allocate an anonymous section object. # C: O(size)
    pub fn new_section(&self, size: usize) -> Option<Arc<NtObject>> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        Some(NtObject::new_section(id, NtSection::new(size)?))
    }

    /// Wrap a VFS file in a section object. # C: O(1)
    pub fn new_file_section(&self, file: Arc<vfs::File>, size: usize) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_section(id, NtSection::from_file(file, size))
    }

    /// Allocate a symbolic-link object with one immutable target. # C: O(1)
    pub fn new_symbolic_link(&self, target: String) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_symbolic_link(id, target)
    }

    /// Wrap an unpublished scheduler task in a thread object. # C: O(1)
    pub fn new_thread(&self, task: Arc<Task>) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_thread(id, task)
    }

    /// Wrap an unpublished scheduler task in a process object. # C: O(1)
    pub fn new_process(&self, task: Arc<Task>) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_process(id, task)
    }

    /// Insert an object with its granted access mask and return its handle. # C: O(N)
    pub fn insert(&self, object: Arc<NtObject>, access: u32) -> Option<NtHandle> {
        let mut entries = self.entries.lock();
        let index = entries.iter().position(|entry| entry.object.is_none()).unwrap_or(entries.len());
        if index >= HANDLE_INDEX_MASK as usize { return None; }
        if index == entries.len() { entries.push(Entry { object: None, access: 0, flags: 0, generation: 1 }); }
        let entry = &mut entries[index];
        if entry.generation == 0 { entry.generation = 1; }
        entry.object = Some(object);
        entry.access = access;
        entry.flags = 0;
        NtHandle::new(index + FIRST_INDEX, entry.generation)
    }

    /// Resolve a handle only when its generation and access mask still match. # C: O(1)
    pub fn get(&self, handle: NtHandle, required_access: u32) -> Option<Arc<NtObject>> {
        let (index, generation) = handle.parts()?;
        let entries = self.entries.lock();
        let entry = entries.get(index - FIRST_INDEX)?;
        if entry.generation != generation || entry.access & required_access != required_access { return None; }
        entry.object.clone()
    }

    pub fn contains(&self, handle: NtHandle) -> bool {
        self.get(handle, 0).is_some()
    }

    /// Return the rights granted to a live handle without resolving its object.
    /// # C: O(1)
    pub fn access(&self, handle: NtHandle) -> Option<u32> {
        let (index, generation) = handle.parts()?;
        let entries = self.entries.lock();
        let entry = entries.get(index - FIRST_INDEX)?;
        if entry.generation != generation || entry.object.is_none() { return None; }
        Some(entry.access)
    }

    /// Return the user-visible handle flags. # C: O(1)
    pub fn flags(&self, handle: NtHandle) -> Option<u32> {
        let (index, generation) = handle.parts()?;
        let entries = self.entries.lock();
        let entry = entries.get(index - FIRST_INDEX)?;
        (entry.generation == generation && entry.object.is_some()).then_some(entry.flags)
    }

    /// Update the user-visible inherit/protect-from-close flags. # C: O(1)
    pub fn set_flags(&self, handle: NtHandle, flags: u32) -> Option<()> {
        let (index, generation) = handle.parts()?;
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(index - FIRST_INDEX)?;
        if entry.generation != generation || entry.object.is_none() { return None; }
        entry.flags = flags;
        Some(())
    }

    /// Test whether a user close is prohibited by the handle flags. # C: O(1)
    pub fn is_protected_from_close(&self, handle: NtHandle) -> bool {
        self.flags(handle).is_some_and(|flags| flags & 2 != 0)
    }

    /// Close one handle and release its object reference after table removal. # C: O(1)
    pub fn close(&self, handle: NtHandle) -> bool {
        self.close_with_last(handle).is_some()
    }

    /// Close one handle and report whether it was the final handle for its
    /// shared object. The result is computed while table removal is
    /// serialized, so paired external resources are released exactly once.
    /// # C: O(N_handles)
    pub fn close_with_last(&self, handle: NtHandle) -> Option<bool> {
        let Some((index, generation)) = handle.parts() else { return None; };
        let mut entries = self.entries.lock();
        let object = {
            let Some(entry) = entries.get_mut(index - FIRST_INDEX) else { return None; };
            if entry.generation != generation || entry.object.is_none() { return None; }
            if entry.flags & 2 != 0 { return None; }
            let object = entry.object.take();
            entry.access = 0;
            entry.flags = 0;
            entry.generation = entry.generation.wrapping_add(1);
            if entry.generation == 0 { entry.generation = 1; }
            object
        };
        let has_live_handle = object.as_ref().is_some_and(|object| entries.iter().any(|other|
            other.object.as_ref().is_some_and(|candidate| alloc::sync::Arc::ptr_eq(candidate, object))));
        drop(entries);
        if let Some(object) = object {
            namespace::release_temporary(&object, has_live_handle);
            drop(object);
        }
        Some(!has_live_handle)
    }
    /// Duplicate a handle with a subset of its granted rights. # C: O(1)
    pub fn duplicate(&self, handle: NtHandle, desired_access: u32) -> Option<NtHandle> {
        let object = self.get(handle, desired_access)?;
        self.insert(object, desired_access)
    }

    /// Wake wait-multiple callers after a state-bearing object changes. # C: O(N_waiters)
    pub fn wake_waiters(&self) { self.waiters.wake_all(); }

    /// Return the process-local fanout list used by wait-multiple predicates. # C: O(1)
    pub fn waiters(&self) -> &WaitList { &self.waiters }
}

impl Default for NtHandleTable {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
#[path = "nt_object/tests.rs"]
mod tests;
