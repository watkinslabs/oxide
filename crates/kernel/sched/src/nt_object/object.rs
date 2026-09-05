//! Native object identity, payloads, events, and semaphores.

use alloc::{string::String, sync::Arc};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use sync::{Spinlock, TaskList as TaskListClass};
use crate::Task;
use super::{NtActivationContext, NtCompletionPort, NtDeleteOnClose, NtFileShare, NtJob,
    NtMutant, NtPipe, NtPipeEndpoint, NtTimer, NtToken};
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use crate::live::WaitList;

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
    ActivationContext,
}
/// Stable identity and type of one native object.
pub struct NtObject {
    pub(super) kind: NtObjectType,
    pub(super) id: u64,
    pub(super) event: Option<Arc<NtEvent>>,
    pub(super) semaphore: Option<Arc<NtSemaphore>>,
    pub(super) mutant: Option<Arc<NtMutant>>,
    pub(super) timer: Option<Arc<NtTimer>>,
    pub(super) completion: Option<Arc<NtCompletionPort>>,
    pub(super) activation: Option<Arc<NtActivationContext>>,
    pub(super) token: Option<Arc<NtToken>>,
    pub(super) job: Option<Arc<NtJob>>,
    pub(super) pipe: Option<Arc<NtPipe>>,
    pub(super) pipe_endpoint: Option<Arc<NtPipeEndpoint>>,
    pub(super) file: Option<Arc<vfs::File>>,
    pub(super) file_info: Option<NtFileInfo>,
    pub(super) section: Option<Arc<NtSection>>,
    pub(super) symbolic_link: Option<Arc<NtSymbolicLink>>,
    pub(super) task: Option<Arc<Task>>,
    #[allow(dead_code)]
    pub(super) file_share: Option<Arc<NtFileShare>>,
    #[allow(dead_code)]
    pub(super) delete_on_close: Option<Arc<NtDeleteOnClose>>,
    pub(super) file_completion: Spinlock<Option<(Arc<NtCompletionPort>, u64)>, TaskListClass>,
}
/// Windows file-descriptor metadata retained by the canonical NT file object.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtFileInfo { pub fd_type: u32, pub cacheable: u32, pub options: u32 }
impl NtFileInfo {
    /// Wine server descriptor classes used by `get_handle_fd`.
    pub const FD_TYPE_FILE: u32 = 1;
    pub const FD_TYPE_DIR: u32 = 2;
    pub const FD_TYPE_SOCKET: u32 = 3;
    pub const FD_TYPE_CHAR: u32 = 5;

    /// Derive the Wine descriptor class from the VFS inode and retain NT open options. # C: O(1)
    pub fn from_file(file: &vfs::File, options: u32) -> Self {
        Self::for_type(file.inode().file_type(), options)
    }

    /// Derive descriptor metadata from the inode class. # C: O(1)
    pub fn for_type(file_type: vfs::types::FileType, options: u32) -> Self {
        let (fd_type, cacheable) = match file_type {
            vfs::types::FileType::Regular | vfs::types::FileType::BlockDev => (Self::FD_TYPE_FILE, 1),
            vfs::types::FileType::Directory => (Self::FD_TYPE_DIR, 1),
            vfs::types::FileType::Socket => (Self::FD_TYPE_SOCKET, 0),
            vfs::types::FileType::CharDev | vfs::types::FileType::Fifo | vfs::types::FileType::Symlink => (Self::FD_TYPE_CHAR, 0),
        };
        Self { fd_type, cacheable, options }
    }
}

#[cfg(test)]
mod tests {
    use super::NtFileInfo;
    use vfs::types::FileType;

    #[test]
    fn wine_descriptor_metadata_preserves_open_options() {
        let info = NtFileInfo::for_type(FileType::Regular, 0x1234_5678);
        assert_eq!(info.fd_type, NtFileInfo::FD_TYPE_FILE);
        assert_eq!(info.cacheable, 1);
        assert_eq!(info.options, 0x1234_5678);
    }

    #[test]
    fn wine_descriptor_metadata_classifies_non_files() {
        let cases = [
            (FileType::Directory, NtFileInfo::FD_TYPE_DIR, 1),
            (FileType::Socket, NtFileInfo::FD_TYPE_SOCKET, 0),
            (FileType::CharDev, NtFileInfo::FD_TYPE_CHAR, 0),
            (FileType::Fifo, NtFileInfo::FD_TYPE_CHAR, 0),
            (FileType::Symlink, NtFileInfo::FD_TYPE_CHAR, 0),
        ];
        for (file_type, fd_type, cacheable) in cases {
            let info = NtFileInfo::for_type(file_type, 0);
            assert_eq!((info.fd_type, info.cacheable), (fd_type, cacheable));
        }
    }
}
/// Immutable byte backing for an anonymous NT section. Writable views use the
/// VMM's normal private fault path until shared section-page ownership exists.
pub struct NtSection {
    bytes: Arc<[u8]>,
    size: usize,
    protection: vmm::VmaProt,
    file: Option<Arc<vfs::File>>,
    flags: u32,
    file_share: Option<Arc<NtFileShare>>,
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
        Self::new_with_flags(size, 0)
    }
    /// Construct zero-filled section backing with protocol-visible flags. # C: O(size)
    pub fn new_with_flags(size: usize, flags: u32) -> Option<Arc<Self>> {
        Self::new_with_protection(size, flags, vmm::VmaProt::READ | vmm::VmaProt::WRITE | vmm::VmaProt::EXEC)
    }
    /// Construct zero-filled section backing with maximum view protection. # C: O(size)
    pub fn new_with_protection(size: usize, flags: u32, protection: vmm::VmaProt) -> Option<Arc<Self>> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).ok()?;
        bytes.resize(size, 0);
        Some(Arc::new(Self { bytes: bytes.into(), size, protection, file: None, flags, file_share: None }))
    }
    /// Construct a file-backed section retaining the VFS open description. # C: O(1)
    pub fn from_file(file: Arc<vfs::File>, size: usize) -> Arc<Self> {
        Self::from_file_with_flags(file, size, 0)
    }
    /// Construct file-backed section backing with protocol-visible flags. # C: O(1)
    pub fn from_file_with_flags(file: Arc<vfs::File>, size: usize, flags: u32) -> Arc<Self> {
        Self::from_file_with_protection(file, size, flags, vmm::VmaProt::READ | vmm::VmaProt::WRITE | vmm::VmaProt::EXEC)
    }
    /// Construct file-backed section backing with maximum view protection. # C: O(1)
    pub fn from_file_with_protection(file: Arc<vfs::File>, size: usize, flags: u32, protection: vmm::VmaProt) -> Arc<Self> {
        Arc::new(Self { bytes: Arc::from(&[][..]), size, protection, file: Some(file), flags, file_share: None })
    }
    /// Construct a file-backed section retaining its mapping share claim. # C: O(1)
    pub fn from_file_with_share(file: Arc<vfs::File>, size: usize, flags: u32, file_share: Arc<NtFileShare>) -> Arc<Self> {
        Self::from_file_with_share_and_protection(file, size, flags, vmm::VmaProt::READ | vmm::VmaProt::WRITE | vmm::VmaProt::EXEC, file_share)
    }
    /// Construct file-backed section backing with sharing and maximum protection. # C: O(1)
    pub fn from_file_with_share_and_protection(file: Arc<vfs::File>, size: usize, flags: u32, protection: vmm::VmaProt, file_share: Arc<NtFileShare>) -> Arc<Self> {
        Arc::new(Self { bytes: Arc::from(&[][..]), size, protection, file: Some(file), flags, file_share: Some(file_share) })
    }
    /// Return the section's byte backing for a VMA. # C: O(1)
    pub fn bytes(&self) -> Arc<[u8]> { self.bytes.clone() }
    /// Return the section extent. # C: O(1)
    pub fn size(&self) -> usize { self.size }
    /// Return the maximum protection permitted for views. # C: O(1)
    pub fn protection(&self) -> vmm::VmaProt { self.protection }
    /// Return the retained file description, if this is file-backed. # C: O(1)
    pub fn file(&self) -> Option<Arc<vfs::File>> { self.file.clone() }
    /// Return protocol-visible mapping flags. # C: O(1)
    pub fn flags(&self) -> u32 { self.flags }
}
impl NtObject {
    /// Create one immutable native object identity. # C: O(1)
    pub fn new(kind: NtObjectType, id: u64) -> Arc<Self> {
        Arc::new(Self { kind, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, activation: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None, section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create an event-backed native object. # C: O(1)
    pub fn new_event(id: u64, manual_reset: bool, initial_state: bool) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Event, id,
            event: Some(Arc::new(NtEvent::new(manual_reset, initial_state))), semaphore: None, mutant: None, timer: None, completion: None, activation: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None, section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a counting semaphore object. # C: O(1)
    pub fn new_semaphore(id: u64, initial: i64, maximum: i64) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Semaphore, id, event: None,
            semaphore: Some(Arc::new(NtSemaphore::new(initial as u32, maximum as u32))), mutant: None, timer: None, completion: None, activation: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None, section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a thread-owned NT mutant. # C: O(1)
    pub fn new_mutant(id: u64, owner: Option<u64>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Mutant, id, event: None, semaphore: None,
            mutant: Some(Arc::new(NtMutant::new(owner))), timer: None, completion: None, activation: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None, section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a waitable NT timer object. # C: O(1)
    pub fn new_timer(id: u64, manual_reset: bool) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Timer, id, event: None, semaphore: None,
            mutant: None, timer: Some(Arc::new(NtTimer::new(manual_reset))), completion: None, activation: None, token: None, file: None,
            section: None, symbolic_link: None, task: None, job: None, pipe: None, pipe_endpoint: None, file_info: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a file object retaining the canonical VFS open description. # C: O(1)
    pub fn new_file(id: u64, file: Arc<vfs::File>) -> Arc<Self> {
        let delete = NtDeleteOnClose::new(file.as_ref(), false);
        let info = NtFileInfo::from_file(file.as_ref(), 0);
        Self::new_file_with_share_and_info(id, file, info, None, delete)
    }
    /// Create a file object retaining its Windows sharing claim. # C: O(1)
    pub fn new_file_with_share(id: u64, file: Arc<vfs::File>, file_share: Option<Arc<NtFileShare>>, delete_on_close: Option<Arc<NtDeleteOnClose>>) -> Arc<Self> {
        let info = NtFileInfo::from_file(file.as_ref(), 0);
        Self::new_file_with_share_and_info(id, file, info, file_share, delete_on_close)
    }
    /// Create a file object while retaining its complete Windows descriptor metadata. # C: O(1)
    pub fn new_file_with_share_and_info(id: u64, file: Arc<vfs::File>, info: NtFileInfo,
                                        file_share: Option<Arc<NtFileShare>>, delete_on_close: Option<Arc<NtDeleteOnClose>>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::File, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, activation: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: Some(file), file_info: Some(info), section: None, symbolic_link: None, task: None, file_share, delete_on_close, file_completion: Spinlock::new(None) })
    }
    /// Create an anonymous section object. # C: O(1)
    pub fn new_section(id: u64, section: Arc<NtSection>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Section, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, activation: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None, section: Some(section), symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create one symbolic-link object identity. # C: O(1)
    pub fn new_symbolic_link(id: u64, target: String) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::SymbolicLink, id, event: None, semaphore: None, mutant: None, timer: None,
            completion: None, activation: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None, section: None, symbolic_link: Some(NtSymbolicLink::new(target)),
            task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a process object backed by the canonical scheduler task. # C: O(1)
    pub fn new_process(id: u64, task: Arc<Task>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Process, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, activation: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None, section: None, symbolic_link: None, task: Some(task), file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    /// Create a thread object backed by the canonical scheduler task. # C: O(1)
    pub fn new_thread(id: u64, task: Arc<Task>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Thread, id, event: None, semaphore: None, mutant: None, timer: None, completion: None, activation: None, token: None, job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None, section: None, symbolic_link: None, task: Some(task), file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
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

    /// Apply the signal operation used by signal-and-wait. # C: O(1)
    pub fn signal_for_wait(&self, tid: u64) -> Result<(), NtSignalError> {
        match self.kind {
            NtObjectType::Event => self.event.as_ref().ok_or(NtSignalError::Unsupported)?.set(),
            NtObjectType::Semaphore => {
                if self.semaphore.as_ref().ok_or(NtSignalError::Unsupported)?.release(1).is_none() {
                    return Err(NtSignalError::LimitExceeded);
                }
            }
            NtObjectType::Mutant => {
                self.mutant.as_ref().ok_or(NtSignalError::Unsupported)?.release(tid)
                    .map_err(|_| NtSignalError::NotOwner)?;
            }
            _ => return Err(NtSignalError::Unsupported),
        }
        Ok(())
    }

    /// Return the timer primitive carried by a timer object. # C: O(1)
    pub fn timer(&self) -> Option<Arc<NtTimer>> { self.timer.clone() }
    pub fn job(&self) -> Option<Arc<NtJob>> { self.job.clone() }
    pub fn pipe(&self) -> Option<Arc<NtPipe>> { self.pipe.clone() }
    pub fn pipe_endpoint(&self) -> Option<Arc<NtPipeEndpoint>> { self.pipe_endpoint.clone() }

    pub fn completion(&self) -> Option<Arc<NtCompletionPort>> { self.completion.clone() }
    /// Create an activation-context identity with one caller reference. # C: O(1)
    pub fn new_activation_context(id: u64) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::ActivationContext, id, event: None, semaphore: None,
            mutant: None, timer: None, completion: None, activation: Some(NtActivationContext::new()),
            token: None, job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None, section: None,
            symbolic_link: None, task: None, file_share: None, delete_on_close: None,
            file_completion: Spinlock::new(None) })
    }
    pub fn activation_context(&self) -> Option<Arc<NtActivationContext>> { self.activation.clone() }
    pub fn new_token(id: u64, uid: u32, gid: u32) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Token, id, event: None, semaphore: None, mutant: None,
            timer: None, completion: None, activation: None, token: Some(Arc::new(NtToken::new(uid, gid))), job: None, pipe: None, pipe_endpoint: None, file: None, file_info: None,
            section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }
    pub fn token(&self) -> Option<Arc<NtToken>> { self.token.clone() }
    pub fn duplicate_token(id: u64, token: Arc<NtToken>) -> Arc<Self> {
        Arc::new(Self { kind: NtObjectType::Token, id, event: None, semaphore: None, mutant: None,
            timer: None, completion: None, activation: None, token: Some(token), job: None, pipe: None, pipe_endpoint: None, file: None, section: None, symbolic_link: None,
            task: None, file_info: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }

    /// Return the next armed timer deadline, or `None` for non-timers/disarmed timers. # C: O(1)
    pub fn timer_deadline(&self) -> Option<u64> { self.timer.as_ref().and_then(|timer| timer.deadline()) }

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
    /// Return the descriptor metadata retained at NT file creation. # C: O(1)
    pub fn file_info(&self) -> Option<NtFileInfo> { self.file_info }
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

/// Failure classes for the signal half of a native signal-and-wait operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtSignalError { Unsupported, LimitExceeded, NotOwner }
/// Native event state backed by the scheduler's wait primitive.
pub struct NtEvent {
    manual_reset: bool,
    signaled: core::sync::atomic::AtomicBool,
    pulse_epoch: core::sync::atomic::AtomicU64,
    pulse_claimed: core::sync::atomic::AtomicU64,
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    waiters: WaitList,
}

/// Native counting semaphore state backed by the scheduler wait primitive.
pub struct NtSemaphore {
    count: core::sync::atomic::AtomicU32,
    maximum: u32,
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    waiters: WaitList,
}

impl NtSemaphore {
    fn new(initial: u32, maximum: u32) -> Self {
        Self { count: core::sync::atomic::AtomicU32::new(initial), maximum,
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            waiters: WaitList::new() }
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
                Ok(_) => {
                    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
                    self.waiters.wake_all();
                    return Some(current);
                }
                Err(value) => current = value,
            }
        }
    }

    /// Wait for and consume one permit. # C: O(N_wakeups)
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait(&self, deadline_ns: u64, now: impl Fn() -> u64) -> crate::WaitOutcome {
        // SAFETY: caller supplies process context and this predicate owns no external lock.
        unsafe { crate::live::wait_event_interruptible_until(&self.waiters, deadline_ns, now, || self.try_wait()) }
    }

    /// Alertable semaphore wait with a distinct native APC outcome. # C: O(N_wakeups)
    /// # SAFETY: caller is process context and owns no semaphore/wait-list lock.
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait_alertable(&self, deadline_ns: u64, now: impl Fn() -> u64,
                                 apc: impl FnMut() -> bool) -> crate::NtWaitOutcome {
        // SAFETY: forwarded to the scheduler alertable wait contract.
        unsafe { crate::live::wait_event_interruptible_until_user_apc(&self.waiters,
            deadline_ns, now, apc, || self.try_wait()) }
    }
}

impl NtEvent {
    fn new(manual_reset: bool, initial_state: bool) -> Self {
        Self { manual_reset, signaled: core::sync::atomic::AtomicBool::new(initial_state),
            pulse_epoch: core::sync::atomic::AtomicU64::new(0),
            pulse_claimed: core::sync::atomic::AtomicU64::new(0),
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            waiters: WaitList::new() }
    }

    /// Set the event and wake eligible waiters. # C: O(N_waiters)
    pub fn set(&self) {
        self.signaled.store(true, Ordering::Release);
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
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
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
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
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait(&self, deadline_ns: u64, now: impl Fn() -> u64) -> crate::WaitOutcome {
        let mut pulse_epoch = self.pulse_epoch();
        // SAFETY: forwarded to the scheduler predicate loop under the same
        // process-context and lock-ordering contract.
        unsafe { crate::live::wait_event_interruptible_until(&self.waiters, deadline_ns, now,
            || self.try_wait() || self.try_pulse_since(&mut pulse_epoch)) }
    }

    /// Alertable event wait with a distinct native APC outcome. # C: O(N_wakeups)
    /// # SAFETY: caller is process context and owns no event/wait-list lock.
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait_alertable(&self, deadline_ns: u64, now: impl Fn() -> u64,
                                 apc: impl FnMut() -> bool) -> crate::NtWaitOutcome {
        let mut pulse_epoch = self.pulse_epoch();
        // SAFETY: forwarded to the scheduler alertable wait contract.
        unsafe { crate::live::wait_event_interruptible_until_user_apc(&self.waiters,
            deadline_ns, now, apc,
            || self.try_wait() || self.try_pulse_since(&mut pulse_epoch)) }
    }
}
