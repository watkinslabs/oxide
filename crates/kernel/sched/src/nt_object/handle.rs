use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

use crate::Task;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use crate::live::WaitList;
use super::{namespace, lookup_directory, NtCompletionPort, NtDeleteOnClose, NtFileInfo, NtFileShare,
    NtJob, NtObject, NtObjectType, NtPipe, NtPipeConfig, NtPipeSide, NtSection, NtToken};

const HANDLE_INDEX_BITS: u32 = 16;
const HANDLE_INDEX_MASK: u32 = (1 << HANDLE_INDEX_BITS) - 1;
const FIRST_INDEX: usize = 1;
const INVALID_HANDLE: u32 = u32::MAX;

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
    retired: bool,
}

/// Process-local native handle table.
pub struct NtHandleTable {
    entries: Spinlock<Vec<Entry>, TaskListClass>,
    next_object_id: AtomicU64,
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    waiters: WaitList,
}

impl NtHandleTable {
    /// Create an empty process handle table. # C: O(1)
    pub fn new() -> Self {
        Self { entries: Spinlock::new(Vec::new()), next_object_id: AtomicU64::new(1),
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            waiters: WaitList::new() }
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
            timer: None, completion: None, activation: None, token: None, job: Some(Arc::new(NtJob::new())), pipe: None, pipe_endpoint: None, file: None, file_info: None,
            section: None, symbolic_link: None, task: None, file_share: None, delete_on_close: None,
            file_completion: Spinlock::new(None) })
    }

    /// Allocate one named-pipe object with scheduler-owned configuration. # C: O(1)
    pub fn new_named_pipe(&self, config: NtPipeConfig) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        Arc::new(NtObject { kind: NtObjectType::NamedPipe, id, event: None, semaphore: None,
            mutant: None, timer: None, completion: None, activation: None, token: None, job: None,
            pipe: Some(Arc::new(NtPipe::new(config))), pipe_endpoint: None, file: None, file_info: None, section: None,
            symbolic_link: None, task: None, file_share: None, delete_on_close: None,
            file_completion: Spinlock::new(None) })
    }

    pub fn new_named_pipe_endpoint(&self, pipe: Arc<NtPipe>, side: NtPipeSide) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        let endpoint = Arc::new(pipe.endpoint_with_instance(side));
        Arc::new(NtObject { kind: NtObjectType::NamedPipe, id, event: None, semaphore: None,
            mutant: None, timer: None, completion: None, activation: None, token: None, job: None,
            pipe: Some(pipe), pipe_endpoint: Some(endpoint), file: None, file_info: None, section: None,
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
            mutant: None, timer: None, completion: Some(Arc::new(NtCompletionPort::new(concurrency))), activation: None, token: None, job: None,
            file: None, file_info: None, section: None, symbolic_link: None, task: None, pipe: None, pipe_endpoint: None, file_share: None, delete_on_close: None, file_completion: Spinlock::new(None) })
    }

    pub fn new_token(&self, uid: u32, gid: u32) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_token(id, uid, gid)
    }

    /// Allocate an activation-context identity with one caller reference. # C: O(1)
    pub fn new_activation_context(&self) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_activation_context(id)
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
        let info = NtFileInfo::from_file(file.as_ref(), 0);
        self.new_file_with_share_and_delete_and_info(file, share, delete, info)
    }

    /// Wrap a VFS file with sharing, deletion, and Windows descriptor metadata. # C: O(1)
    pub fn new_file_with_share_and_delete_and_info(&self, file: Arc<vfs::File>, share: Arc<NtFileShare>, delete: bool, info: NtFileInfo) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        let delete_state = NtDeleteOnClose::new(file.as_ref(), delete);
        NtObject::new_file_with_share_and_info(id, file, info, Some(share), delete_state)
    }

    /// Allocate an anonymous section object. # C: O(size)
    pub fn new_section(&self, size: usize) -> Option<Arc<NtObject>> {
        self.new_section_with_flags(size, 0)
    }
    /// Allocate an anonymous section with protocol-visible flags. # C: O(size)
    pub fn new_section_with_flags(&self, size: usize, flags: u32) -> Option<Arc<NtObject>> {
        self.new_section_with_protection(size, flags, vmm::VmaProt::READ | vmm::VmaProt::WRITE | vmm::VmaProt::EXEC)
    }
    /// Allocate an anonymous section with maximum view protection. # C: O(size)
    pub fn new_section_with_protection(&self, size: usize, flags: u32, protection: vmm::VmaProt) -> Option<Arc<NtObject>> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        Some(NtObject::new_section(id, NtSection::new_with_protection(size, flags, protection)?))
    }

    /// Wrap a VFS file in a section object. # C: O(1)
    pub fn new_file_section(&self, file: Arc<vfs::File>, size: usize) -> Arc<NtObject> {
        self.new_file_section_with_flags(file, size, 0)
    }
    /// Wrap a VFS file in a section carrying protocol-visible flags. # C: O(1)
    pub fn new_file_section_with_flags(&self, file: Arc<vfs::File>, size: usize, flags: u32) -> Arc<NtObject> {
        self.new_file_section_with_protection(file, size, flags, vmm::VmaProt::READ | vmm::VmaProt::WRITE | vmm::VmaProt::EXEC)
    }
    /// Wrap a VFS file in a section with maximum view protection. # C: O(1)
    pub fn new_file_section_with_protection(&self, file: Arc<vfs::File>, size: usize, flags: u32, protection: vmm::VmaProt) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_section(id, NtSection::from_file_with_protection(file, size, flags, protection))
    }

    /// Wrap a VFS file in a section while retaining its mapping share claim. # C: O(1)
    pub fn new_file_section_with_share(&self, file: Arc<vfs::File>, size: usize, flags: u32, share: Arc<NtFileShare>) -> Arc<NtObject> {
        self.new_file_section_with_share_and_protection(file, size, flags, vmm::VmaProt::READ | vmm::VmaProt::WRITE | vmm::VmaProt::EXEC, share)
    }
    /// Wrap a VFS file in a section with sharing and maximum protection. # C: O(1)
    pub fn new_file_section_with_share_and_protection(&self, file: Arc<vfs::File>, size: usize, flags: u32, protection: vmm::VmaProt, share: Arc<NtFileShare>) -> Arc<NtObject> {
        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        NtObject::new_section(id, NtSection::from_file_with_share_and_protection(file, size, flags, protection, share))
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
        Self::insert_locked(&mut entries, object, access)
    }

    fn insert_locked(entries: &mut Vec<Entry>, object: Arc<NtObject>, access: u32) -> Option<NtHandle> {
        let index = entries.iter().position(|entry| entry.object.is_none() && !entry.retired).unwrap_or(entries.len());
        if index >= HANDLE_INDEX_MASK as usize { return None; }
        if index == entries.len() { entries.push(Entry { object: None, access: 0, flags: 0, generation: 1, retired: false }); }
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

    /// Return the number of live handles in this process table from one
    /// lock-consistent snapshot. # C: O(N)
    pub fn live_handle_count(&self) -> u32 {
        self.entries.lock().iter().filter(|entry| entry.object.is_some()).count() as u32
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

    /// Return the live handle count for the object named by `handle` while
    /// holding the table lock, so object queries cannot observe a torn count.
    /// # C: O(N)
    pub fn handle_count(&self, handle: NtHandle) -> Option<u32> {
        let (index, generation) = handle.parts()?;
        let entries = self.entries.lock();
        let entry = entries.get(index - FIRST_INDEX)?;
        let object = entry.object.as_ref()?;
        if entry.generation != generation { return None; }
        Some(entries.iter().filter(|candidate| candidate.object.as_ref().is_some_and(|other|
            alloc::sync::Arc::ptr_eq(other, object))).count() as u32)
    }

    /// Return the granted rights and live object-handle count from one table
    /// snapshot for `NtQueryObject`. # C: O(N)
    pub fn access_and_handle_count(&self, handle: NtHandle) -> Option<(u32, u32)> {
        let (index, generation) = handle.parts()?;
        let entries = self.entries.lock();
        let entry = entries.get(index - FIRST_INDEX)?;
        let object = entry.object.as_ref()?;
        if entry.generation != generation { return None; }
        let count = entries.iter().filter(|candidate| candidate.object.as_ref().is_some_and(|other|
            alloc::sync::Arc::ptr_eq(other, object))).count() as u32;
        Some((entry.access, count))
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

    /// Consume a source handle as part of a successful duplicate operation.
    /// # C: O(N_handles)
    pub fn close_duplicate_source(&self, handle: NtHandle) -> bool {
        self.close_with_last_inner(handle, false).is_some()
    }

    /// Close one handle and report whether it was the final handle for its
    /// shared object. The result is computed while table removal is
    /// serialized, so paired external resources are released exactly once.
    /// # C: O(N_handles)
    pub fn close_with_last(&self, handle: NtHandle) -> Option<bool> {
        self.close_with_last_inner(handle, false)
    }

    fn close_with_last_inner(&self, handle: NtHandle, duplicate_source: bool) -> Option<bool> {
        let Some((index, generation)) = handle.parts() else { return None; };
        let mut entries = self.entries.lock();
        let object = {
            let Some(entry) = entries.get_mut(index - FIRST_INDEX) else { return None; };
            if entry.generation != generation || entry.object.is_none() { return None; }
            if !duplicate_source && entry.flags & 2 != 0 { return None; }
            let object = entry.object.take();
            entry.access = 0;
            entry.flags = 0;
            entry.generation = entry.generation.wrapping_add(1);
            if entry.generation == 0 { entry.retired = true; }
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
        let (index, generation) = handle.parts()?;
        let mut entries = self.entries.lock();
        let object = {
            let entry = entries.get(index - FIRST_INDEX)?;
            if entry.generation != generation || entry.access & desired_access != desired_access {
                return None;
            }
            entry.object.clone()?
        };
        Self::insert_locked(&mut entries, object, desired_access)
    }

    /// Wake wait-multiple callers after a state-bearing object changes. # C: O(N_waiters)
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub fn wake_waiters(&self) { self.waiters.wake_all(); }

    /// Return the process-local fanout list used by wait-multiple predicates. # C: O(1)
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub fn waiters(&self) -> &WaitList { &self.waiters }
}

impl Default for NtHandleTable {
    fn default() -> Self { Self::new() }
}
