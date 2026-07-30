extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;

use super::parse::BtfIndex;

const FIRST_OBJECT_ID: u32 = 1;
const OBJECT_ID_EXCLUSIVE_MAX: u32 = i32::MAX as u32;
const LAST_OBJECT_ID: u32 = OBJECT_ID_EXCLUSIVE_MAX - 1;
const OBJECT_ID_COUNT: u32 = LAST_OBJECT_ID;

enum RegistryEntry {
    Reserved(u32),
    Live(u32, Weak<BtfObject>),
}

impl RegistryEntry {
    fn id(&self) -> u32 {
        match self {
            Self::Reserved(id) | Self::Live(id, _) => *id,
        }
    }
}

struct Registry {
    entries: Vec<RegistryEntry>,
}

static NEXT_ID: AtomicU32 = AtomicU32::new(FIRST_OBJECT_ID);
static REGISTRY: Spinlock<Registry, TaskListClass> =
    Spinlock::new(Registry { entries: Vec::new() });

pub(crate) struct BtfObject {
    id: u32,
    raw: Vec<u8>,
    _index: BtfIndex,
}

impl BtfObject {
    /// Publish one parsed object while retaining its exact input bytes.
    /// # C: O(number of live objects + input allocation)
    /// # Ctx: process; caller holds no `TaskListClass` lock
    /// # Lk: takes `TaskListClass`
    /// # Sleeps: no
    pub(crate) fn register(raw: Vec<u8>, index: BtfIndex)
        -> Result<Arc<Self>, Errno>
    {
        let id = reserve_id()?;
        let object = match Arc::try_new(Self { id, raw, _index: index }) {
            Ok(object) => object,
            Err(_) => {
                cancel_id(id);
                return Err(Errno::Enomem);
            }
        };
        settle_id(id, &object);
        Ok(object)
    }

    /// Stable nonzero registry ID.
    /// # C: O(1)
    pub(crate) fn id(&self) -> u32 { self.id }

    /// Exact byte sequence retained for object lifetime.
    /// # C: O(1)
    pub(crate) fn raw(&self) -> &[u8] { &self.raw }

    #[cfg(test)]
    /// Parser-owned canonical type index.
    /// # C: O(1)
    pub(crate) fn index(&self) -> &BtfIndex { &self._index }
}

impl Drop for BtfObject {
    fn drop(&mut self) {
        let mut registry = REGISTRY.lock();
        let Ok(at) = registry.entries.binary_search_by_key(&self.id, RegistryEntry::id)
            else { return; };
        let remove = match &registry.entries[at] {
            RegistryEntry::Live(_, owner) => {
                owner.strong_count() == 0 && core::ptr::eq(owner.as_ptr(), self)
            }
            RegistryEntry::Reserved(_) => false,
        };
        if remove { registry.entries.remove(at); }
    }
}

/// Pin a live object by stable ID.
/// # C: O(log(number of live objects))
/// # Ctx: process; caller holds no `TaskListClass` lock
/// # Lk: takes `TaskListClass`
/// # Sleeps: no
pub(crate) fn get_by_id(id: u32) -> Result<Arc<BtfObject>, Errno> {
    if !valid_object_id(id) { return Err(Errno::Enoent); }
    let mut registry = REGISTRY.lock();
    let at = registry.entries.binary_search_by_key(&id, RegistryEntry::id)
        .map_err(|_| Errno::Enoent)?;
    match &registry.entries[at] {
        RegistryEntry::Live(_, owner) => match owner.upgrade() {
            Some(object) => Ok(object),
            None => {
                registry.entries.remove(at);
                Err(Errno::Enoent)
            }
        },
        RegistryEntry::Reserved(_) => Err(Errno::Enoent),
    }
}

/// Return the least live ID strictly greater than `start`.
/// # C: O(number of dead entries + log(number of live objects))
/// # Ctx: process; caller holds no `TaskListClass` lock
/// # Lk: takes `TaskListClass`
/// # Sleeps: no
pub(crate) fn next_id(start: u32) -> Result<u32, Errno> {
    if start >= OBJECT_ID_EXCLUSIVE_MAX { return Err(Errno::Einval); }
    let mut registry = REGISTRY.lock();
    let mut at = match registry.entries.binary_search_by_key(&start, RegistryEntry::id) {
        Ok(at) => at + 1,
        Err(at) => at,
    };
    while at < registry.entries.len() {
        match &registry.entries[at] {
            RegistryEntry::Reserved(_) => at += 1,
            RegistryEntry::Live(_, owner) if owner.strong_count() != 0 =>
                return Ok(registry.entries[at].id()),
            RegistryEntry::Live(_, _) => { registry.entries.remove(at); }
        }
    }
    Err(Errno::Enoent)
}

fn reserve_id() -> Result<u32, Errno> {
    let mut examined = 0u32;
    while examined < OBJECT_ID_COUNT {
        let id = next_candidate_id();
        examined += 1;
        let mut registry = REGISTRY.lock();
        match registry.entries.binary_search_by_key(&id, RegistryEntry::id) {
            Ok(at) => {
                let reusable = match &registry.entries[at] {
                    RegistryEntry::Reserved(_) => false,
                    RegistryEntry::Live(_, owner) => owner.strong_count() == 0,
                };
                if reusable {
                    registry.entries[at] = RegistryEntry::Reserved(id);
                    return Ok(id);
                }
            }
            Err(at) => {
                registry.entries.try_reserve(1).map_err(|_| Errno::Enomem)?;
                registry.entries.insert(at, RegistryEntry::Reserved(id));
                return Ok(id);
            }
        }
    }
    Err(Errno::Enospc)
}

fn next_candidate_id() -> u32 {
    loop {
        let observed = NEXT_ID.load(Ordering::Relaxed);
        let id = if valid_object_id(observed) { observed } else { FIRST_OBJECT_ID };
        if NEXT_ID.compare_exchange_weak(
            observed, successor_id(id), Ordering::Relaxed, Ordering::Relaxed,
        ).is_ok() {
            return id;
        }
    }
}

fn successor_id(id: u32) -> u32 {
    if id < FIRST_OBJECT_ID || id >= LAST_OBJECT_ID {
        FIRST_OBJECT_ID
    } else {
        id + 1
    }
}

fn valid_object_id(id: u32) -> bool {
    (FIRST_OBJECT_ID..OBJECT_ID_EXCLUSIVE_MAX).contains(&id)
}

fn settle_id(id: u32, object: &Arc<BtfObject>) {
    let mut registry = REGISTRY.lock();
    let at = registry.entries.binary_search_by_key(&id, RegistryEntry::id);
    hal::kassert!(
        matches!(at, Ok(at)
            if matches!(registry.entries[at],
                RegistryEntry::Reserved(entry_id) if entry_id == id)),
        "settling an unreserved BTF object ID"
    );
    let Ok(at) = at else { return; };
    registry.entries[at] = RegistryEntry::Live(id, Arc::downgrade(object));
}

fn cancel_id(id: u32) {
    let mut registry = REGISTRY.lock();
    let Ok(at) = registry.entries.binary_search_by_key(&id, RegistryEntry::id)
        else { return; };
    if matches!(registry.entries[at], RegistryEntry::Reserved(entry_id) if entry_id == id) {
        registry.entries.remove(at);
    }
}

#[cfg(test)]
#[path = "object_tests.rs"]
mod tests;
