//! Canonical PMM registry and transaction for driver-owned movable pages.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use movable::{Mode, MoveError, Ops, OwnerId};
use sync::{Spinlock, TaskList};

#[derive(Copy, Clone)]
struct Owner { generation: u32, ops: Ops, live: u32, inflight: u32, dying: bool }
#[derive(Copy, Clone)]
struct Page { pa: u64, owner: OwnerId, isolated: bool }
struct Registry { owners: Vec<Option<Owner>>, pages: Vec<Page> }
impl Registry { const fn new() -> Self { Self { owners: Vec::new(), pages: Vec::new() } } }
static REGISTRY: Spinlock<Registry, TaskList> = Spinlock::new(Registry::new());
static NEXT_GENERATION: AtomicU32 = AtomicU32::new(1);

/// Register one generic movable-page owner. # C: O(owners)
pub fn register(ops: Ops) -> Result<OwnerId, MoveError> {
    let mut registry = REGISTRY.lock();
    let generation = NEXT_GENERATION.fetch_add(1, Ordering::AcqRel);
    if let Some(slot) = registry.owners.iter().position(Option::is_none) {
        registry.owners[slot] = Some(Owner { generation, ops, live: 0, inflight: 0, dying: false });
        return Ok(OwnerId { slot: slot as u32, generation });
    }
    registry.owners.try_reserve(1).map_err(|_| MoveError::Permanent)?;
    registry.owners.push(Some(Owner { generation, ops, live: 0, inflight: 0, dying: false }));
    Ok(OwnerId { slot: (registry.owners.len() - 1) as u32, generation })
}

fn owner_mut(registry: &mut Registry, owner: OwnerId) -> Result<&mut Owner, MoveError> {
    let entry = registry.owners.get_mut(owner.slot as usize).and_then(Option::as_mut).ok_or(MoveError::Permanent)?;
    if entry.generation != owner.generation { return Err(MoveError::Permanent); }
    Ok(entry)
}

/// Publish a newly allocated movable object frame before the owner exposes it. # C: O(pages)
pub fn publish(owner: OwnerId, pa: u64) -> Result<(), MoveError> {
    let mut registry = REGISTRY.lock();
    if owner_mut(&mut registry, owner)?.dying || registry.pages.iter().any(|page| page.pa == pa) { return Err(MoveError::Permanent); }
    registry.pages.try_reserve(1).map_err(|_| MoveError::Permanent)?;
    registry.pages.push(Page { pa, owner, isolated: false });
    owner_mut(&mut registry, owner)?.live = owner_mut(&mut registry, owner)?.live.saturating_add(1);
    Ok(())
}

/// Remove an owner page after its owner has made it unreachable. # C: O(pages)
pub fn release(owner: OwnerId, pa: u64) -> Result<(), MoveError> {
    let mut registry = REGISTRY.lock();
    let index = registry.pages.iter().position(|page| page.pa == pa && page.owner == owner && !page.isolated).ok_or(MoveError::Permanent)?;
    registry.pages.swap_remove(index);
    let entry = owner_mut(&mut registry, owner)?;
    entry.live = entry.live.checked_sub(1).ok_or(MoveError::Permanent)?;
    Ok(())
}

/// Start a Linux-shaped isolate/migrate/putback transaction. # C: O(pages)
pub fn migrate(source: u64, destination: u64, mode: Mode) -> Result<(), MoveError> {
    let (owner, ops) = {
        let mut registry = REGISTRY.lock();
        let index = registry.pages.iter().position(|page| page.pa == source).ok_or(MoveError::Permanent)?;
        let owner = registry.pages[index].owner;
        let isolated = registry.pages[index].isolated;
        let (dying, ops) = { let entry = owner_mut(&mut registry, owner)?; (entry.dying, entry.ops) };
        if dying || isolated { return Err(MoveError::Busy); }
        owner_mut(&mut registry, owner)?.inflight = owner_mut(&mut registry, owner)?.inflight.saturating_add(1);
        registry.pages[index].isolated = true;
        (owner, ops)
    };
    if !(ops.isolate)(owner, source, mode) { return finish_failed(owner, source, ops, MoveError::Busy); }
    let result = (ops.migrate)(owner, destination, source, mode);
    let mut registry = REGISTRY.lock();
    let index = registry.pages.iter().position(|page| page.pa == source && page.owner == owner).ok_or(MoveError::Permanent)?;
    let entry = owner_mut(&mut registry, owner)?;
    entry.inflight = entry.inflight.checked_sub(1).ok_or(MoveError::Permanent)?;
    match result {
        Ok(()) => { registry.pages[index] = Page { pa: destination, owner, isolated: false }; Ok(()) }
        Err(error) => { registry.pages[index].isolated = false; drop(registry); (ops.putback)(owner, source); Err(error) }
    }
}

fn finish_failed(owner: OwnerId, source: u64, ops: Ops, error: MoveError) -> Result<(), MoveError> {
    let mut registry = REGISTRY.lock();
    let index = registry.pages.iter().position(|page| page.pa == source && page.owner == owner).ok_or(MoveError::Permanent)?;
    registry.pages[index].isolated = false;
    owner_mut(&mut registry, owner)?.inflight = owner_mut(&mut registry, owner)?.inflight.checked_sub(1).ok_or(MoveError::Permanent)?;
    drop(registry);
    (ops.putback)(owner, source);
    Err(error)
}

/// Begin owner teardown only after all of its movable pages were released. # C: O(1)
pub fn unregister(owner: OwnerId) -> Result<(), MoveError> {
    let mut registry = REGISTRY.lock();
    let entry = owner_mut(&mut registry, owner)?;
    if entry.live != 0 || entry.inflight != 0 { entry.dying = true; return Err(MoveError::Busy); }
    registry.owners[owner.slot as usize] = None;
    Ok(())
}
