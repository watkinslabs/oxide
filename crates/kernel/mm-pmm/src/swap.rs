//! Canonical swap-area ownership: page-sized slots over block devices.
extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use block::{BlockDevice, BlockError, BlockRequest};
use hal::pt_walker::SwapEntry;
use sync::{Spinlock, TaskList};
pub use discard::SwapDiscard;
mod discard;
mod layout;
pub use layout::SwapFileGeometry;
use layout::*;
pub mod hibernate;

/// Filesystem-provided swap backing returned through the VFS
/// `address_space_operations::swap_activate` hook. The owning filesystem
/// keeps any inode pin alive through `device`; dropping the backing therefore
/// is the filesystem's swap-deactivate boundary.
pub struct SwapFileBacking {
    pub name: String,
    pub device: Arc<dyn BlockDevice>,
    pub resume_device: Option<String>,
    pub resume_pages: Vec<u64>,
    pub raw_device: Arc<dyn BlockDevice>,
}
const SWAP_AREA_COUNT: usize = SwapEntry::MAX_KIND as usize + 1;
/// Initial PTE reference held by a slot made visible after a successful write.
const INITIAL_SLOT_PTE_REFS: u32 = 1;
/// Linux's implicit priority when `SWAP_FLAG_PREFER` is absent.
pub const DEFAULT_PRIORITY: i32 = -2;
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SwapError {
    Busy,
    Inval,
    Io,
    NoMem,
    NoSpace,
    NoSuchArea,
}
impl From<BlockError> for SwapError {
    fn from(error: BlockError) -> Self {
        match error {
            BlockError::Enomem => Self::NoMem,
            BlockError::Einval => Self::Inval,
            BlockError::Ebusy => Self::Busy,
            _ => Self::Io,
        }
    }
}
pub type Result<T> = core::result::Result<T, SwapError>;
#[derive(Copy, Clone, Eq, PartialEq)]
enum Slot {
    Free,
    Reserved,
    Writing,
    Releasing,
    Hibernate,
    /// `refs` is the number of swap PTEs; `memcg` is the one canonical
    /// cgroup charge for their shared anonymous contents.
    Used { refs: u32, memcg: u64 },
}
struct Area {
    name: String,
    display_name: String,
    backing: SwapBacking,
    claimed: bool,
    draining: bool,
    hibernating: bool,
    priority: i32,
    discard: SwapDiscard,
    device: Arc<dyn BlockDevice>,
    blocks_per_page: u32,
    file_geometry: Option<SwapFileGeometry>,
    /// Sparse authoritative slot state. Absent entries are free; permanently
    /// unavailable header/bad pages are kept separately, so swapon never
    /// allocates RAM proportional to the logical swap device size.
    slots: BTreeMap<usize, Slot>,
    slot_count: usize,
    reserved: Vec<u32>,
    next_free: usize,
}
impl Area {
    fn used_slots(&self) -> u64 {
        self.slots.values().filter(|slot| matches!(slot, Slot::Used { .. })).count() as u64
    }
    fn has_live_slots(&self) -> bool {
        self.hibernating || self.slots.values().any(|slot| matches!(slot, Slot::Writing | Slot::Releasing | Slot::Hibernate | Slot::Used { .. }))
    }
    fn has_hibernate_slots(&self) -> bool {
        self.hibernating
    }
    fn page_block(&self, offset: u64) -> Result<u64> {
        offset.checked_mul(self.blocks_per_page as u64).ok_or(SwapError::Inval)
    }
    fn slot(&self, offset: usize) -> Option<Slot> {
        if offset >= self.slot_count { return None; }
        if offset == SWAP_HEADER_PAGE as usize || self.reserved.binary_search(&(offset as u32)).is_ok() { return Some(Slot::Reserved); }
        Some(self.slots.get(&offset).copied().unwrap_or(Slot::Free))
    }
    fn set_slot(&mut self, offset: usize, slot: Slot) -> Result<()> {
        if self.slot(offset) == Some(Slot::Reserved) { return Err(SwapError::Inval); }
        if matches!(slot, Slot::Free) { self.slots.remove(&offset); } else { self.slots.insert(offset, slot); }
        Ok(())
    }
    fn next_free_slot(&mut self) -> Option<usize> {
        let first = self.next_free.max(FIRST_DATA_PAGE as usize);
        for offset in first..self.slot_count {
            if self.slot(offset) == Some(Slot::Free) { self.next_free = offset + 1; return Some(offset); }
        }
        for offset in FIRST_DATA_PAGE as usize..first {
            if self.slot(offset) == Some(Slot::Free) { self.next_free = offset + 1; return Some(offset); }
        }
        None
    }
    fn has_free_slot(&self) -> bool {
        (FIRST_DATA_PAGE as usize..self.slot_count).any(|offset| self.slot(offset) == Some(Slot::Free))
    }
}
struct Areas {
    areas: [Option<Area>; SWAP_AREA_COUNT],
    /// Linux assigns every later default-priority area one level below the
    /// preceding default area, so older defaults are exhausted first.
    next_default_priority: i32,
    /// One rotor for each distinct explicit priority currently or previously
    /// used. The bounded swap-type table bounds this state without a second
    /// unbounded priority registry.
    rotors: [Option<PriorityRotor>; SWAP_AREA_COUNT],
}
#[derive(Copy, Clone)]
struct PriorityRotor { priority: i32, next_kind: u8 }
impl Areas {
    const fn new() -> Self {
        Self {
            areas: [const { None }; SWAP_AREA_COUNT],
            next_default_priority: DEFAULT_PRIORITY,
            rotors: [const { None }; SWAP_AREA_COUNT],
        }
    }
    fn allocate_default_priority(&mut self) -> Result<i32> {
        let priority = self.next_default_priority;
        self.next_default_priority = priority.checked_sub(1).ok_or(SwapError::NoSpace)?;
        Ok(priority)
    }
    fn rotation_start(&self, priority: i32) -> usize {
        self.rotors.iter().flatten().find(|rotor| rotor.priority == priority)
            .map_or(0, |rotor| rotor.next_kind as usize)
    }
    fn advance_rotation(&mut self, priority: i32, kind: usize) -> Result<()> {
        let next_kind = if kind + 1 == SWAP_AREA_COUNT { 0 } else { kind + 1 } as u8;
        if let Some(rotor) = self.rotors.iter_mut().flatten().find(|rotor| rotor.priority == priority) {
            rotor.next_kind = next_kind;
            return Ok(());
        }
        let slot = self.rotors.iter_mut().find(|rotor| rotor.is_none()).ok_or(SwapError::NoSpace)?;
        *slot = Some(PriorityRotor { priority, next_kind });
        Ok(())
    }
    fn forget_rotation_if_unused(&mut self, priority: i32) {
        if self.areas.iter().flatten().any(|area| area.priority == priority) { return; }
        if let Some(rotor) = self.rotors.iter_mut().find(|rotor|
            rotor.is_some_and(|rotor| rotor.priority == priority))
        {
            *rotor = None;
        }
    }
}
static AREAS: Spinlock<Areas, TaskList> = Spinlock::new(Areas::new());
/// Whether direct reclaim has an active, non-draining destination area.
/// # C: O(number of swap areas)
pub fn has_writable_area() -> bool {
    AREAS.lock().areas.iter().flatten().any(|area| {
        !area.draining && area.has_free_slot()
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AreaInfo {
    pub name: String,
    pub display_name: String,
    pub backing: SwapBacking,
    pub kind: u8,
    pub pages: u64,
    pub used_pages: u64,
    pub priority: i32,
}

/// Linux `/proc/swaps` backing class. The PMM owns it alongside the canonical
/// area identity, so presentation cannot infer a file/device type from names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SwapBacking { BlockDevice, File }


/// Activate a block-registry disk and retain its canonical consumer claim for
/// the lifetime of the area. Production `swapon` uses this entry point.
/// # C: O(device pages + N_disks + header I/O)
pub fn activate_registered(name: &str) -> Result<u8> {
    activate_registered_inner(name, None, SwapDiscard::None)
}

/// Activate a registered block device at the caller-selected Linux swap
/// priority. Allocation always selects the highest-priority area that has a
/// free slot; `/proc/swaps` exposes the same value.
/// # C: O(device pages + N_disks + header I/O)
pub fn activate_registered_with_priority(name: &str, priority: i32) -> Result<u8> {
    activate_registered_inner(name, Some(priority), SwapDiscard::None)
}

/// Activate a registered block device with priority and Linux discard policy.
/// Incapable device queues accept the request but keep no discard policy.
/// # C: O(device pages + N_disks + header I/O)
pub fn activate_registered_with_options(name: &str, priority: Option<i32>, discard: SwapDiscard) -> Result<u8> {
    activate_registered_inner(name, priority, discard)
}

fn activate_registered_inner(name: &str, priority: Option<i32>, discard: SwapDiscard) -> Result<u8> {
    let disk = block::registry::by_name(name).ok_or(SwapError::NoSuchArea)?;
    if !block::registry::claim(name) { return Err(SwapError::NoSuchArea); }
    let layout = match read_swap_layout(&disk.dev) {
        Ok(layout) => layout,
        Err(error) => { let _ = block::registry::release(name); return Err(error); }
    };
    match activate_inner(String::from(name), String::from(name), SwapBacking::BlockDevice,
                         disk.dev.clone(), true, priority, discard, layout, None) {
        Ok(kind) => Ok(kind),
        Err(error) => {
            let _ = block::registry::release(name);
            Err(error)
        }
    }
}

/// Activate an already-pinned direct block view, such as an ext4 swapfile.
/// Unlike a registry device, its owner keeps the backing lifetime claim and
/// releases it when this canonical area drops. # C: O(device pages + header I/O)
pub fn activate_device_with_priority(name: String, device: Arc<dyn BlockDevice>, priority: i32) -> Result<u8> {
    let layout = read_swap_layout(&device)?;
    activate_inner(name.clone(), name, SwapBacking::BlockDevice, device, false,
        Some(priority), SwapDiscard::None, layout, None)
}

/// Activate an ext4-backed swapfile. `name` is the inode-stable canonical
/// identity; `display_name` is the pathname supplied to `swapon`, retained by
/// the same area record for Linux `/proc/swaps` presentation. # C: O(header I/O)
pub fn activate_file(name: String, display_name: String, device: Arc<dyn BlockDevice>,
                     geometry: SwapFileGeometry) -> Result<u8> {
    let layout = read_swap_layout(&device)?;
    activate_inner(name, display_name, SwapBacking::File, device, false, None,
        SwapDiscard::None, layout, Some(geometry))
}

/// Activate an ext4-backed swapfile with an explicit Linux swap priority.
/// # C: O(header I/O)
pub fn activate_file_with_priority(name: String, display_name: String,
                                   device: Arc<dyn BlockDevice>, priority: i32,
                                   geometry: SwapFileGeometry) -> Result<u8>
{
    let layout = read_swap_layout(&device)?;
    activate_inner(name, display_name, SwapBacking::File, device, false, Some(priority),
        SwapDiscard::None, layout, Some(geometry))
}

/// Activate an ext4-backed swapfile with Linux priority and discard policy.
/// # C: O(header I/O + activation discard)
pub fn activate_file_with_options(name: String, display_name: String, device: Arc<dyn BlockDevice>,
                                  priority: Option<i32>, discard: SwapDiscard,
                                  geometry: SwapFileGeometry) -> Result<u8>
{
    let layout = read_swap_layout(&device)?;
    activate_inner(name, display_name, SwapBacking::File, device, false, priority, discard,
        layout, Some(geometry))
}

/// Activate a filesystem swapfile whose address-space owner cannot provide a
/// stable raw-device resume map. Ordinary paging is still valid; hibernation
/// resume geometry is an additional capability, not a prerequisite for
/// `swapon(2)`.
pub fn activate_file_without_resume(name: String, display_name: String,
                                     device: Arc<dyn BlockDevice>,
                                     priority: Option<i32>, discard: SwapDiscard)
    -> Result<u8>
{
    let layout = read_swap_layout(&device)?;
    activate_inner(name, display_name, SwapBacking::File, device, false, priority,
        discard, layout, None)
}

fn activate_inner(name: String, display_name: String, backing: SwapBacking,
                  device: Arc<dyn BlockDevice>, claimed: bool, priority: Option<i32>,
                  discard: SwapDiscard, layout: SwapLayout,
                  file_geometry: Option<SwapFileGeometry>) -> Result<u8> {
    let block_size = device.block_size() as u64;
    let page_size = hal::PAGE_SIZE_BYTES;
    if block_size == 0 || page_size % block_size != 0 { return Err(SwapError::Inval); }
    let blocks_per_page = u32::try_from(page_size / block_size).map_err(|_| SwapError::Inval)?;
    let mut reserved = layout.bad_pages;
    reserved.sort_unstable();
    let discard = discard.for_device(device.supports_discard());
    if backing == SwapBacking::File {
        if let Some(geometry) = file_geometry.as_ref() {
            validate_file_geometry(geometry, layout.slots)?;
        }
    } else if file_geometry.is_some() { return Err(SwapError::Inval); }
    let mut area = Area { name, display_name, backing, claimed, draining: false, hibernating: false, priority: DEFAULT_PRIORITY, discard, device: device.clone(), blocks_per_page, file_geometry,
        slots: BTreeMap::new(), slot_count: layout.slots, reserved, next_free: FIRST_DATA_PAGE as usize };
    // Linux's activation discard is best effort: failed discard is reported but
    // does not reject a usable swap area.
    if area.discard.once() { let _ = discard::discard_free_area(&area); }
    let mut areas = AREAS.lock();
    if areas.areas.iter().flatten().any(|area| Arc::ptr_eq(&area.device, &device)) {
        return Err(SwapError::Busy);
    }
    let kind = areas.areas.iter().position(Option::is_none).ok_or(SwapError::NoSpace)?;
    let priority = match priority { Some(priority) => priority, None => areas.allocate_default_priority()? };
    area.priority = priority;
    areas.areas[kind] = Some(area);
    Ok(kind as u8)
}


/// Remove an inactive swap area. `swapoff` must migrate every used page before
/// this operation; rejecting a nonempty area prevents losing a live PTE's data.
/// # C: O(area pages)
pub fn deactivate(kind: u8) -> Result<()> {
    let mut areas = AREAS.lock();
    let area = areas.areas.get(kind as usize).and_then(Option::as_ref).ok_or(SwapError::NoSuchArea)?;
    if area.has_live_slots() { return Err(SwapError::Busy); }
    let area = areas.areas[kind as usize].take().ok_or(SwapError::NoSuchArea)?;
    areas.forget_rotation_if_unused(area.priority);
    if area.claimed { let _ = block::registry::release(&area.name); }
    Ok(())
}

/// Begin a swapoff drain. New page-out allocations skip this area while the
/// caller migrates its existing PTEs back to RAM.
/// # C: O(1)
pub fn begin_drain(kind: u8) -> Result<()> {
    let mut areas = AREAS.lock();
    let area = areas.areas.get_mut(kind as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
    if area.draining || area.has_hibernate_slots() { return Err(SwapError::Busy); }
    area.draining = true;
    Ok(())
}

/// End a successful swapoff drain. The area is removed only when no writing,
/// releasing, or PTE-referenced slot remains.
/// # C: O(area pages)
pub fn finish_drain(kind: u8) -> Result<()> {
    let mut areas = AREAS.lock();
    let area = areas.areas.get(kind as usize).and_then(Option::as_ref).ok_or(SwapError::NoSuchArea)?;
    if !area.draining || area.has_live_slots() { return Err(SwapError::Busy); }
    let area = areas.areas[kind as usize].take().ok_or(SwapError::NoSuchArea)?;
    areas.forget_rotation_if_unused(area.priority);
    if area.claimed { let _ = block::registry::release(&area.name); }
    Ok(())
}

/// Cancel an unsuccessful swapoff drain. Existing slots remain intact and the
/// area becomes eligible for future page-out allocation again.
/// # C: O(1)
pub fn cancel_drain(kind: u8) {
    if let Some(area) = AREAS.lock().areas.get_mut(kind as usize).and_then(Option::as_mut) {
        area.draining = false;
    }
}

#[cfg(test)]
mod tests;
mod pages;
pub use pages::{store_page, load_page, retain_page, pte_mapcount, free_page, memcg, snapshot, kind_for_name};
