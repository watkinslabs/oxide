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
const SWAP_AREA_COUNT: usize = SwapEntry::MAX_KIND as usize + 1;
const SWAP_HEADER_PAGE: u64 = 0;
const FIRST_DATA_PAGE: u64 = SWAP_HEADER_PAGE + 1;
/// Width of every 32-bit little-endian field in the Linux swap header.
const SWAP_HEADER_U32_BYTES: usize = core::mem::size_of::<u32>();
/// Linux swap-header format version accepted by the `SWAPSPACE2` signature.
const SWAPSPACE2_VERSION: u32 = 1;
/// Initial PTE reference held by a slot made visible after a successful write.
const INITIAL_SLOT_PTE_REFS: u32 = 1;
const SWAP_HEADER_VERSION_OFFSET: usize = 1024;
const SWAP_HEADER_LAST_PAGE_OFFSET: usize = SWAP_HEADER_VERSION_OFFSET + SWAP_HEADER_U32_BYTES;
const SWAP_HEADER_BAD_PAGE_COUNT_OFFSET: usize = SWAP_HEADER_LAST_PAGE_OFFSET + SWAP_HEADER_U32_BYTES;
const SWAP_HEADER_BAD_PAGES_OFFSET: usize = SWAP_HEADER_BAD_PAGE_COUNT_OFFSET + SWAP_HEADER_U32_BYTES;
const SWAP_MAGIC: &[u8; 10] = b"SWAPSPACE2";
/// Linux's implicit priority when `SWAP_FLAG_PREFER` is absent.
pub const DEFAULT_PRIORITY: i32 = -2;
struct SwapLayout { slots: usize, bad_pages: Vec<u32> }
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
    priority: i32,
    discard: SwapDiscard,
    device: Arc<dyn BlockDevice>,
    blocks_per_page: u32,
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
        self.slots.values().any(|slot| matches!(slot, Slot::Writing | Slot::Releasing | Slot::Used { .. }))
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
                         disk.dev.clone(), true, priority, discard, layout) {
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
    activate_inner(name.clone(), name, SwapBacking::BlockDevice, device, false, Some(priority), SwapDiscard::None, layout)
}

/// Activate an ext4-backed swapfile. `name` is the inode-stable canonical
/// identity; `display_name` is the pathname supplied to `swapon`, retained by
/// the same area record for Linux `/proc/swaps` presentation. # C: O(header I/O)
pub fn activate_file(name: String, display_name: String, device: Arc<dyn BlockDevice>) -> Result<u8> {
    let layout = read_swap_layout(&device)?;
    activate_inner(name, display_name, SwapBacking::File, device, false, None, SwapDiscard::None, layout)
}

/// Activate an ext4-backed swapfile with an explicit Linux swap priority.
/// # C: O(header I/O)
pub fn activate_file_with_priority(name: String, display_name: String,
                                   device: Arc<dyn BlockDevice>, priority: i32) -> Result<u8>
{
    let layout = read_swap_layout(&device)?;
    activate_inner(name, display_name, SwapBacking::File, device, false, Some(priority), SwapDiscard::None, layout)
}

/// Activate an ext4-backed swapfile with Linux priority and discard policy.
/// # C: O(header I/O + activation discard)
pub fn activate_file_with_options(name: String, display_name: String, device: Arc<dyn BlockDevice>,
                                  priority: Option<i32>, discard: SwapDiscard) -> Result<u8>
{
    let layout = read_swap_layout(&device)?;
    activate_inner(name, display_name, SwapBacking::File, device, false, priority, discard, layout)
}

fn read_swap_layout(device: &Arc<dyn BlockDevice>) -> Result<SwapLayout> {
    let block_size = device.block_size() as u64;
    let page_size = hal::PAGE_SIZE_BYTES;
    if block_size == 0 || page_size % block_size != 0 { return Err(SwapError::Inval); }
    let blocks_per_page = u32::try_from(page_size / block_size).map_err(|_| SwapError::Inval)?;
    let pages = device.capacity_blocks() / blocks_per_page as u64;
    if pages <= FIRST_DATA_PAGE { return Err(SwapError::Inval); }
    let mut request = BlockRequest::new_read(SWAP_HEADER_PAGE, blocks_per_page, device.block_size());
    device.submit_sync(&mut request).map_err(SwapError::from)?;
    let page = request.buffer;
    let magic_at = page.len().checked_sub(SWAP_MAGIC.len()).ok_or(SwapError::Inval)?;
    if page.get(magic_at..) != Some(SWAP_MAGIC) { return Err(SwapError::Inval); }
    let word = |off: usize| -> Result<u32> {
        let bytes: [u8; SWAP_HEADER_U32_BYTES] = page.get(off..off + SWAP_HEADER_U32_BYTES).ok_or(SwapError::Inval)?.try_into().map_err(|_| SwapError::Inval)?;
        Ok(u32::from_le_bytes(bytes))
    };
    if word(SWAP_HEADER_VERSION_OFFSET)? != SWAPSPACE2_VERSION { return Err(SwapError::Inval); }
    let last_page = word(SWAP_HEADER_LAST_PAGE_OFFSET)? as u64;
    if last_page < FIRST_DATA_PAGE || last_page >= pages { return Err(SwapError::Inval); }
    let bad_count = word(SWAP_HEADER_BAD_PAGE_COUNT_OFFSET)? as usize;
    let bad_end = SWAP_HEADER_BAD_PAGES_OFFSET.checked_add(bad_count.checked_mul(SWAP_HEADER_U32_BYTES).ok_or(SwapError::Inval)?).ok_or(SwapError::Inval)?;
    if bad_end > magic_at { return Err(SwapError::Inval); }
    let mut bad_pages = Vec::new();
    bad_pages.try_reserve_exact(bad_count).map_err(|_| SwapError::NoMem)?;
    for index in 0..bad_count {
        let bad = word(SWAP_HEADER_BAD_PAGES_OFFSET + index * SWAP_HEADER_U32_BYTES)?;
        if (bad as u64) < FIRST_DATA_PAGE || (bad as u64) > last_page || bad_pages.contains(&bad) { return Err(SwapError::Inval); }
        bad_pages.push(bad);
    }
    let slots = usize::try_from(last_page.checked_add(1).ok_or(SwapError::Inval)?).map_err(|_| SwapError::Inval)?;
    Ok(SwapLayout { slots, bad_pages })
}

fn activate_inner(name: String, display_name: String, backing: SwapBacking,
                  device: Arc<dyn BlockDevice>, claimed: bool, priority: Option<i32>,
                  discard: SwapDiscard, layout: SwapLayout) -> Result<u8> {
    let block_size = device.block_size() as u64;
    let page_size = hal::PAGE_SIZE_BYTES;
    if block_size == 0 || page_size % block_size != 0 { return Err(SwapError::Inval); }
    let blocks_per_page = u32::try_from(page_size / block_size).map_err(|_| SwapError::Inval)?;
    let mut reserved = layout.bad_pages;
    reserved.sort_unstable();
    let discard = discard.for_device(device.supports_discard());
    let mut area = Area { name, display_name, backing, claimed, draining: false, priority: DEFAULT_PRIORITY, discard, device: device.clone(), blocks_per_page,
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
    if area.draining { return Err(SwapError::Busy); }
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

/// Store one complete anonymous page and return its canonical PTE identity.
/// The slot remains reserved while I/O runs, so no concurrent page-out can use
/// it; only successful writes become visible as `Used`.
/// # C: O(area slots + page I/O)
pub fn store_page(page: &[u8], memcg: u64) -> Result<SwapEntry> {
    if page.len() != hal::PAGE_SIZE_BYTES as usize { return Err(SwapError::Inval); }
    let (kind, offset, device, start_block, len_blocks) = {
        let mut areas = AREAS.lock();
        let priority = areas.areas.iter().flatten()
            .filter(|area| !area.draining && area.has_free_slot())
            .map(|area| area.priority).max().ok_or(SwapError::NoSpace)?;
        let start = areas.rotation_start(priority);
        let kind = (0..SWAP_AREA_COUNT).map(|delta| (start + delta) % SWAP_AREA_COUNT)
            .find(|kind| areas.areas[*kind].as_ref().is_some_and(|area|
                !area.draining && area.priority == priority && area.has_free_slot()))
            .ok_or(SwapError::NoSpace)?;
        areas.advance_rotation(priority, kind)?;
        let area = areas.areas[kind].as_mut().ok_or(SwapError::NoSuchArea)?;
        let offset = area.next_free_slot().ok_or(SwapError::NoSpace)?;
        area.set_slot(offset, Slot::Writing)?;
        (kind as u8, offset as u64, area.device.clone(), area.page_block(offset as u64)?, area.blocks_per_page)
    };
    let mut request = BlockRequest::new_write(start_block, len_blocks, page.to_vec());
    if let Err(error) = device.submit_sync(&mut request) {
        let mut areas = AREAS.lock();
        if let Some(area) = areas.areas.get_mut(kind as usize).and_then(Option::as_mut) {
            if area.slot(offset as usize) == Some(Slot::Writing) { area.set_slot(offset as usize, Slot::Free)?; }
        }
        return Err(error.into());
    }
    let mut areas = AREAS.lock();
    let area = areas.areas.get_mut(kind as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
    if area.slot(offset as usize) != Some(Slot::Writing) { return Err(SwapError::Io); }
    area.set_slot(offset as usize, Slot::Used { refs: INITIAL_SLOT_PTE_REFS, memcg })?;
    SwapEntry::new(kind, offset).ok_or(SwapError::Inval)
}

/// Read a complete swapped page without releasing its slot. The fault handler
/// frees it only after it has installed the replacement present PTE.
/// # C: O(page I/O)
pub fn load_page(entry: SwapEntry, page: &mut [u8]) -> Result<()> {
    if page.len() != hal::PAGE_SIZE_BYTES as usize { return Err(SwapError::Inval); }
    let (device, start_block, len_blocks) = {
        let areas = AREAS.lock();
        let area = areas.areas.get(entry.kind() as usize).and_then(Option::as_ref).ok_or(SwapError::NoSuchArea)?;
        if !matches!(area.slot(entry.offset() as usize), Some(Slot::Used { .. })) { return Err(SwapError::Inval); }
        (area.device.clone(), area.page_block(entry.offset())?, area.blocks_per_page)
    };
    let mut request = BlockRequest::new_read(start_block, len_blocks, device.block_size());
    device.submit_sync(&mut request).map_err(SwapError::from)?;
    if request.buffer.len() != page.len() { return Err(SwapError::Io); }
    page.copy_from_slice(&request.buffer);
    Ok(())
}

/// Add one PTE reference to a shared swapped page. Fork/pageout uses this for
/// every mapping after the first; the slot stays live until every PTE is gone.
/// # C: O(1)
pub fn retain_page(entry: SwapEntry) -> Result<()> {
    let mut areas = AREAS.lock();
    let area = areas.areas.get_mut(entry.kind() as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
    // A fork must not publish a new child PTE into an area swapoff has made
    // unavailable.  The clone path handles this Busy result by restoring the
    // parent leaf and retrying from RAM, preserving the Linux drain contract.
    if area.draining { return Err(SwapError::Busy); }
    match area.slot(entry.offset() as usize) {
        Some(Slot::Used { refs, memcg }) => {
            area.set_slot(entry.offset() as usize,
                Slot::Used { refs: refs.checked_add(1).ok_or(SwapError::NoSpace)?, memcg })
        }
        _ => Err(SwapError::Inval),
    }
}

/// Number of live swap PTEs naming `entry`.  This is deliberately separate
/// from block I/O and slot-state ownership: it is the swap analogue of a RAM
/// frame's `PageMeta::mapcount`, and is the sole source for shared-swap PSS.
/// # C: O(1)
pub fn pte_mapcount(entry: SwapEntry) -> Result<u32> {
    let areas = AREAS.lock();
    let area = areas.areas.get(entry.kind() as usize).and_then(Option::as_ref).ok_or(SwapError::NoSuchArea)?;
    match area.slot(entry.offset() as usize) {
        Some(Slot::Used { refs, .. }) => Ok(refs),
        _ => Err(SwapError::Inval),
    }
}

/// Drop one PTE reference after its data has been made resident again or the
/// swapped PTE is unmapped. The slot is reusable only after its final PTE.
/// # C: O(1)
pub fn free_page(entry: SwapEntry) -> Result<()> {
    let release = {
        let mut areas = AREAS.lock();
        let area = areas.areas.get_mut(entry.kind() as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
        match area.slot(entry.offset() as usize) {
            Some(Slot::Used { refs: INITIAL_SLOT_PTE_REFS, memcg }) => {
                area.set_slot(entry.offset() as usize, Slot::Releasing)?;
                Some((area.device.clone(), area.page_block(entry.offset())?, area.blocks_per_page, area.discard, memcg))
            }
            Some(Slot::Used { refs, memcg }) => {
                area.set_slot(entry.offset() as usize, Slot::Used { refs: refs - 1, memcg })?;
                None
            }
            _ => return Err(SwapError::Inval),
        }
    };
    let Some((device, start_block, len_blocks, policy, memcg)) = release else { return Ok(()); };
    let result = device.swap_slot_free_notify(start_block, len_blocks).map_err(SwapError::from);
    let mut areas = AREAS.lock();
    let area = areas.areas.get_mut(entry.kind() as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
    if area.slot(entry.offset() as usize) != Some(Slot::Releasing) { return Err(SwapError::Io); }
    area.set_slot(entry.offset() as usize, Slot::Free)?;
    cgroup::uncharge_swap(memcg, hal::PAGE_SIZE_BYTES);
    drop(areas);
    if policy.pages() { let _ = discard::discard_range(device.as_ref(), start_block, len_blocks); }
    result
}

/// Cgroup owning the anonymous contents of `entry`. The charge remains with
/// that memcg when a process moves or fork adds PTE references. # C: O(1)
pub fn memcg(entry: SwapEntry) -> Result<u64> {
    let areas = AREAS.lock();
    let area = areas.areas.get(entry.kind() as usize).and_then(Option::as_ref).ok_or(SwapError::NoSuchArea)?;
    match area.slot(entry.offset() as usize) {
        Some(Slot::Used { memcg, .. }) => Ok(memcg),
        _ => Err(SwapError::Inval),
    }
}

/// Snapshot active swap areas for `/proc/swaps`, `sysinfo`, and `meminfo`.
/// # C: O(areas + slots)
pub fn snapshot() -> Vec<AreaInfo> {
    let areas = AREAS.lock();
    areas.areas.iter().enumerate().filter_map(|(kind, area)| area.as_ref().map(|area| AreaInfo {
        name: area.name.clone(), kind: kind as u8,
        display_name: area.display_name.clone(), backing: area.backing,
        pages: (area.slot_count - area.reserved.len() - FIRST_DATA_PAGE as usize) as u64,
        used_pages: area.used_slots(),
        priority: area.priority,
    })).collect()
}

/// Find the active area by backing block device name.
/// # C: O(areas)
pub fn kind_for_name(name: &str) -> Option<u8> {
    AREAS.lock().areas.iter().position(|area| area.as_ref().is_some_and(|area| area.name == name)).map(|kind| kind as u8)
}

#[cfg(test)]
mod tests;
