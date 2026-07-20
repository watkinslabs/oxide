use super::*;
use alloc::{boxed::Box, vec};
use std::sync::{Mutex, MutexGuard, Once};

static ZRAM_PROVIDER_ONCE: Once = Once::new();
static ZRAM_TEST_PAGES: Mutex<Vec<Box<[u8]>>> = Mutex::new(Vec::new());

fn zram_test_alloc() -> Option<u64> {
    let mut pages = ZRAM_TEST_PAGES.lock().ok()?;
    pages.push(vec![0; hal::PAGE_SIZE_BYTES as usize].into_boxed_slice());
    Some((pages.len() as u64) * hal::PAGE_SIZE_BYTES)
}
fn zram_test_ptr(pa: u64) -> Option<*mut u8> {
    let index = usize::try_from(pa / hal::PAGE_SIZE_BYTES).ok()?.checked_sub(1)?;
    let mut pages = ZRAM_TEST_PAGES.lock().ok()?;
    Some(pages.get_mut(index)?.as_mut_ptr())
}
fn zram_test_release(_pa: u64) {}
fn zram_test_lock(_pa: u64) -> bool { true }
fn zram_test_unlock(_pa: u64) -> bool { true }
fn install_zram_test_provider() {
    ZRAM_PROVIDER_ONCE.call_once(|| {
        drv_zram::install_page_provider(drv_zram::PageProvider::new(
            zram_test_alloc, zram_test_release, zram_test_ptr, zram_test_lock, zram_test_unlock,
        )).unwrap();
    });
}
use block::{BlockRequest, MemDisk};
use sync::TaskList;

const TEST_BLOCK_BYTES: u32 = 512;
const TEST_DEVICE_BLOCKS: u64 = 64;
const REGISTRY_REJECTED_INDEX: u32 = 0;
const FIRST_USABLE_TEST_SLOT: u64 = FIRST_DATA_PAGE + 1;
const TEST_PAGE_BYTE: u8 = 0x5a;
const EMPTY_PAGE_BYTE: u8 = 0;
const TEST_MEMCG: u64 = 1;
const TEST_BAD_PAGE: u32 = FIRST_DATA_PAGE as u32;
const ZRAM_FIXTURE_PAGE_COUNT: u64 = 8;
const SWAP_HEADER_PAGE_COUNT: u64 = 1;
const TEST_BAD_PAGE_COUNT: u64 = 1;
const PAGE_COUNT_LAST_INDEX_DELTA: u64 = 1;
static SWAP_TEST_LOCK: Mutex<()> = Mutex::new(());

fn swap_test_lock() -> MutexGuard<'static, ()> {
    SWAP_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn write_linux_swap_header<D: BlockDevice + ?Sized>(disk: &Arc<D>, bad_pages: &[u32]) {
    let blocks_per_page = (hal::PAGE_SIZE_BYTES / disk.block_size() as u64) as u32;
    let pages = disk.capacity_blocks() / blocks_per_page as u64;
    let mut page = alloc::vec![0u8; hal::PAGE_SIZE_BYTES as usize];
    page[SWAP_HEADER_VERSION_OFFSET..SWAP_HEADER_VERSION_OFFSET + SWAP_HEADER_U32_BYTES].copy_from_slice(&SWAPSPACE2_VERSION.to_le_bytes());
    page[SWAP_HEADER_LAST_PAGE_OFFSET..SWAP_HEADER_LAST_PAGE_OFFSET + SWAP_HEADER_U32_BYTES].copy_from_slice(&((pages - PAGE_COUNT_LAST_INDEX_DELTA) as u32).to_le_bytes());
    page[SWAP_HEADER_BAD_PAGE_COUNT_OFFSET..SWAP_HEADER_BAD_PAGE_COUNT_OFFSET + SWAP_HEADER_U32_BYTES].copy_from_slice(&(bad_pages.len() as u32).to_le_bytes());
    for (index, bad) in bad_pages.iter().enumerate() {
        let off = SWAP_HEADER_BAD_PAGES_OFFSET + index * SWAP_HEADER_U32_BYTES;
        page[off..off + SWAP_HEADER_U32_BYTES].copy_from_slice(&bad.to_le_bytes());
    }
    let magic_at = page.len() - SWAP_MAGIC.len();
    page[magic_at..].copy_from_slice(SWAP_MAGIC);
    let mut request = BlockRequest::new_write(SWAP_HEADER_PAGE, blocks_per_page, page);
    disk.submit_sync(&mut request).unwrap();
}

#[test]
fn shared_swap_fork_and_unmap_pte_mapcount() {
    let _guard = swap_test_lock();
    let disk = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    write_linux_swap_header(&disk, &[TEST_BAD_PAGE]);
    let name = "swap-test";
    assert_ne!(block::registry::register(name, disk), REGISTRY_REJECTED_INDEX);
    let kind = activate_registered(name).unwrap();
    let data = alloc::vec![TEST_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize];
    let entry = store_page(&data, TEST_MEMCG).unwrap();
    assert_eq!(entry.kind(), kind);
    assert_eq!(entry.offset(), FIRST_USABLE_TEST_SLOT);
    assert_eq!(pte_mapcount(entry), Ok(INITIAL_SLOT_PTE_REFS));
    let mut loaded = alloc::vec![EMPTY_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize];
    load_page(entry, &mut loaded).unwrap();
    assert_eq!(loaded, data);
    assert_eq!(snapshot().into_iter().find(|area| area.kind == kind).unwrap().used_pages, INITIAL_SLOT_PTE_REFS as u64);
    retain_page(entry).unwrap();
    assert_eq!(pte_mapcount(entry), Ok(INITIAL_SLOT_PTE_REFS + 1));
    free_page(entry).unwrap();
    assert_eq!(pte_mapcount(entry), Ok(INITIAL_SLOT_PTE_REFS));
    assert_eq!(deactivate(kind), Err(SwapError::Busy));
    free_page(entry).unwrap();
    deactivate(kind).unwrap();
    assert!(block::registry::unregister(name));
}

#[test]
fn draining_area_refuses_fork_reference_before_child_pte_publication() {
    let _guard = swap_test_lock();
    let disk = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    write_linux_swap_header(&disk, &[]);
    let name = "swap-draining-fork";
    assert_ne!(block::registry::register(name, disk), REGISTRY_REJECTED_INDEX);
    let kind = activate_registered(name).unwrap();
    let page = alloc::vec![TEST_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize];
    let entry = store_page(&page, TEST_MEMCG).unwrap();
    assert_eq!(entry.kind(), kind);
    begin_drain(kind).unwrap();
    assert_eq!(retain_page(entry), Err(SwapError::Busy));
    assert_eq!(pte_mapcount(entry), Ok(INITIAL_SLOT_PTE_REFS));
    free_page(entry).unwrap();
    finish_drain(kind).unwrap();
    assert!(block::registry::unregister(name));
}

#[test]
fn activation_rejects_non_swap_disk_without_leaking_claim() {
    let _guard = swap_test_lock();
    let disk = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    let name = "swap-invalid-header";
    assert_ne!(block::registry::register(name, disk), REGISTRY_REJECTED_INDEX);
    assert_eq!(activate_registered(name), Err(SwapError::Inval));
    assert!(!block::registry::is_claimed(name));
    assert!(block::registry::unregister(name));
}

#[test]
fn direct_backing_activation_neither_registers_nor_claims_a_device() {
    let _guard = swap_test_lock();
    let disk = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    write_linux_swap_header(&disk, &[]);
    let name = alloc::string::String::from("ext4-direct-swap-test");
    let device: Arc<dyn BlockDevice> = disk;
    let kind = activate_device_with_priority(name.clone(), device, DEFAULT_PRIORITY).unwrap();
    let data = alloc::vec![TEST_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize];
    let entry = store_page(&data, TEST_MEMCG).unwrap();
    assert_eq!(entry.kind(), kind);
    free_page(entry).unwrap();
    deactivate(kind).unwrap();
    assert!(block::registry::by_name(&name).is_none());
}

#[test]
fn file_backing_records_linux_proc_swaps_identity_and_path() {
    let _guard = swap_test_lock();
    let disk = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    write_linux_swap_header(&disk, &[]);
    let identity = alloc::string::String::from("ext4:test-fsid:test-ino");
    let path = alloc::string::String::from("/var/tmp/swapfile");
    let device: Arc<dyn BlockDevice> = disk;
    let kind = activate_file_with_priority(identity.clone(), path.clone(), device, DEFAULT_PRIORITY).unwrap();
    let info = snapshot().into_iter().find(|area| area.kind == kind).unwrap();
    assert_eq!(info.name, identity);
    assert_eq!(info.display_name, path);
    assert_eq!(info.backing, SwapBacking::File);
    deactivate(kind).unwrap();
}

#[test]
fn snapshot_excludes_header_and_bad_pages_from_capacity() {
    let _guard = swap_test_lock();
    let disk = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    write_linux_swap_header(&disk, &[TEST_BAD_PAGE]);
    let name = "swap-capacity";
    assert_ne!(block::registry::register(name, disk), REGISTRY_REJECTED_INDEX);
    let kind = activate_registered(name).unwrap();
    let info = snapshot().into_iter().find(|area| area.kind == kind).unwrap();
    let blocks_per_page = hal::PAGE_SIZE_BYTES / TEST_BLOCK_BYTES as u64;
    let total_pages = TEST_DEVICE_BLOCKS / blocks_per_page;
    let reserved_pages = SWAP_HEADER_PAGE_COUNT + TEST_BAD_PAGE_COUNT;
    assert_eq!(info.pages, total_pages - reserved_pages);
    assert_eq!(info.used_pages, 0);
    deactivate(kind).unwrap();
    assert!(block::registry::unregister(name));
}

#[test]
fn final_swap_reference_reclaims_zram_slot() {
    let _guard = swap_test_lock();
    install_zram_test_provider();
    let index = drv_zram::hot_add().unwrap();
    let name = alloc::format!("zram{}", index);
    let zram = drv_zram::by_index(index).unwrap();
    zram.set_disksize(hal::PAGE_SIZE_BYTES * ZRAM_FIXTURE_PAGE_COUNT).unwrap();
    write_linux_swap_header(&zram, &[]);
    let kind = activate_registered(&name).unwrap();
    let header_mem = zram.stats().mem_used;
    let mut data = alloc::vec![EMPTY_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize];
    for (index, byte) in data.iter_mut().enumerate() { *byte = index as u8; }
    let entry = store_page(&data, TEST_MEMCG).unwrap();
    assert_eq!(entry.kind(), kind);
    assert_ne!(zram.stats().mem_used, EMPTY_PAGE_BYTE as u64);
    free_page(entry).unwrap();
    assert_eq!(zram.stats().mem_used, header_mem);
    assert_eq!(zram.stats().notify_free, INITIAL_SLOT_PTE_REFS as u64);
    deactivate(kind).unwrap();
    zram.reset().unwrap();
    assert!(drv_zram::hot_remove(index).is_ok());
}

#[test]
fn page_store_prefers_highest_priority_area() {
    let _guard = swap_test_lock();
    const LOW_PRIORITY: i32 = -1;
    const HIGH_PRIORITY: i32 = 1;
    let low = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    let high = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    let low_name = "swap-priority-low";
    let high_name = "swap-priority-high";
    write_linux_swap_header(&low, &[]);
    write_linux_swap_header(&high, &[]);
    assert_ne!(block::registry::register(low_name, low), REGISTRY_REJECTED_INDEX);
    assert_ne!(block::registry::register(high_name, high), REGISTRY_REJECTED_INDEX);
    let low_kind = activate_registered_with_priority(low_name, LOW_PRIORITY).unwrap();
    let high_kind = activate_registered_with_priority(high_name, HIGH_PRIORITY).unwrap();
    let page = alloc::vec![TEST_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize];
    let entry = store_page(&page, TEST_MEMCG).unwrap();
    assert_eq!(entry.kind(), high_kind);
    assert_eq!(snapshot().into_iter().find(|area| area.kind == high_kind).unwrap().priority, HIGH_PRIORITY);
    free_page(entry).unwrap();
    deactivate(low_kind).unwrap();
    deactivate(high_kind).unwrap();
    assert!(block::registry::unregister(low_name));
    assert!(block::registry::unregister(high_name));
}

#[test]
fn equal_explicit_priorities_round_robin_between_areas() {
    let _guard = swap_test_lock();
    const EXPLICIT_PRIORITY: i32 = 7;
    let first = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    let second = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    let first_name = "swap-priority-round-robin-first";
    let second_name = "swap-priority-round-robin-second";
    write_linux_swap_header(&first, &[]);
    write_linux_swap_header(&second, &[]);
    assert_ne!(block::registry::register(first_name, first), REGISTRY_REJECTED_INDEX);
    assert_ne!(block::registry::register(second_name, second), REGISTRY_REJECTED_INDEX);
    let first_kind = activate_registered_with_priority(first_name, EXPLICIT_PRIORITY).unwrap();
    let second_kind = activate_registered_with_priority(second_name, EXPLICIT_PRIORITY).unwrap();
    let page = alloc::vec![TEST_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize];
    let first_entry = store_page(&page, TEST_MEMCG).unwrap();
    let second_entry = store_page(&page, TEST_MEMCG).unwrap();
    assert_eq!(first_entry.kind(), first_kind);
    assert_eq!(second_entry.kind(), second_kind);
    free_page(first_entry).unwrap();
    free_page(second_entry).unwrap();
    deactivate(first_kind).unwrap();
    deactivate(second_kind).unwrap();
    assert!(block::registry::unregister(first_name));
    assert!(block::registry::unregister(second_name));
}

#[test]
fn default_priority_uses_older_area_before_newer_area() {
    let _guard = swap_test_lock();
    let older = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    let newer = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    let older_name = "swap-default-priority-older";
    let newer_name = "swap-default-priority-newer";
    write_linux_swap_header(&older, &[]);
    write_linux_swap_header(&newer, &[]);
    assert_ne!(block::registry::register(older_name, older), REGISTRY_REJECTED_INDEX);
    assert_ne!(block::registry::register(newer_name, newer), REGISTRY_REJECTED_INDEX);
    let older_kind = activate_registered(older_name).unwrap();
    let newer_kind = activate_registered(newer_name).unwrap();
    let areas = snapshot();
    let older_priority = areas.iter().find(|area| area.kind == older_kind).unwrap().priority;
    let newer_priority = areas.iter().find(|area| area.kind == newer_kind).unwrap().priority;
    assert!(older_priority > newer_priority);
    let page = alloc::vec![TEST_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize];
    let first_entry = store_page(&page, TEST_MEMCG).unwrap();
    let second_entry = store_page(&page, TEST_MEMCG).unwrap();
    assert_eq!(first_entry.kind(), older_kind);
    assert_eq!(second_entry.kind(), older_kind);
    free_page(first_entry).unwrap();
    free_page(second_entry).unwrap();
    deactivate(older_kind).unwrap();
    deactivate(newer_kind).unwrap();
    assert!(block::registry::unregister(older_name));
    assert!(block::registry::unregister(newer_name));
}

#[test]
fn duplicate_registered_activation_is_busy_and_releases_extra_claim() {
    let _guard = swap_test_lock();
    let disk = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    let name = "swap-duplicate-activation";
    write_linux_swap_header(&disk, &[]);
    assert_ne!(block::registry::register(name, disk), REGISTRY_REJECTED_INDEX);
    let kind = activate_registered(name).unwrap();
    assert_eq!(activate_registered(name), Err(SwapError::Busy));
    deactivate(kind).unwrap();
    assert!(!block::registry::is_claimed(name));
    assert!(block::registry::unregister(name));
}

#[test]
fn discard_once_zeros_free_swap_area_but_preserves_header() {
    let _guard = swap_test_lock();
    let disk = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    write_linux_swap_header(&disk, &[]);
    let blocks_per_page = (hal::PAGE_SIZE_BYTES / TEST_BLOCK_BYTES as u64) as u32;
    let first_data_block = FIRST_DATA_PAGE * blocks_per_page as u64;
    let mut stale = BlockRequest::new_write(first_data_block, blocks_per_page,
        alloc::vec![TEST_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize]);
    disk.submit_sync(&mut stale).unwrap();
    let name = "swap-discard-once";
    assert_ne!(block::registry::register(name, disk.clone()), REGISTRY_REJECTED_INDEX);
    let kind = activate_registered_with_options(name, None, SwapDiscard::from_swapon(true, true, false)).unwrap();
    let mut freed = BlockRequest::new_read(first_data_block, blocks_per_page, TEST_BLOCK_BYTES);
    disk.submit_sync(&mut freed).unwrap();
    assert!(freed.buffer.iter().all(|byte| *byte == EMPTY_PAGE_BYTE));
    let mut header = BlockRequest::new_read(SWAP_HEADER_PAGE, blocks_per_page, TEST_BLOCK_BYTES);
    disk.submit_sync(&mut header).unwrap();
    assert_eq!(&header.buffer[header.buffer.len() - SWAP_MAGIC.len()..], SWAP_MAGIC);
    deactivate(kind).unwrap();
    assert!(block::registry::unregister(name));
}

#[test]
fn discard_pages_zeros_finally_released_slot() {
    let _guard = swap_test_lock();
    let disk = MemDisk::<TaskList>::new(TEST_BLOCK_BYTES, TEST_DEVICE_BLOCKS);
    write_linux_swap_header(&disk, &[]);
    let name = "swap-discard-pages";
    assert_ne!(block::registry::register(name, disk.clone()), REGISTRY_REJECTED_INDEX);
    let kind = activate_registered_with_options(name, None, SwapDiscard::from_swapon(true, false, true)).unwrap();
    let entry = store_page(&alloc::vec![TEST_PAGE_BYTE; hal::PAGE_SIZE_BYTES as usize], TEST_MEMCG).unwrap();
    let blocks_per_page = (hal::PAGE_SIZE_BYTES / TEST_BLOCK_BYTES as u64) as u32;
    free_page(entry).unwrap();
    let mut freed = BlockRequest::new_read(entry.offset() * blocks_per_page as u64, blocks_per_page, TEST_BLOCK_BYTES);
    disk.submit_sync(&mut freed).unwrap();
    assert!(freed.buffer.iter().all(|byte| *byte == EMPTY_PAGE_BYTE));
    deactivate(kind).unwrap();
    assert!(block::registry::unregister(name));
}

#[test]
fn discard_selector_without_enable_is_ignored_like_linux() {
    assert_eq!(SwapDiscard::from_swapon(false, true, true), SwapDiscard::None);
    assert_eq!(SwapDiscard::from_swapon(true, true, true), SwapDiscard::Once);
    assert_eq!(SwapDiscard::from_swapon(true, false, false), SwapDiscard::Both);
    assert_eq!(SwapDiscard::Both.for_device(false), SwapDiscard::None);
}
