use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::TaskList;

/// Byte offset for complete sysfs attribute reads and writes.
const ATTRIBUTE_START_OFFSET: u64 = 0;
/// Cleared capacity after a successful zram reset.
const RESET_CAPACITY_BLOCKS: u64 = 0;
/// Initial byte used to fill a test read buffer.
const EMPTY_READ_BYTE: u8 = 0;
/// Initial zram state rendered by the Linux `initstate` ABI.
const ZRAM_INITIALIZED_TEXT: &[u8] = b"1\n";
/// Linux exposes both zram memory-accounting controls as write-only files.
const ZRAM_MEMORY_ACCOUNTING_MODE: u16 = crate::WO_PERM;
/// Linux text request that disables the zram memory limit and resets max use.
const ZRAM_ZERO_TEXT: &[u8] = b"0\n";
/// Linux compressed-writeback configuration before zram initialization.
const COMPRESSED_WRITEBACK_ENABLED_TEXT: &[u8] = b"1\n";
/// `compact` is a write-trigger attribute: Linux does not parse its payload.
const COMPACT_TRIGGER_TEXT: &[u8] = b"compact-now\n";
/// Linux rejects zero in-flight writeback requests.
const WRITEBACK_BATCH_SIZE_ZERO_TEXT: &[u8] = b"0\n";
/// Valid nonzero writeback batch size accepted by Linux.
const WRITEBACK_BATCH_SIZE_ONE_TEXT: &[u8] = b"1\n";
/// Linux age-form idle request with no elapsed-age threshold.
const IDLE_ZERO_SECONDS_TEXT: &[u8] = b"0\n";
/// Read buffer capacity for the fixed-width `initstate` text.
const INITSTATE_BUFFER_BYTES: usize = ZRAM_INITIALIZED_TEXT.len();
/// Writes made by Rust's `fs::write` use these Linux open flags.
const SYSFS_GENERATOR_OPEN_FLAGS: vfs::OpenFlags = vfs::OpenFlags::O_WRONLY.union(vfs::OpenFlags::O_TRUNC);
/// Unique registry suffixes keep backing-device fixtures independent.
static BACKING_DEV_TEST_ID: AtomicU32 = AtomicU32::new(0);
/// One PMM page is sufficient for backing-device selection tests.
const BACKING_DEV_PAGE_COUNT: u64 = 1;
/// 512-byte logical zram sectors do not meet Linux's native write-zeroes gate.
const ZRAM_NO_NATIVE_WRITE_ZEROES_SECTORS: u64 = 0;
/// One complete zram page expressed in the device's 512-byte sectors.
const ZRAM_PAGE_BLOCKS: u32 = hal::PAGE_SIZE_BYTES as u32 / drv_zram::ZRAM_BLOCK_SIZE;
/// A request one sector past the configured disk is invalid Linux zram I/O.
const INVALID_ZRAM_BLOCK: u64 = ZRAM_PAGE_BLOCKS as u64;
/// io_stat has four decimal fields: failed reads/writes, invalid I/O, notify_free.
const IO_STAT_INVALID_IO_TEXT: &[u8] = b"0 0 1 0\n";
/// Exact Linux `debug_stat_show()` text for a newly added zram device.
const DEBUG_STAT_EMPTY_TEXT: &[u8] = b"version: 1\n0        0\n";
/// Linux zram queue leaves and their device-topology values.
const ZRAM_QUEUE_ATTRIBUTES: &[(&str, u64)] = &[
    ("logical_block_size", drv_zram::ZRAM_BLOCK_SIZE as u64),
    ("physical_block_size", hal::PAGE_SIZE_BYTES),
    ("minimum_io_size", hal::PAGE_SIZE_BYTES),
    ("optimal_io_size", hal::PAGE_SIZE_BYTES),
    ("max_write_zeroes_sectors", ZRAM_NO_NATIVE_WRITE_ZEROES_SECTORS),
    ("max_write_zeroes_unmap_sectors", ZRAM_NO_NATIVE_WRITE_ZEROES_SECTORS),
];

/// Resolve and write one zram sysfs leaf through the real VFS path walk,
/// matching zram-generator's `fs::write` setup path. # C: O(path components)
fn generator_write(root: &Arc<vfs::Dentry>, path: &str, body: &[u8]) {
    let (inode, dentry) = vfs::path_lookup(root.clone(), root.clone(), path,
        vfs::LookupFlags::default()).expect("resolve zram sysfs leaf");
    let fdt = vfs::FdTable::new();
    let fd = vfs::file::install_open_at(&fdt, inode, dentry, SYSFS_GENERATOR_OPEN_FLAGS,
        0, vfs::FileCred::root(), usize::MAX, None).expect("open zram sysfs leaf with truncation");
    assert_eq!(fdt.get(fd).expect("generator sysfs fd").write(body), Ok(body.len()));
}

#[test]
fn zram_generator_path_writes_keep_each_sysfs_leaf_distinct() {
    let index = drv_zram::hot_add().expect("zram hot-add");
    let name = alloc::format!("zram{}", index);
    let root = make_sys_block_inode();
    let root_dentry = vfs::Dentry::new_root(root);
    let mem_limit_path = alloc::format!("/{}/mem_limit", name);
    let disksize_path = alloc::format!("/{}/disksize", name);
    let (mem_limit, _) = vfs::path_lookup(root_dentry.clone(), root_dentry.clone(), &mem_limit_path,
        vfs::LookupFlags::default()).expect("resolve mem_limit");
    let (disksize, _) = vfs::path_lookup(root_dentry.clone(), root_dentry.clone(), &disksize_path,
        vfs::LookupFlags::default()).expect("resolve disksize");
    assert_ne!(mem_limit.ino(), disksize.ino(), "distinct zram sysfs leaves require distinct inode identities");
    generator_write(&root_dentry, &mem_limit_path, b"0");
    let page_bytes = hal::PAGE_SIZE_BYTES as u64;
    let disksize_text = alloc::format!("{}", page_bytes);
    generator_write(&root_dentry, &disksize_path, disksize_text.as_bytes());
    assert!(drv_zram::by_index(index).expect("live zram").initialized());
    assert!(drv_zram::hot_remove(index).is_ok());
}

#[test]
fn zram_memory_accounting_attributes_have_linux_write_only_modes() {
    for name in ["mem_limit", "mem_used_max"] {
        assert_eq!(zram::group().find(name).expect("zram accounting attribute").mode,
            ZRAM_MEMORY_ACCOUNTING_MODE);
    }
}

#[test]
fn zram_io_stat_reports_invalid_io_in_its_linux_field() {
    let index = drv_zram::hot_add().expect("zram hot-add");
    let name = alloc::format!("zram{}", index);
    let root = make_sys_block_inode();
    let dir = root.lookup(&name).expect("zram disk dir");
    let disksize = dir.lookup("disksize").expect("disksize");
    let size_text = alloc::format!("{}\n", hal::PAGE_SIZE_BYTES);
    assert_eq!(disksize.write(ATTRIBUTE_START_OFFSET, size_text.as_bytes()), Ok(size_text.len()));
    let disk = block::registry::by_name(&name).expect("published zram");
    let mut request = block::BlockRequest::new_read(INVALID_ZRAM_BLOCK, ZRAM_PAGE_BLOCKS, drv_zram::ZRAM_BLOCK_SIZE);
    assert_eq!(disk.dev.submit_sync(&mut request), Err(block::BlockError::Eio));
    let io_stat = dir.lookup("io_stat").expect("io_stat");
    let mut out = [EMPTY_READ_BYTE; IO_STAT_INVALID_IO_TEXT.len()];
    assert_eq!(io_stat.read(ATTRIBUTE_START_OFFSET, &mut out), Ok(IO_STAT_INVALID_IO_TEXT.len()));
    assert_eq!(&out, IO_STAT_INVALID_IO_TEXT);
    assert!(drv_zram::hot_remove(index).is_ok());
}

#[test]
fn zram_debug_stat_matches_linux_fixed_width_sysfs_text() {
    let index = drv_zram::hot_add().expect("zram hot-add");
    let name = alloc::format!("zram{}", index);
    let root = make_sys_block_inode();
    let dir = root.lookup(&name).expect("zram disk dir");
    let debug_stat = dir.lookup("debug_stat").expect("debug_stat");
    let mut out = [EMPTY_READ_BYTE; DEBUG_STAT_EMPTY_TEXT.len()];
    assert_eq!(debug_stat.read(ATTRIBUTE_START_OFFSET, &mut out), Ok(DEBUG_STAT_EMPTY_TEXT.len()));
    assert_eq!(&out, DEBUG_STAT_EMPTY_TEXT);
    assert!(drv_zram::hot_remove(index).is_ok());
}

#[test]
fn zram_queue_limits_publish_linux_page_geometry() {
    let index = drv_zram::hot_add().expect("zram hot-add");
    let name = alloc::format!("zram{}", index);
    let root = make_sys_block_inode();
    let dir = root.lookup(&name).expect("zram disk dir");
    let queue = dir.lookup("queue").expect("zram queue dir");
    for (attribute, value) in ZRAM_QUEUE_ATTRIBUTES {
        let expected = alloc::format!("{}\n", value);
        let mut out = alloc::vec![EMPTY_READ_BYTE; expected.len()];
        let node = queue.lookup(attribute).expect("zram queue attribute");
        assert_eq!(node.read(ATTRIBUTE_START_OFFSET, &mut out), Ok(expected.len()));
        assert_eq!(out, expected.as_bytes());
    }
    assert!(drv_zram::hot_remove(index).is_ok());
}

#[test]
fn zram_sysfs_configures_published_device() {
    let index = drv_zram::hot_add().expect("zram hot-add");
    let name = alloc::format!("zram{}", index);
    let root = make_sys_block_inode();
    let dir = root.lookup(&name).expect("zram disk dir");
    let compressed_writeback = dir.lookup("compressed_writeback").expect("compressed_writeback");
    assert_eq!(compressed_writeback.write(ATTRIBUTE_START_OFFSET, COMPRESSED_WRITEBACK_ENABLED_TEXT), Ok(COMPRESSED_WRITEBACK_ENABLED_TEXT.len()));
    let mut compressed_out = [EMPTY_READ_BYTE; COMPRESSED_WRITEBACK_ENABLED_TEXT.len()];
    assert_eq!(compressed_writeback.read(ATTRIBUTE_START_OFFSET, &mut compressed_out), Ok(COMPRESSED_WRITEBACK_ENABLED_TEXT.len()));
    assert_eq!(&compressed_out, COMPRESSED_WRITEBACK_ENABLED_TEXT);
    let writeback_batch_size = dir.lookup("writeback_batch_size").expect("writeback_batch_size");
    assert_eq!(writeback_batch_size.write(ATTRIBUTE_START_OFFSET, WRITEBACK_BATCH_SIZE_ZERO_TEXT), Err(VfsError::Einval));
    assert_eq!(writeback_batch_size.write(ATTRIBUTE_START_OFFSET, WRITEBACK_BATCH_SIZE_ONE_TEXT), Ok(WRITEBACK_BATCH_SIZE_ONE_TEXT.len()));
    let mut writeback_batch_size_out = [EMPTY_READ_BYTE; WRITEBACK_BATCH_SIZE_ONE_TEXT.len()];
    assert_eq!(writeback_batch_size.read(ATTRIBUTE_START_OFFSET, &mut writeback_batch_size_out), Ok(WRITEBACK_BATCH_SIZE_ONE_TEXT.len()));
    assert_eq!(&writeback_batch_size_out, WRITEBACK_BATCH_SIZE_ONE_TEXT);
    let size = dir.lookup("disksize").expect("disksize");
    let page_bytes = hal::PAGE_SIZE_BYTES as u64;
    let text = alloc::format!("{}\n", page_bytes);
    assert_eq!(size.write(ATTRIBUTE_START_OFFSET, text.as_bytes()), Ok(text.len()));
    let disk = block::registry::by_name(&name).expect("published zram");
    assert_eq!(disk.dev.capacity_blocks(), page_bytes / drv_zram::ZRAM_BLOCK_SIZE as u64);
    let init = dir.lookup("initstate").expect("initstate");
    let mut out = [EMPTY_READ_BYTE; INITSTATE_BUFFER_BYTES];
    assert_eq!(init.read(ATTRIBUTE_START_OFFSET, &mut out), Ok(ZRAM_INITIALIZED_TEXT.len()));
    assert_eq!(&out, ZRAM_INITIALIZED_TEXT);
    let idle = dir.lookup("idle").expect("idle");
    assert_eq!(idle.write(ATTRIBUTE_START_OFFSET, IDLE_ZERO_SECONDS_TEXT), Ok(IDLE_ZERO_SECONDS_TEXT.len()));
    let compact = dir.lookup("compact").expect("compact");
    assert_eq!(compact.write(ATTRIBUTE_START_OFFSET, COMPACT_TRIGGER_TEXT), Ok(COMPACT_TRIGGER_TEXT.len()));
    let mem_limit = dir.lookup("mem_limit").expect("mem_limit");
    assert_eq!(mem_limit.write(ATTRIBUTE_START_OFFSET, ZRAM_ZERO_TEXT), Ok(ZRAM_ZERO_TEXT.len()));
    let mem_used_max = dir.lookup("mem_used_max").expect("mem_used_max");
    assert_eq!(mem_used_max.write(ATTRIBUTE_START_OFFSET, ZRAM_ZERO_TEXT), Ok(ZRAM_ZERO_TEXT.len()));
    assert!(block::registry::claim(&name));
    assert_eq!(dir.lookup("reset").unwrap().write(ATTRIBUTE_START_OFFSET, ZRAM_INITIALIZED_TEXT), Err(VfsError::Ebusy));
    assert!(block::registry::release(&name));
    assert_eq!(dir.lookup("reset").unwrap().write(ATTRIBUTE_START_OFFSET, ZRAM_INITIALIZED_TEXT), Ok(ZRAM_INITIALIZED_TEXT.len()));
    assert_eq!(disk.dev.capacity_blocks(), RESET_CAPACITY_BLOCKS);
    assert!(block::registry::claim(&name));
    assert_eq!(drv_zram::hot_remove(index), Err(block::BlockError::Ebusy));
    assert!(block::registry::release(&name));
    assert!(drv_zram::hot_remove(index).is_ok());
}

#[test]
fn zram_backing_dev_sysfs_uses_canonical_path_and_replaces_before_init() {
    let index = drv_zram::hot_add().expect("zram hot-add");
    let zram_name = alloc::format!("zram{}", index);
    let id = BACKING_DEV_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let first_name = alloc::format!("zram-sysfs-backing-first-{}", id);
    let second_name = alloc::format!("zram-sysfs-backing-second-{}", id);
    let blocks = hal::PAGE_SIZE_BYTES / drv_zram::ZRAM_BLOCK_SIZE as u64 * BACKING_DEV_PAGE_COUNT;
    let first: Arc<dyn block::BlockDevice> = block::MemDisk::<TaskList>::new(drv_zram::ZRAM_BLOCK_SIZE, blocks);
    let second: Arc<dyn block::BlockDevice> = block::MemDisk::<TaskList>::new(drv_zram::ZRAM_BLOCK_SIZE, blocks);
    assert_ne!(block::registry::register(&first_name, first), 0);
    assert_ne!(block::registry::register(&second_name, second), 0);
    let root = make_sys_block_inode();
    let dir = root.lookup(&zram_name).expect("zram disk dir");
    let backing_dev = dir.lookup("backing_dev").expect("backing_dev");
    let first_path = alloc::format!("/dev/{}\n", first_name);
    let second_path = alloc::format!("/dev/{}\n", second_name);
    assert_eq!(backing_dev.write(ATTRIBUTE_START_OFFSET, b"1:0\n"), Err(VfsError::Einval));
    assert_eq!(backing_dev.write(ATTRIBUTE_START_OFFSET, b"/dev/zram-backing-missing\n"), Err(VfsError::Enxio));
    assert_eq!(backing_dev.write(ATTRIBUTE_START_OFFSET, first_path.as_bytes()), Ok(first_path.len()));
    let mut first_out = alloc::vec![EMPTY_READ_BYTE; first_path.len()];
    assert_eq!(backing_dev.read(ATTRIBUTE_START_OFFSET, &mut first_out), Ok(first_path.len()));
    assert_eq!(first_out, first_path.as_bytes());
    assert!(block::registry::is_claimed(&first_name));
    assert_eq!(backing_dev.write(ATTRIBUTE_START_OFFSET, second_path.as_bytes()), Ok(second_path.len()));
    assert!(!block::registry::is_claimed(&first_name));
    assert!(block::registry::is_claimed(&second_name));
    let mut second_out = alloc::vec![EMPTY_READ_BYTE; second_path.len()];
    assert_eq!(backing_dev.read(ATTRIBUTE_START_OFFSET, &mut second_out), Ok(second_path.len()));
    assert_eq!(second_out, second_path.as_bytes());
    let size = dir.lookup("disksize").expect("disksize");
    let size_text = alloc::format!("{}\n", hal::PAGE_SIZE_BYTES);
    assert_eq!(size.write(ATTRIBUTE_START_OFFSET, size_text.as_bytes()), Ok(size_text.len()));
    assert_eq!(backing_dev.write(ATTRIBUTE_START_OFFSET, first_path.as_bytes()), Err(VfsError::Ebusy));
    assert!(drv_zram::hot_remove(index).is_ok());
    assert!(block::registry::unregister(&first_name));
    assert!(block::registry::unregister(&second_name));
}
