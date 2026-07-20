//! Optional Linux `CONFIG_ZRAM_MEMORY_TRACKING` debugfs hierarchy.
//!
//! `zram/` resolves its children from zram-control on every lookup/readdir;
//! `block_state` renders directly from each device's canonical slot table.

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::file_ops::FileOps;
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::{default_inode_ops, mk_mode};
use vfs::{DirContext, FileType, Ino, InodeRef, KResult, VfsError};

/// Linux debugfs directory permissions.
const DEBUG_DIR_MODE: u16 = 0o755;
/// Linux zram `block_state` is root-readable only.
const BLOCK_STATE_MODE: u16 = 0o400;
/// Stable debugfs inode ranges, separate for root, device, and leaf nodes.
const ZRAM_ROOT_INO: Ino = 0x7a72_0000;
const ZRAM_DEVICE_INO_BASE: Ino = 0x7a72_1000;
const ZRAM_BLOCK_STATE_INO_BASE: Ino = 0x7a72_2000;
/// Widths are the Linux `read_block_state` text ABI, not presentation choice.
const BLOCK_STATE_NUMBER_WIDTH: usize = 12;
const BLOCK_STATE_SUBSECOND_DIGITS: usize = 6;
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;
const NANOSECONDS_PER_MICROSECOND: u64 = 1_000;
const ZRAM_DEVICE_PREFIX: &str = "zram";
const BLOCK_STATE_LEAF: &str = "block_state";
const FIRST_DIRECTORY_COOKIE: u64 = 1;

/// Build the optional `/sys/kernel/debug/zram` root. # C: O(1)
pub fn register() {
    crate::register_debug("/sys/kernel/debug/zram", make_root_inode());
}

/// Resolve the `zramN` suffix without accepting arbitrary debugfs names.
/// # C: O(name length)
fn device_index(name: &str) -> Option<u32> { name.strip_prefix(ZRAM_DEVICE_PREFIX)?.parse().ok() }

/// zram's dynamic debugfs root. Device existence comes from zram-control's
/// one authoritative device table rather than a debugfs-side registry.
struct ZramRootOps;
impl vfs::InodeOps for ZramRootOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let index = device_index(name).ok_or(VfsError::Enoent)?;
        let zram = drv_zram::by_index(index).ok_or(VfsError::Enoent)?;
        Ok(make_device_inode(index, zram))
    }
}
impl FileOps for ZramRootOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let indices = drv_zram::indices();
        let mut position = ctx.pos as usize;
        while position < indices.len() {
            let index = indices[position];
            let name = format!("{ZRAM_DEVICE_PREFIX}{index}");
            let next = u64::try_from(position).unwrap_or(u64::MAX).saturating_add(FIRST_DIRECTORY_COOKIE);
            if !ctx.emit(&name, inode.lookup(&name)?.ino(), FileType::Directory, next) { return Ok(()); }
            position += 1;
        }
        Ok(())
    }
}

/// One live zram device directory. Retaining the `Arc` matches an open Linux
/// debugfs file: hot removal hides future lookup but does not invalidate it.
struct ZramDeviceData { zram: Arc<drv_zram::Zram> }
struct ZramDeviceOps;
impl vfs::InodeOps for ZramDeviceOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        if name != BLOCK_STATE_LEAF { return Err(VfsError::Enoent); }
        let data = inode.private::<ZramDeviceData>().ok_or(VfsError::Einval)?;
        Ok(make_block_state_inode(Arc::clone(&data.zram), inode.ino()))
    }
}
impl FileOps for ZramDeviceOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        if ctx.pos != 0 { return Ok(()); }
        let leaf = inode.lookup(BLOCK_STATE_LEAF)?;
        let _ = ctx.emit(BLOCK_STATE_LEAF, leaf.ino(), FileType::Regular, FIRST_DIRECTORY_COOKIE);
        Ok(())
    }
}

/// Per-open-independent data for one `block_state` inode.
struct BlockStateData { zram: Arc<drv_zram::Zram> }
struct BlockStateOps;
impl FileOps for BlockStateOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<BlockStateData>().ok_or(VfsError::Einval)?;
        let body = render_block_state(&data.zram)?;
        Ok(read_window(&body, off, buf))
    }
}

/// Copy one dynamic text window, returning EOF after the current rendering.
/// # C: O(buffer length)
fn read_window(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let Ok(off) = usize::try_from(off) else { return 0; };
    let Some(available) = body.get(off..) else { return 0; };
    let count = available.len().min(buf.len());
    buf[..count].copy_from_slice(&available[..count]);
    count
}

/// Render current state using the exact upstream six-flag order: `swhirn`.
/// Only allocated pages are listed, just as Linux's `zram_allocated` filter.
/// # C: O(allocated zram pages)
fn render_block_state(zram: &drv_zram::Zram) -> KResult<Vec<u8>> {
    let records = zram.block_states().map_err(|_| VfsError::Einval)?;
    let mut body = Vec::new();
    body.try_reserve(records.len().saturating_mul(BLOCK_STATE_NUMBER_WIDTH)).map_err(|_| VfsError::Enomem)?;
    for record in records {
        let seconds = record.access_ns / NANOSECONDS_PER_SECOND;
        let micros = record.access_ns % NANOSECONDS_PER_SECOND / NANOSECONDS_PER_MICROSECOND;
        let flags = [
            flag(record.same, b's'), flag(record.written_back, b'w'), flag(record.huge, b'h'),
            flag(record.idle, b'i'), flag(record.recompressed, b'r'), flag(record.incompressible, b'n'),
        ];
        body.extend_from_slice(format!("{index:>width$} {seconds:>width$}.{micros:0digits$} {flags}\n",
            index = record.index, flags = core::str::from_utf8(&flags).expect("ASCII zram block-state flags"),
            width = BLOCK_STATE_NUMBER_WIDTH, digits = BLOCK_STATE_SUBSECOND_DIGITS).as_bytes());
    }
    Ok(body)
}

/// Render one upstream state letter or its absent marker. # C: O(1)
const fn flag(set: bool, letter: u8) -> u8 { if set { letter } else { b'.' } }

/// Build the dynamic root directory inode. # C: O(1)
fn make_root_inode() -> InodeRef {
    InodeBuilder::new(ZRAM_ROOT_INO, mk_mode(FileType::Directory, DEBUG_DIR_MODE),
        Arc::new(ZramRootOps), Arc::new(ZramRootOps)).build()
}

/// Build one dynamic zram device directory inode. # C: O(1)
fn make_device_inode(index: u32, zram: Arc<drv_zram::Zram>) -> InodeRef {
    let ino = ZRAM_DEVICE_INO_BASE + Ino::from(index);
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DEBUG_DIR_MODE), Arc::new(ZramDeviceOps), Arc::new(ZramDeviceOps))
        .private(Arc::new(ZramDeviceData { zram })).build()
}

/// Build one dynamic block-state leaf inode. # C: O(1)
fn make_block_state_inode(zram: Arc<drv_zram::Zram>, device_ino: Ino) -> InodeRef {
    let index = device_ino.saturating_sub(ZRAM_DEVICE_INO_BASE);
    InodeBuilder::new(ZRAM_BLOCK_STATE_INO_BASE + index, mk_mode(FileType::Regular, BLOCK_STATE_MODE),
        default_inode_ops(), Arc::new(BlockStateOps)).private(Arc::new(BlockStateData { zram })).build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use block::BlockDevice;

    const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
    const FIRST_BLOCK: u64 = 0;

    #[test]
    fn block_state_path_enumerates_live_zram_and_renders_current_slot_flags() {
        register();
        let index = drv_zram::hot_add().expect("hot-add zram");
        let zram = drv_zram::by_index(index).expect("live zram");
        zram.set_disksize(PAGE_BYTES).expect("configure zram");
        let blocks = u32::try_from(PAGE_BYTES / u64::from(drv_zram::ZRAM_BLOCK_SIZE)).expect("page blocks");
        let mut request = block::BlockRequest::new_write(FIRST_BLOCK, blocks, alloc::vec![0; PAGE_BYTES as usize]);
        zram.submit_sync(&mut request).expect("write same-filled zram page");

        let root = crate::debug_root().lookup_path("zram").expect("debugfs zram root");
        let device = root.lookup(&format!("{ZRAM_DEVICE_PREFIX}{index}")).expect("live zram debugfs directory");
        let inode = device.lookup(BLOCK_STATE_LEAF).expect("debugfs block_state path");
        let mut bytes = [0; 128];
        let count = inode.read(0, &mut bytes).expect("read block state");
        let text = core::str::from_utf8(&bytes[..count]).expect("ASCII block-state ABI");
        assert!(text.contains("s....."), "same-filled page uses Linux state order: {text}");
        assert_eq!(inode.read(count as u64, &mut bytes).expect("read block-state EOF"), 0);
        let mut discard = block::BlockRequest::new_discard(FIRST_BLOCK, blocks);
        zram.submit_sync(&mut discard).expect("discard tracked zram page");
        assert_eq!(inode.read(0, &mut bytes).expect("read current block state"), 0,
            "a block_state read renders the canonical table at read time, not an open-time snapshot");
        drv_zram::hot_remove(index).expect("remove test zram");
    }

    #[test]
    fn block_state_directory_hides_removed_device_without_debugfs_registry_state() {
        register();
        let index = drv_zram::hot_add().expect("hot-add zram");
        let root = crate::debug_root().lookup_path("zram").expect("debugfs zram root");
        let name = format!("{ZRAM_DEVICE_PREFIX}{index}");
        assert!(root.lookup(&name).is_ok());
        drv_zram::hot_remove(index).expect("remove test zram");
        assert!(matches!(root.lookup(&name), Err(VfsError::Enoent)));
    }
}
