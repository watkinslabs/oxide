//! Shared hosted-test support: bring up a global PMM backed by a real host
//! allocation so the ext4 D8 frame store (`alloc_object_frame`/`frame_ptr`/
//! `dec_object_ref_and_maybe_free_frame`) operates on valid memory in
//! `cargo test`. The HHDM mapping is the identity-with-offset `hhdm + pa`,
//! with `hhdm` set to a leaked host buffer base so `frame_ptr(pa) = buf + pa`.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use std::sync::Once;

use boot_info::{BootInfo, BootMemKind, BootMemRegion};
use vfs::fs::FileSystem;
use vfs::{InodeRef, SimpleSuperOps, SuperBlock, SuperOps};

/// 64 MiB hosted pool — ample for any fixture file's pages plus the buddy
/// bitmaps carved from the front.
const POOL: usize = 64 * 1024 * 1024;

/// Initialise the process-global PMM once (cargo runs each integration test
/// file as its own process, so this Once is per-binary). After this, the ext4
/// frame store's PMM calls resolve against real host memory.
pub fn boot_hosted_pmm() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let layout = std::alloc::Layout::from_size_align(POOL, 4096).unwrap();
        // SAFETY: non-zero, 4 KiB-aligned layout; leaked for the test process.
        let buf = unsafe { std::alloc::alloc_zeroed(layout) } as u64;
        assert!(buf != 0, "host pool alloc failed");
        let regions = [BootMemRegion { base_pa: 0, len: POOL as u64, kind: BootMemKind::Usable }];
        let info = BootInfo {
            memmap_count: 1,
            memmap_ptr: regions.as_ptr(),
            seed: [0u8; 32],
            boot_ns: 0,
            rsdp_pa: 0,
            hhdm_offset: buf,           // page_ptr(pfn) = buf + pfn*4096
            smp_info_array: 0,
            smp_count: 0,
            bsp_lapic_id: 0,
            _pad: 0,
        };
        // SAFETY: regions slice outlives the call; hhdm_offset is the live base
        // of a Usable host pool; single-threaded init under Once.
        unsafe { pmm::setup::init_from_boot_info(&info).expect("pmm init"); }
        pmm::setup::init_page_meta((POOL as u64) / 4096);
    });
}

/// Build a hosted ext4 test superblock without using removed backend authority.
pub fn realize_sb(fs: Arc<dyn FileSystem>, root: Option<InodeRef>, dev: u64, s_id: String) -> Arc<SuperBlock> {
    let root = root.or_else(|| fs.root());
    let s_op: Arc<dyn SuperOps> = fs.super_ops().unwrap_or_else(|| {
        Arc::new(SimpleSuperOps {
            magic: fs.magic(),
            block_size: fs.block_size(),
            options: fs.show_options(),
        })
    });
    let ty: Arc<dyn vfs::FileSystemType> =
        vfs::fs::FsType::new(fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _, _| unreachable!("test fs type is not mounted through ->mount")));
    let sb = SuperBlock::from_ops(ty, s_op, root, fs.magic(), dev, fs.block_size(), s_id, Arc::new(()));
    fs.set_sb(Arc::downgrade(&sb)).expect("test ext4 set_sb");
    if let Some(name) = fs.sysfs_name() { sb.set_sysfs_name(&name); }
    sb
}

/// Fallible hosted realization path matching the VFS fill-super boundary.
pub fn realize_sb_result(fs: Arc<dyn FileSystem>, root: Option<InodeRef>, _dev: u64, s_id: String) -> vfs::KResult<Arc<SuperBlock>> {
    let root = root.or_else(|| fs.root());
    let ty: Arc<dyn vfs::FileSystemType> =
        vfs::fs::FsType::new(fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _, _| unreachable!("test fs type is not mounted through ->mount")));
    vfs::fs::superblock_from_filesystem(ty, fs, root, s_id, 0)
}

/// Fallible hosted realization with `SB_RDONLY` set before `FileSystem::set_sb`.
pub fn realize_sb_readonly_result(fs: Arc<dyn FileSystem>, root: Option<InodeRef>, dev: u64, s_id: String) -> vfs::KResult<Arc<SuperBlock>> {
    let root = root.or_else(|| fs.root());
    let s_op: Arc<dyn SuperOps> = fs.super_ops().unwrap_or_else(|| {
        Arc::new(SimpleSuperOps {
            magic: fs.magic(),
            block_size: fs.block_size(),
            options: fs.show_options(),
        })
    });
    let ty: Arc<dyn vfs::FileSystemType> =
        vfs::fs::FsType::new(fs.name(), fs.magic(), fs.fs_flags(), Box::new(|_, _, _, _, _| unreachable!("test fs type is not mounted through ->mount")));
    let sb = SuperBlock::from_ops(ty, s_op, root, fs.magic(), dev, fs.block_size(), s_id, Arc::new(()));
    sb.set_readonly(true);
    fs.set_sb(Arc::downgrade(&sb))?;
    if let Some(name) = fs.sysfs_name() { sb.set_sysfs_name(&name); }
    Ok(sb)
}
