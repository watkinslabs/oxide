//! zram-specific `/sys/block/zramN` attributes and stores.

use alloc::vec::Vec;

use vfs::{FileType, KResult, VfsError};

use crate::kobject::{AttrGroup, Attribute};
use crate::{RO_PERM, RW_PERM, WO_PERM};

/// Linux `debug_stat` pool identifier for the single zram metadata pool.
const DEBUG_STAT_POOL_ID: u8 = 0;
/// Linux `debug_stat` formats `miss_free` with `%8llu`.
const DEBUG_STAT_MISS_FREE_COLUMN_WIDTH: usize = 8;
/// A sysfs `reset` value must be nonzero according to the Linux zram ABI.
const RESET_MINIMUM_VALUE: u16 = 1;
/// Linux text request that clears the `mem_used_max` high-water mark.
const MEM_USED_MAX_RESET_TEXT: &str = "0";

const ATTRS: &[Attribute] = &[
    Attribute { name: "size", mode: RO_PERM }, Attribute { name: "ro", mode: RO_PERM },
    Attribute { name: "removable", mode: RO_PERM }, Attribute { name: "dev", mode: RO_PERM },
    Attribute { name: "uevent", mode: RW_PERM }, Attribute { name: "disksize", mode: RW_PERM },
    Attribute { name: "initstate", mode: RO_PERM }, Attribute { name: "comp_algorithm", mode: RW_PERM },
    Attribute { name: "recomp_algorithm", mode: RW_PERM }, Attribute { name: "recompress", mode: WO_PERM },
    Attribute { name: "algorithm_params", mode: WO_PERM }, Attribute { name: "compact", mode: WO_PERM },
    Attribute { name: "mem_limit", mode: WO_PERM }, Attribute { name: "mem_used_max", mode: WO_PERM },
    Attribute { name: "mm_stat", mode: RO_PERM }, Attribute { name: "io_stat", mode: RO_PERM },
    Attribute { name: "debug_stat", mode: RO_PERM }, Attribute { name: "backing_dev", mode: RW_PERM },
    Attribute { name: "idle", mode: WO_PERM }, Attribute { name: "writeback", mode: WO_PERM },
    Attribute { name: "bd_stat", mode: RO_PERM }, Attribute { name: "writeback_limit", mode: RW_PERM },
    Attribute { name: "writeback_batch_size", mode: RW_PERM },
    Attribute { name: "writeback_limit_enable", mode: RW_PERM },
    Attribute { name: "compressed_writeback", mode: RW_PERM }, Attribute { name: "reset", mode: WO_PERM },
];

static GROUP: AttrGroup = AttrGroup { attrs: ATTRS };

/// Whether `name` resolves to one live zram block device. # C: O(devices)
pub(super) fn is_zram(name: &str) -> bool { drv_zram::by_name(name).is_some() }

/// zram's per-disk default attribute group. # C: O(1)
pub(super) fn group() -> &'static AttrGroup { &GROUP }

/// Render a zram-owned leaf, leaving generic block leaves to the caller.
/// # C: O(1)
pub(super) fn show(disk: &block::registry::Disk, leaf: &str) -> Option<Vec<u8>> {
    let zram = drv_zram::by_name(&disk.name)?;
    let st = zram.stats();
    match leaf {
        "disksize" => Some(alloc::format!("{}\n", st.disksize).into_bytes()),
        "initstate" => Some(alloc::format!("{}\n", zram.initialized() as u8).into_bytes()),
        "comp_algorithm" => Some(alloc::format!("{}\n", zram.algorithms()).into_bytes()),
        "recomp_algorithm" => Some(zram.recompression_algorithms().into_bytes()),
        "mm_stat" => Some(alloc::format!("{} {} {} {} {} {} {} {} {}\n", st.orig_data_size, st.compr_data_size, st.mem_used, st.mem_limit, st.mem_used_max, st.same_pages, st.pages_compacted, st.huge_pages, st.huge_pages_since).into_bytes()),
        "io_stat" => Some(alloc::format!("{} {} {} {}\n", st.failed_reads, st.failed_writes, st.invalid_io, st.notify_free).into_bytes()),
        "debug_stat" => Some(alloc::format!("version: {}\n{} {:>width$}\n", drv_zram::ZRAM_DEBUG_STAT_VERSION,
            DEBUG_STAT_POOL_ID, st.miss_free, width = DEBUG_STAT_MISS_FREE_COLUMN_WIDTH).into_bytes()),
        "backing_dev" => Some(match zram.backing_dev() {
            Some(path) => alloc::format!("{}\n", path).into_bytes(), None => b"none\n".to_vec(),
        }),
        "bd_stat" => {
            let units = hal::PAGE_SIZE_BYTES / drv_zram::ZRAM_WRITEBACK_ACCOUNTING_BYTES;
            Some(alloc::format!("{} {} {}\n", st.backing_pages * units, st.backing_reads * units, st.backing_writes * units).into_bytes())
        }
        "writeback_limit" => Some(alloc::format!("{}\n", st.writeback_limit).into_bytes()),
        "writeback_batch_size" => Some(alloc::format!("{}\n", st.writeback_batch_size).into_bytes()),
        "writeback_limit_enable" => Some(alloc::format!("{}\n", st.writeback_limit_enable as u8).into_bytes()),
        "compressed_writeback" => Some(alloc::format!("{}\n", st.compressed_writeback as u8).into_bytes()),
        _ => None,
    }
}

fn error(error: block::BlockError) -> VfsError {
    match error {
        block::BlockError::Eagain => VfsError::Eagain,
        block::BlockError::Ebusy => VfsError::Ebusy,
        block::BlockError::Enomem => VfsError::Enomem,
        block::BlockError::Enospc => VfsError::Enospc,
        block::BlockError::Enxio => VfsError::Enxio,
        _ => VfsError::Einval,
    }
}

/// Apply zram compressor parameters. Kernel sysfs writes resolve `dict=` in
/// the writer's VFS context; hosted unit tests exercise the driver-only ABI.
#[cfg(target_os = "oxide-kernel")]
fn set_algorithm_params(zram: &drv_zram::Zram, value: &str) -> KResult<()> {
    match super::zram_dictionary::dictionary_path(value) {
        Some(path) => {
            zram.reset_algorithm_params_text(value).map_err(error)?;
            zram.set_algorithm_params_with_dictionary_text(value, super::zram_dictionary::read_dictionary(path)?).map_err(error)
        }
        None => zram.set_algorithm_params_text(value).map_err(error),
    }
}

/// Resolve `backing_dev` through the writer's real root/cwd and credentials,
/// then pass the resulting canonical block identity into the zram owner.
#[cfg(target_os = "oxide-kernel")]
fn set_backing_dev(zram: &drv_zram::Zram, value: &str) -> KResult<()> {
    let context = sched::live::current_vfs_lookup_context().ok_or(VfsError::Enoent)?;
    let path = vfs::path_lookup_at_root_cred(
        context.start.dentry, context.start.mnt_id,
        context.root.dentry, context.root.mnt_id,
        value, vfs::LookupFlags { beneath: context.beneath, ..Default::default() },
        sched::cred::current_vfs_cred(),
    )?;
    if path.inode.file_type() != FileType::BlockDev { return Err(VfsError::Enotblk); }
    let disk = block::registry::by_dev(path.inode.rdev()).ok_or(VfsError::Enxio)?;
    let display = vfs::mount::render_path_for_mount(path.mnt_id, &path.dentry);
    zram.set_backing_disk(display, disk).map_err(error)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn set_backing_dev(zram: &drv_zram::Zram, value: &str) -> KResult<()> {
    zram.set_backing_dev_text(value).map_err(error)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn set_algorithm_params(zram: &drv_zram::Zram, value: &str) -> KResult<()> {
    zram.set_algorithm_params_text(value).map_err(error)
}

#[cfg(feature = "debug-zram")]
fn trace_store(attr: &str, value: &str) {
    klog::write_raw(b"[ZRAM-SYSFS] "); klog::write_raw(attr.as_bytes());
    klog::write_raw(b"="); klog::write_raw(value.as_bytes()); klog::write_raw(b"\n");
}

/// Store one zram-specific attribute. `None` lets generic `uevent` handling
/// proceed; every other result is the zram ABI result. # C: O(driver action)
pub(super) fn store(name: &str, attr: &str, buf: &[u8]) -> Option<KResult<usize>> {
    let zram = drv_zram::by_name(name)?;
    let value = match core::str::from_utf8(buf) { Ok(value) => value.trim(), Err(_) => return Some(Err(VfsError::Einval)) };
    #[cfg(feature = "debug-zram")]
    trace_store(attr, value);
    // B1347: the disksize store is where the boot heap-corruptor writes garbage
    // into a freed block <32 kalloc ops before this call's big allocation carve
    // trips on it. Arm per-op free-list validation now (no-op unless a kalloc
    // diag feature is built) so the stray write is caught within one op and its
    // running context (tid / syscall / in_irq) is named. Arm at mem_limit too
    // (the store 2ms before disksize) to BRACKET whether the free list is
    // already corrupt one store earlier — narrowing the writer's window.
    if matches!(attr, "disksize" | "mem_limit") { kalloc::arm_tight_validate(); }
    // B1347: pinpoint the process-context stray write in the disksize call chain.
    if attr == "disksize" { kalloc::checkpoint(b"store-enter"); }
    let result = match attr {
        "disksize" => zram.set_disksize_text(value), "mem_limit" => zram.set_mem_limit_text(value),
        "comp_algorithm" => zram.set_algorithm_text(value), "recomp_algorithm" => zram.set_recomp_algorithm_text(value),
        "recompress" => zram.recompress_text(value),
        "algorithm_params" => return Some(set_algorithm_params(&zram, value).map(|()| buf.len())),
        "compact" => zram.compact(), "backing_dev" => return Some(set_backing_dev(&zram, value).map(|()| buf.len())),
        "idle" => zram.mark_idle_text(value), "writeback" => zram.writeback_text(value),
        "writeback_limit" => zram.set_writeback_limit_text(value),
        "writeback_batch_size" => zram.set_writeback_batch_size_text(value),
        "writeback_limit_enable" => zram.set_writeback_limit_enable_text(value),
        "compressed_writeback" => zram.set_compressed_writeback_text(value),
        "reset" => {
            if value.parse::<u16>().ok().filter(|value| *value >= RESET_MINIMUM_VALUE).is_none() { return Some(Err(VfsError::Einval)); }
            // Linux `zram_reset_device` first excludes new block opens and
            // holders, then resets while that disk admission gate is held.
            let gate = match block::registry::try_quiesce(name) {
                Some(gate) => gate,
                None => return Some(Err(VfsError::Ebusy)),
            };
            let result = zram.reset();
            drop(gate);
            result
        }
        "mem_used_max" if value == MEM_USED_MAX_RESET_TEXT => zram.reset_mem_used_max(),
        "uevent" => return None,
        _ => return Some(Err(VfsError::Einval)),
    };
    Some(result.map(|()| buf.len()).map_err(error))
}
