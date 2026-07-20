//! Synthetic sysfs inode layout owned by the sysfs filesystem.
pub(crate) const ROOT: u64 = 0x5100_0001;
pub(crate) const CLASS: u64 = 0x5100_0002;
pub(crate) const KOBJ_ROOT: u64 = 0x5100_1000;
pub(crate) const SYMLINK: u64 = 0x5100_0080;
pub(crate) const ATTR: u64 = 0x5100_2000;
pub(crate) const UEVENT: u64 = 0x5100_3000;
pub(crate) const NET_STATS_DIR: u64 = 0x5100_4000;
pub(crate) const NET_STATS_ATTR: u64 = 0x5100_4001;
pub(crate) const TTY_VIRT: u64 = 0x5101_0001;
pub(crate) const TTY_CLASS: u64 = 0x5101_0002;
pub(crate) const TTY_ATTR: u64 = 0x5101_2000;
pub(crate) const TTY_DIR: u64 = 0x5101_1000;
pub(crate) const TTY_RO_ATTR: u64 = 0x5101_4000;
pub(crate) const TTY_RW_ATTR: u64 = 0x5101_3000;
pub(crate) const DRM_VIRT: u64 = 0x5104_0001;
pub(crate) const DRM_CLASS: u64 = 0x5104_0002;
pub(crate) const DRM_ROOT: u64 = 0x5104_0003;
pub(crate) const DRM_DIR: u64 = 0x5104_1000;
pub(crate) const DRM_ATTR: u64 = 0x5104_2000;
pub(crate) const DRM_RW_ATTR: u64 = 0x5104_3000;
pub(crate) const INPUT_VIRT: u64 = 0x5105_0001;
pub(crate) const INPUT_CLASS: u64 = 0x5105_0002;
pub(crate) const INPUT_DIR: u64 = 0x5105_1000;
pub(crate) const INPUT_ATTR: u64 = 0x5105_2000;
pub(crate) const INPUT_LINK: u64 = 0x5105_3000;
pub(crate) const DMI_ID_BASE: u64 = 0x0000_0000_0DD1_0000;
pub(crate) const DMI_CLASS_OFFSET: u64 = 0x100;
pub(crate) const CHAR_VIRT_MEM: u64 = 0x5106_0001;
pub(crate) const CHAR_CLASS_MEM: u64 = 0x5106_0002;
pub(crate) const CHAR_VIRT_MISC: u64 = 0x5106_0003;
pub(crate) const CHAR_CLASS_MISC: u64 = 0x5106_0004;
pub(crate) const CHAR_VIRT_SOUND: u64 = 0x5106_0005;
pub(crate) const CHAR_CLASS_SOUND: u64 = 0x5106_0006;
pub(crate) const CHAR_VIRT_GRAPHICS: u64 = 0x5106_0007;
pub(crate) const CHAR_CLASS_GRAPHICS: u64 = 0x5106_0008;
pub(crate) const CHAR_DIR: u64 = 0x5106_1000;
pub(crate) const CHAR_ATTR: u64 = 0x5106_2000;
pub(crate) const CHAR_LINK: u64 = 0x5106_3000;
pub(crate) const BLOCK_ROOT: u64 = 0x5103_0001;
pub(crate) const BLOCK_VIRT: u64 = 0x5103_0002;
pub(crate) const BLOCK_CLASS: u64 = 0x5103_0003;
pub(crate) const BLOCK_DISK_DIR: u64 = 0x5103_1000;
pub(crate) const BLOCK_QUEUE_DIR: u64 = 0x5103_1100;
pub(crate) const BLOCK_DEVICE_DIR: u64 = 0x5103_1200;
pub(crate) const BLOCK_CLASS_LINK: u64 = 0x5103_3000;
/// Dynamic `/sys/block/<disk>` leaves are keyed by the live registry index and
/// their owning kobject attribute class.  `i_ino` is the canonical VFS cache
/// key, so sharing a generic attribute inode would alias distinct sysfs files.
const BLOCK_DYNAMIC_ATTR_BASE: u64 = 0x5103_4000_0000_0000;
const BLOCK_DYNAMIC_ATTR_DISK_SHIFT: u32 = 8;
const BLOCK_DYNAMIC_ATTR_CLASS_SHIFT: u32 = 6;
const BLOCK_DYNAMIC_ATTR_SLOT_MASK: u8 = 0x3f;

/// Attribute kobject beneath one dynamically registered block disk.
#[derive(Copy, Clone)]
pub(crate) enum BlockDynamicAttrClass { Disk, Queue, Device }

/// Stable inode identity for one live block kobject leaf. # C: O(1)
pub(crate) fn block_dynamic_attr_ino(disk_index: u32, class: BlockDynamicAttrClass, slot: u8) -> Option<u64> {
    if slot > BLOCK_DYNAMIC_ATTR_SLOT_MASK { return None; }
    let class = match class {
        BlockDynamicAttrClass::Disk => 0u64,
        BlockDynamicAttrClass::Queue => 1u64,
        BlockDynamicAttrClass::Device => 2u64,
    };
    Some(BLOCK_DYNAMIC_ATTR_BASE
        | ((disk_index as u64) << BLOCK_DYNAMIC_ATTR_DISK_SHIFT)
        | (class << BLOCK_DYNAMIC_ATTR_CLASS_SHIFT)
        | slot as u64)
}
pub(crate) const MODULE_ROOT: u64 = 0x5100_7000;
pub(crate) const MODULE_DIR: u64 = 0x5100_7001;
pub(crate) const MODULE_PARAM_DIR: u64 = 0x5100_7002;
pub(crate) const MODULE_ATTR: u64 = 0x5100_7003;
pub(crate) const STALE_UEVENT: u64 = 0x51dc_a001;
pub(crate) const UEVENT_SEQNUM: u64 = 0x5107_0001;
pub(crate) const ZRAM_CONTROL_ROOT: u64 = 0x5108_0001;
pub(crate) const ZRAM_CONTROL_HOT_ADD: u64 = 0x5108_2001;
pub(crate) const ZRAM_CONTROL_HOT_REMOVE: u64 = 0x5108_2002;
