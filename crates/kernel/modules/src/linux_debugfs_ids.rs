/// debugfs automount points draw from the one range `vfs::pseudo_ino` reserves
/// for them, and wrap inside it rather than counting on into a neighbour's.
pub(crate) static NEXT_AUTOMOUNT_INO: vfs::pseudo_ino::RegionAllocator
    = vfs::pseudo_ino::RegionAllocator::new(&vfs::pseudo_ino::DEBUGFS_AUTOMOUNT);
