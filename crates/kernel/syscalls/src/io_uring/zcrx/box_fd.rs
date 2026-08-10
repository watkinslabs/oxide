// The descriptor an exported zero-copy receive instance travels on.
//
// Exporting hands out a descriptor whose only job is to name one instance, so
// a second ring can adopt it. The descriptor is what keeps the instance
// REACHABLE; the instance's own user count is what keeps its device queue
// bound. The two are deliberately separate: a descriptor left open after every
// ring let go must not keep a device queue provisioned, and a ring that
// adopted the instance must not lose its queue when the exporter closes the
// descriptor it adopted through.
//
// The instance is carried in the inode's private slot, and that is also the
// identity check an adoption makes: a descriptor whose inode carries no
// instance is not one of these, whatever else it is.

use alloc::sync::Arc;

use vfs::{
    default_inode_ops, get_next_ino, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef,
};

use super::ifq::ZcrxIfq;

/// Neither read nor written: the descriptor names an instance, it does not
/// carry its data.
struct ZcrxBoxOps;
impl FileOps for ZcrxBoxOps {
    fn read(&self, _i: &Inode, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> {
        Err(vfs::VfsError::Einval)
    }
    fn write(&self, _i: &Inode, _o: u64, _b: &[u8]) -> vfs::KResult<usize> {
        Err(vfs::VfsError::Einval)
    }
}

/// Wrap an instance into an inode a descriptor can be installed over. The
/// number comes from io_uring's reserved range so the shared close hook
/// reaches it; what makes the descriptor an exported instance is the instance
/// it carries, not the number. # C: O(1)
pub fn make_box_inode(ifq: Arc<ZcrxIfq>) -> InodeRef {
    let ino = vfs::pseudo_ino::IO_URING.at(get_next_ino() as u64);
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(),
                      Arc::new(ZcrxBoxOps))
        .private(ifq)
        .build()
}

/// The instance a descriptor names, or `None` when it names none. # C: O(1)
pub fn ifq_of(file: &Arc<vfs::File>) -> Option<Arc<ZcrxIfq>> {
    Arc::clone(file.inode().i_private()).downcast::<ZcrxIfq>().ok()
}

/// The instance an inode carries, for the shared close hook. # C: O(1)
pub fn ifq_of_inode(inode: &InodeRef) -> Option<Arc<ZcrxIfq>> {
    Arc::clone(inode.i_private()).downcast::<ZcrxIfq>().ok()
}
