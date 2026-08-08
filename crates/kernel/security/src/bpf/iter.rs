//! BPF iterators.
//!
//! Module manifest:
//!
//!   targets.rs  the object kinds this kernel can walk, and their stubs
//!   seq.rs      the descriptor `BPF_ITER_CREATE` mints and the walk it runs
//!
//! An iterator program names its target by a type id in the kernel's own
//! type information, exactly as an LSM program names its hook — one attach
//! target mechanism, not two. The link binds the program to that target;
//! the descriptor runs the walk.

extern crate alloc;
use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::{FileType, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};

use super::{BPF_FD_MODE, ids};

#[path = "iter/targets.rs"]
pub mod targets;
#[path = "iter/seq.rs"]
mod seq;

pub use targets::{IterTarget, target_by_stub_name};

/// fd-backed iterator link: a program bound to one target. Dropping the
/// last reference drops the link's id with it.
pub struct BpfIterLinkInode {
    pub(super) id: u32,
    target: IterTarget,
    /// The program this link runs, pinned so it outlives every descriptor
    /// the loader closed.
    prog: InodeRef,
}

impl BpfIterLinkInode {
    /// # C: O(1)
    pub(crate) fn target(&self) -> IterTarget { self.target }
    /// # C: O(1)
    pub(crate) fn prog(&self) -> InodeRef { Arc::clone(&self.prog) }
}

impl Drop for BpfIterLinkInode {
    fn drop(&mut self) { super::link::forget_link_id(self.id); }
}

/// Build the iterator link fd inode, drawing its id from the one link id
/// registry so it is reachable by LINK_GET_FD_BY_ID and appears in a
/// LINK_GET_NEXT_ID walk beside every other link kind. # C: O(log links)
pub fn make_bpf_iter_link_inode(target: IterTarget, prog: InodeRef) -> InodeRef {
    let id = super::link::reserve_link_id();
    let inode = InodeBuilder::new(ids::INO_LINK, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(BpfIterLinkInode { id, target, prog }))
        .build();
    super::link::settle_link_id(id, &inode);
    inode
}

/// `bpf_iter_new_fd()`. # C: O(fd words)
pub(super) fn new_fd(link: InodeRef) -> Result<i64, Errno> { seq::new_fd(link) }
