//! The inode a Bluetooth socket file description hangs off.
//!
//! One inode per socket, carrying the protocol's own state in the private slot.
//! The data path delegates to that state; nothing about a protocol is decided
//! here, which is what keeps this file an adapter rather than a second place
//! where a socket's rules live.

extern crate alloc;
use alloc::sync::Arc;

use sync::{HciDev as BtSockClass, Spinlock};
use vfs::{FileOps, Inode, InodeRef, KResult, VfsError};

use super::hci_sock::HciSocket;

/// A raw controller socket behind its lock.
pub struct HciSocketFile { pub state: Spinlock<HciSocket, BtSockClass> }

impl HciSocketFile {
    /// An unbound socket. # C: O(1)
    pub fn new() -> HciSocketFile { HciSocketFile { state: Spinlock::new(HciSocket::new()) } }
}

impl Default for HciSocketFile {
    fn default() -> Self { Self::new() }
}

struct HciSocketFileOps;

impl FileOps for HciSocketFileOps {
    /// A read hands over one whole queued frame. A frame longer than the buffer
    /// is refused rather than split: the socket is frame-oriented, and half a
    /// frame would desynchronise the reader permanently. # C: O(len)
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let f = inode.private::<HciSocketFile>().ok_or(VfsError::Einval)?;
        let Some(frame) = f.state.lock().pop() else { return Err(VfsError::Eagain); };
        if frame.len() > buf.len() { return Err(VfsError::Einval); }
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }

    /// # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let readable = inode.private::<HciSocketFile>()
            .is_some_and(|f| f.state.lock().readable());
        if readable { vfs::POLL_IN | vfs::POLL_OUT } else { vfs::POLL_OUT }
    }
}

/// Inode numbers for Bluetooth sockets, from the range reserved for them.
static NEXT_INO: vfs::pseudo_ino::RegionAllocator
    = vfs::pseudo_ino::RegionAllocator::new(&vfs::pseudo_ino::BLUETOOTH);

/// Build the inode for a raw controller socket. # C: O(1)
pub fn make_hci_socket_inode(sock: Arc<HciSocketFile>) -> InodeRef {
    vfs::InodeBuilder::new(
        NEXT_INO.alloc(),
        vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(),
        Arc::new(HciSocketFileOps),
    )
    .private(sock)
    .build()
}

/// Recover the socket behind an inode. # C: O(1)
pub fn hci_socket_from_inode(inode: &Inode) -> Option<&HciSocketFile> {
    inode.private::<HciSocketFile>()
}
