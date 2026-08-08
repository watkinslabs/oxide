// The listener descriptor: an anonymous inode whose private state IS the
// listener, so descriptor lifetime and listener lifetime are one fact. Last
// close detaches, which releases every task still waiting on a supervisor
// that can no longer answer.

extern crate alloc;

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::{File, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, OpenFlags};
use vfs::{PollSubscribers, VfsError, default_inode_ops, mk_mode};

use super::listener::{self, Listener};

/// `i_private` of a listener fd.
pub struct SeccompListenerInode {
    pub listener: Arc<Listener>,
}

/// Fixed inode number for every listener fd, as an anonymous-inode factory
/// gives its files.
const LISTENER_INO: u64 = 0x5343_4D50_0000_0001;
const LISTENER_MODE: u16 = 0o600;

struct ListenerFileOps;

impl FileOps for ListenerFileOps {
    /// A listener is a control channel, not a data stream: it carries no
    /// read/write, only its ioctls.
    /// # C: O(1)
    fn read(&self, _i: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Einval) }
    /// # C: O(1)
    fn write(&self, _i: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Einval) }

    /// # C: O(N_notifications)
    fn poll_open_file(&self, file: &File) -> u32 {
        match listener_of_inode(file.inode()) {
            Some(l) => l.inner.lock().poll_mask(listener::has_users(l.id)),
            None => vfs::POLL_ERR,
        }
    }

    /// # C: O(1)
    fn poll_subscribers(&self, file: &File) -> Option<Arc<PollSubscribers>> {
        listener_of_inode(file.inode()).map(|l| l.poll_subs.clone())
    }

    /// Last close of the listener: no supervisor can answer through it again.
    /// # C: O(N_notifications)
    fn on_release_file(&self, file: &File) {
        if let Some(l) = listener_of_inode(file.inode()) { listener::detach(&l); }
    }
}

/// Build the anonymous inode backing a listener fd. # C: O(1)
pub fn make_listener_inode(listener: Arc<Listener>) -> InodeRef {
    InodeBuilder::new(LISTENER_INO, mk_mode(FileType::Regular, LISTENER_MODE),
                      default_inode_ops(), Arc::new(ListenerFileOps))
        .private(Arc::new(SeccompListenerInode { listener }))
        .build()
}

/// The listener behind an inode, or `None` when the inode is not a listener.
/// # C: O(1)
pub fn listener_of_inode(inode: &InodeRef) -> Option<Arc<Listener>> {
    inode.private::<SeccompListenerInode>().map(|p| p.listener.clone())
}

/// Whether a descriptor is a listener fd — the test the ioctl router uses so
/// a foreign inode reusing these command numbers never reaches this handler.
/// # C: O(1)
pub fn is_listener_inode(inode: &InodeRef) -> bool {
    inode.private::<SeccompListenerInode>().is_some()
}

/// Create a listener and publish it as a close-on-exec descriptor of the
/// calling task. The reservation is taken BEFORE the listener exists so a
/// descriptor-table failure cannot leave a listener nothing can ever close.
/// # C: O(1)
pub fn install(wait_killable_recv: bool) -> Result<(i32, u64), Errno> {
    let cur = sched::current().ok_or(Errno::Esrch)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole writer of its own fd table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let fd = fdt.get_unused_fd_flags(OpenFlags::O_CLOEXEC, cur.nofile_soft())
                .map_err(|_| Errno::Emfile)?;
    let l = listener::create(wait_killable_recv);
    let inode = make_listener_inode(l.clone());
    let dentry = vfs::dcache::d_alloc_pseudo("[seccomp notify]", inode.clone(),
                                             &crate::anon_dname::ANON_INODE_OPS);
    let id = l.id;
    fdt.fd_install(fd, File::new(inode, dentry, OpenFlags::O_RDWR));
    Ok((fd, id))
}

/// Withdraw a listener published by [`install`] because the install it belongs
/// to failed afterwards. The descriptor never named anything else, so closing
/// it is what detaches the listener.
/// # C: O(1)
pub fn uninstall(fd: i32) {
    let Some(cur) = sched::current() else { return };
    // SAFETY: running task on this CPU; preempt-off; sole writer of its own fd table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return };
    let _ = fdt.close(fd);
}
