// Descriptor resolution for the socket-holding bpf map. The only part of the
// store path that needs a running task, kept apart from the decisions it feeds
// so those stay hosted-testable (`docs/53§4`).

use syscall::errno::Errno;
use security::bpf::map::sockarray::{self, SockHandle};

/// Publish the resolvers the map calls back into. Idempotent. # C: O(1)
pub fn install() { sockarray::install_sock_resolvers(from_fd, super::state_of); }

/// The socket a descriptor names, if it may be stored. Errors run in the order
/// a caller can observe: a descriptor that is not open at all, then one that is
/// not a socket, then the socket's own shape. # C: O(1)
fn from_fd(fd: i32) -> Result<SockHandle, Errno> {
    let cur = sched::live::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; sole reader of the fd-table slot for this lookup.
    let table = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = table.get(fd).map_err(|_| Errno::Ebadf)?;
    let sock = file.inode().i_private().clone()
        .downcast::<crate::sock::InetSocket>().map_err(|_| Errno::Enotsock)?;
    sockarray::stored_shape_check(super::stored_shape(&sock))?;
    super::handle_of(&sock).ok_or(Errno::Einval)
}
