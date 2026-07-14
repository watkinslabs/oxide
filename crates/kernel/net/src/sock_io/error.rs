use crate::NetError;
use syscall::errno::Errno;

/// Map a canonical positive Linux socket errno to the network work surface. # C: O(1)
pub(crate) fn pending_net_error(errno: i32) -> NetError {
    if errno == Errno::Econnrefused as i32 { NetError::Econnrefused }
    else if errno == Errno::Econnreset as i32 { NetError::Econnreset }
    else if errno == Errno::Emsgsize as i32 { NetError::Emsgsize }
    else if errno == Errno::Enetunreach as i32 { NetError::Enetunreach }
    else if errno == Errno::Enobufs as i32 { NetError::Enobufs }
    else if errno == Errno::Eaddrnotavail as i32 { NetError::Eaddrnotavail }
    else if errno == Errno::Etimedout as i32 { NetError::Etimedout }
    else { NetError::Eio }
}
