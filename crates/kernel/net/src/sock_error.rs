use crate::NetError;
use syscall::errno::Errno;

/// Map a canonical positive Linux socket errno to the network work surface. # C: O(1)
pub(crate) fn pending_net_error(errno: i32) -> NetError {
    if errno == Errno::Econnrefused as i32 { NetError::Econnrefused }
    else if errno == Errno::Econnreset as i32 { NetError::Econnreset }
    else if errno == Errno::Emsgsize as i32 { NetError::Emsgsize }
    else if errno == Errno::Enetunreach as i32 { NetError::Enetunreach }
    else if errno == Errno::Ehostunreach as i32 { NetError::Ehostunreach }
    else if errno == Errno::Eacces as i32 { NetError::Eacces }
    else if errno == Errno::Enonet as i32 { NetError::Enonet }
    else if errno == Errno::Enoprotoopt as i32 { NetError::Enoprotoopt }
    else if errno == Errno::Eopnotsupp as i32 { NetError::Eopnotsupp }
    else if errno == Errno::Eproto as i32 { NetError::Eproto }
    else if errno == Errno::Ehostdown as i32 { NetError::Ehostdown }
    else if errno == Errno::Enobufs as i32 { NetError::Enobufs }
    else if errno == Errno::Eaddrnotavail as i32 { NetError::Eaddrnotavail }
    else if errno == Errno::Etimedout as i32 { NetError::Etimedout }
    else { NetError::Eio }
}

/// Linux `__inet_stream_connect` reports `ECONNABORTED` when TCP reaches
/// CLOSE without an asynchronously published `sk_err`. # C: O(1)
pub(crate) fn terminal_connect_error(errno: i32) -> NetError {
    if errno == 0 { NetError::Econnaborted } else { pending_net_error(errno) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_active_open_without_pending_error_is_connection_aborted() {
        assert_eq!(terminal_connect_error(0), NetError::Econnaborted);
    }

    #[test]
    fn closed_active_open_preserves_pending_transport_error() {
        assert_eq!(terminal_connect_error(Errno::Econnrefused as i32), NetError::Econnrefused);
    }
}
