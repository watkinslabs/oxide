use alloc::sync::Arc;

use super::InetSocket;

/// One accepted socket plus its optional AF_UNIX garbage-collector pin.
pub struct Accepted {
    pub new_sock: Arc<InetSocket>,
    pub peer: Option<(crate::Ipv4Addr, u16)>,
    pub unix_gc_pin: Option<crate::GcPin>,
}

/// Complete ABI-specific accepted-peer copy-out, releasing the child on failure.
/// # C: O(1) plus copy-out
pub fn complete_accepted<E>(accepted: Accepted,
                            copyout: impl FnOnce(&InetSocket) -> Result<(), E>,
                            discard: impl FnOnce(&Accepted))
    -> Result<Accepted, E>
{
    if let Err(error) = copyout(&accepted.new_sock) {
        discard(&accepted);
        return Err(error);
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copyout_failure_releases_the_accepted_socket_and_keeps_its_error() {
        use core::sync::atomic::Ordering;
        let local = crate::Endpoint { ip: crate::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), port: 41_001 };
        let remote = crate::Endpoint { ip: crate::IpAddr::V4(crate::Ipv4Addr::new(192, 0, 2, 1)), port: 443 };
        let child = Arc::new(InetSocket::new_tcp());
        let entry = Arc::new(crate::stack::TcpEntry::new_bound_with_error(
            crate::TcpConn::new_client(local, remote, 1), child.error.clone(), None));
        *child.kind.lock() = super::super::SockKind::TcpConn(entry.clone());
        let accepted = Accepted { new_sock: child.clone(), peer: None, unix_gc_pin: None };

        assert!(matches!(complete_accepted(accepted, |_| Err::<(), _>(17),
                                           |accepted| accepted.new_sock.release_file()), Err(17)));
        assert!(child.released.load(Ordering::Acquire));
        assert_eq!(entry.conn.lock().state, crate::tcp_state::TcpState::Closed);
    }

    #[test]
    fn successful_copyout_keeps_the_accepted_socket_open() {
        use core::sync::atomic::Ordering;
        let child = Arc::new(InetSocket::new_tcp());
        let accepted = Accepted { new_sock: child.clone(), peer: None, unix_gc_pin: None };

        assert!(complete_accepted(accepted, |_| Ok::<(), i32>(()),
                                  |accepted| accepted.new_sock.release_file()).is_ok());
        assert!(!child.released.load(Ordering::Acquire));
    }
}
