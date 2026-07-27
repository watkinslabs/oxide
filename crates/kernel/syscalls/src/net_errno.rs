use syscall::errno::Errno;

/// Map a network work-function error to a negated Linux syscall errno. # C: O(1)
pub(crate) fn errno_from_neterr(error: net::NetError) -> i64 {
    // See `namei_common::errno`: the restart sentinel passes through raw so the
    // dispatch tail owns the restart decision. `sock_intr_errno`
    // (`include/net/sock.h:2759`) chose it precisely because the wait had no
    // SO_{RCV,SND}TIMEO and therefore IS restartable.
    -(match error {
        net::NetError::Erestartsys => return syscall::restart::restart_sys(),
        net::NetError::Eaddrinuse => Errno::Eaddrinuse,
        net::NetError::Eaddrnotavail => Errno::Eaddrnotavail,
        net::NetError::Edestaddrreq => Errno::Edestaddrreq,
        net::NetError::Emsgsize => Errno::Emsgsize,
        net::NetError::Enobufs => Errno::Enobufs,
        net::NetError::Enomem => Errno::Enomem,
        net::NetError::Enetunreach => Errno::Enetunreach,
        net::NetError::Ehostunreach => Errno::Ehostunreach,
        net::NetError::Eacces => Errno::Eacces,
        net::NetError::Enonet => Errno::Enonet,
        net::NetError::Enoprotoopt => Errno::Enoprotoopt,
        net::NetError::Eopnotsupp => Errno::Eopnotsupp,
        net::NetError::Esocktnosupport => Errno::Esocktnosupport,
        net::NetError::Eproto => Errno::Eproto,
        net::NetError::Ehostdown => Errno::Ehostdown,
        net::NetError::Enodev => Errno::Enodev,
        net::NetError::Enetdown => Errno::Enetdown,
        net::NetError::Einval => Errno::Einval,
        net::NetError::Eio => Errno::Eio,
        net::NetError::Eagain => Errno::Eagain,
        net::NetError::Eafnosupport => Errno::Eafnosupport,
        net::NetError::Eisconn => Errno::Eisconn,
        net::NetError::Ealready => Errno::Ealready,
        net::NetError::Ebusy => Errno::Ebusy,
        net::NetError::Enospc => Errno::Enospc,
        net::NetError::Eperm => Errno::Eperm,
        net::NetError::Einprogress => Errno::Einprogress,
        net::NetError::Enotconn => Errno::Enotconn,
        net::NetError::Erange => Errno::Erange,
        net::NetError::Econnrefused => Errno::Econnrefused,
        net::NetError::Econnaborted => Errno::Econnaborted,
        net::NetError::Econnreset => Errno::Econnreset,
        net::NetError::Etimedout => Errno::Etimedout,
        net::NetError::Epipe => Errno::Epipe,
        net::NetError::Enoent => Errno::Enoent,
        net::NetError::Eintr => Errno::Eintr,
    } as i32 as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_restart_sentinel_passes_through_raw_not_as_an_errno() {
        // `sock_intr_errno` picked ERESTARTSYS precisely because the wait had
        // no SO_{RCV,SND}TIMEO and IS restartable. Mapping it into the errno
        // table here would be the flattening `NetError::Erestartsys` exists to
        // prevent — the dispatch tail owns the restart decision.
        assert_eq!(errno_from_neterr(net::NetError::Erestartsys),
                   syscall::restart::restart_sys());
        assert_eq!(errno_from_neterr(net::NetError::Erestartsys), -512);
    }

    #[test]
    fn a_timed_wait_still_reports_a_real_eintr() {
        // The other half of `sock_intr_errno`: with a socket timeout set the
        // call is NOT restartable and userspace must see EINTR.
        assert_eq!(errno_from_neterr(net::NetError::Eintr),
                   -(Errno::Eintr.as_i32() as i64));
        assert_ne!(errno_from_neterr(net::NetError::Eintr),
                   errno_from_neterr(net::NetError::Erestartsys));
    }

    #[test]
    fn every_sock_intr_verdict_encodes_distinctly_end_to_end() {
        use net::sock_intr::{NO_TIMEOUT, sock_intr_net};
        assert_eq!(errno_from_neterr(sock_intr_net(NO_TIMEOUT)),
                   syscall::restart::restart_sys());
        assert_eq!(errno_from_neterr(sock_intr_net(1_000_000)),
                   -(Errno::Eintr.as_i32() as i64));
    }
}
