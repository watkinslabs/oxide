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

/// Linux `sock_intr_errno(timeo)` (`include/net/sock.h:2755-2761`) as the
/// negated i64 a blocking socket-receive ABI shim returns: the ERESTARTSYS
/// sentinel passes through raw for the dispatch tail when the wait carried no
/// SO_{RCV,SND}TIMEO, a real EINTR when it did. ONE owner so a shim never
/// re-decides it — the shims embed the wait loops Linux keeps in
/// `unix_stream_read_generic` / `tcp_recvmsg_locked` /
/// `__skb_wait_for_more_packets`, and each of those ends in this same call.
/// # C: O(1)
pub(crate) fn sock_intr_errno(deadline_ns: u64) -> i64 {
    errno_from_neterr(net::sock_intr::sock_intr_net(deadline_ns))
}

/// The interrupted-wait arm of a blocking stream RECEIVE. Linux breaks out of
/// `tcp_recvmsg_locked`'s loop with the bytes already copied whenever any were
/// (`net/ipv4/tcp.c:2735-2742`) and reports `sock_intr_errno(timeo)` only on the
/// nothing-copied arm (`tcp.c:2783-2786`); `unix_stream_read_generic` has the
/// same split (`net/unix/af_unix.c:2997-2999` against the `total`-carrying
/// caller). # C: O(1)
pub(crate) fn recv_interrupted(deadline_ns: u64, transferred: usize) -> Result<usize, i64> {
    if transferred != 0 { return Ok(transferred); }
    Err(sock_intr_errno(deadline_ns))
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
    fn an_untimed_receive_wait_asks_the_tail_to_restart() {
        // B1449: the blocking recv shims returned a flat EINTR, so an
        // SA_RESTART handler could never resume the call — the tail never saw a
        // restart code. `sock_intr_errno(MAX_SCHEDULE_TIMEOUT)` is ERESTARTSYS.
        assert_eq!(sock_intr_errno(net::sock_intr::NO_TIMEOUT),
                   syscall::restart::restart_sys());
        assert!(syscall::restart::is_restart_sys(
            sock_intr_errno(net::sock_intr::NO_TIMEOUT)));
    }

    #[test]
    fn an_so_rcvtimeo_receive_wait_still_reports_eintr() {
        // "Alas, with timeout socket operations are not restartable." The timed
        // row must NOT become restartable when the untimed one does.
        for deadline in [1u64, 1_000, u64::MAX] {
            assert_eq!(sock_intr_errno(deadline), -(Errno::Eintr.as_i32() as i64),
                       "deadline={deadline}");
            assert!(!syscall::restart::is_restart_code(sock_intr_errno(deadline)));
        }
    }

    #[test]
    fn a_flat_eintr_from_a_receive_wait_can_never_restart_on_any_arch() {
        // The decisive, arch-INDEPENDENT statement of this bug. `-EINTR` is not
        // an ERESTART* sentinel, so the syscall-return tail classifies it as
        // `RestartAction::None` under EVERY handler/SA_RESTART combination and
        // hands it straight to userspace. A guest record showing an untimed
        // SA_RESTART recv RESUMING therefore cannot have come from a restart of
        // an interrupted wait while the shim returned this — the wait was not
        // interrupted at all.
        use syscall::restart::{RestartAction, signal_restart_action};
        let eintr = -(Errno::Eintr.as_i32() as i64);
        for handler_ran in [false, true] {
            for sa_restart in [false, true] {
                assert_eq!(signal_restart_action(eintr, handler_ran, sa_restart),
                    RestartAction::None, "handler_ran={handler_ran} sa_restart={sa_restart}");
            }
        }
        let untimed = sock_intr_errno(net::sock_intr::NO_TIMEOUT);
        assert_eq!(signal_restart_action(untimed, true, true), RestartAction::RestartSame);
        assert_eq!(signal_restart_action(untimed, true, false), RestartAction::Eintr);
        assert_eq!(signal_restart_action(untimed, false, false), RestartAction::RestartSame);
        // SO_RCVTIMEO keeps the un-restartable answer it always had.
        assert_eq!(signal_restart_action(sock_intr_errno(1_000), true, true), RestartAction::None);
    }

    #[test]
    fn a_partial_stream_receive_keeps_its_count_instead_of_any_signal_code() {
        // `tcp_recvmsg_locked` breaks with `copied` when anything was copied,
        // whatever the timeout state — the signal code is the empty-transfer arm.
        for deadline in [net::sock_intr::NO_TIMEOUT, 1_000] {
            assert_eq!(recv_interrupted(deadline, 5), Ok(5));
        }
        assert_eq!(recv_interrupted(net::sock_intr::NO_TIMEOUT, 0),
                   Err(syscall::restart::restart_sys()));
        assert_eq!(recv_interrupted(1_000, 0), Err(-(Errno::Eintr.as_i32() as i64)));
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
