//! Readiness the error state contributes to `poll`.

/// The readiness bits a socket's error state contributes.
///
/// A pending errno or any queued record raises the error bit. Only the
/// datagram families additionally raise the priority bit, and only for a
/// socket that asked to select on its error queue. # C: O(1)
pub fn error_poll_mask(pending_errno: bool, queued: bool, select_err_queue: bool,
    datagram: bool) -> u32
{
    if !pending_errno && !queued { return 0; }
    let mut mask = vfs::POLL_ERR;
    if datagram && select_err_queue { mask |= vfs::POLL_PRI; }
    mask
}

#[cfg(test)]
mod tests {
    use super::error_poll_mask;

    #[test]
    fn a_quiet_socket_contributes_nothing() {
        assert_eq!(error_poll_mask(false, false, true, true), 0);
    }

    #[test]
    fn either_a_pending_errno_or_a_queued_record_raises_the_error_bit() {
        assert_eq!(error_poll_mask(true, false, false, false), vfs::POLL_ERR);
        assert_eq!(error_poll_mask(false, true, false, false), vfs::POLL_ERR);
    }

    #[test]
    fn only_a_datagram_socket_that_asked_for_it_raises_the_priority_bit() {
        assert_eq!(error_poll_mask(false, true, true, true), vfs::POLL_ERR | vfs::POLL_PRI);
        assert_eq!(error_poll_mask(false, true, false, true), vfs::POLL_ERR);
        assert_eq!(error_poll_mask(false, true, true, false), vfs::POLL_ERR,
            "a stream socket never reports its error queue as priority readiness");
    }
}
