use super::NetError;

/// What the TCP open did before the caller chooses its ABI result.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Opened { Deferred, Started }

/// What an ordinary `connect` does after its TCP open.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConnectResult { Return, Einprogress, Wait }

/// Turn the Fast Open open result into the `connect` ABI outcome. # C: O(1)
pub(crate) fn connect_result(opened: Opened, nonblock: bool) -> ConnectResult {
    match opened {
        Opened::Deferred => ConnectResult::Return,
        Opened::Started if nonblock => ConnectResult::Einprogress,
        Opened::Started => ConnectResult::Wait,
    }
}

/// A write owns payload, so an open it starts cannot defer for another write.
/// # C: O(1)
pub(crate) fn write_open_result(opened: Opened) -> Result<(), NetError> {
    if opened == Opened::Deferred { Err(NetError::Eopnotsupp) } else { Ok(()) }
}

/// Nonblocking Fast Open reports carried SYN bytes or the pending handshake.
/// # C: O(1)
pub(crate) fn nonblock_write_result(carried: usize) -> Result<usize, NetError> {
    if carried == 0 { Err(NetError::Einprogress) } else { Ok(carried) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_connect_returns_without_a_syn_or_wait() {
        assert_eq!(connect_result(Opened::Deferred, false), ConnectResult::Return);
        assert_eq!(connect_result(Opened::Deferred, true), ConnectResult::Return);
    }

    #[test]
    fn started_connect_only_waits_when_blocking() {
        assert_eq!(connect_result(Opened::Started, false), ConnectResult::Wait);
        assert_eq!(connect_result(Opened::Started, true), ConnectResult::Einprogress);
    }

    #[test]
    fn write_opens_cannot_defer_and_nonblocking_result_tracks_syn_payload() {
        assert_eq!(write_open_result(Opened::Deferred), Err(NetError::Eopnotsupp));
        assert_eq!(write_open_result(Opened::Started), Ok(()));
        assert_eq!(nonblock_write_result(0), Err(NetError::Einprogress));
        assert_eq!(nonblock_write_result(7), Ok(7));
    }
}
