//! Winsock network-event projection over the Linux-shaped socket readiness ABI.
//!
//! `InetSocket::poll()` remains the only readiness owner. This module translates
//! its result for an NT/Winsock adapter; it does not retain subscriptions,
//! edge state, or socket status of its own.

/// Socket lifecycle role needed to disambiguate Linux readable/writable bits.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WindowsSocketRole {
    /// A listening socket maps readable readiness to `FD_ACCEPT`.
    Listener,
    /// A nonblocking connection attempt maps writable/error readiness to `FD_CONNECT`.
    Connecting,
    /// A connected socket maps ordinary readiness to read/write events.
    Connected,
}

/// Winsock network-event bits (`FD_*`).
pub mod event {
    pub const READ: u32 = 0x0000_0001;
    pub const WRITE: u32 = 0x0000_0002;
    pub const OOB: u32 = 0x0000_0004;
    pub const ACCEPT: u32 = 0x0000_0008;
    pub const CONNECT: u32 = 0x0000_0010;
    pub const CLOSE: u32 = 0x0000_0020;
}

/// Translate one Linux socket readiness snapshot to Winsock event bits.
///
/// The input must be the mask returned by the canonical socket owner. `POLL_IN`
/// means accept only for a listener; `POLL_OUT` means connect only while the
/// socket is in its connecting state. Hangup/error readiness is reported as
/// close for established sockets and connect for an unfinished connection.
/// # C: O(1)
pub fn from_poll_mask(mask: u32, role: WindowsSocketRole) -> u32 {
    let mut events = 0;
    if mask & vfs::POLL_IN != 0 {
        events |= match role {
            WindowsSocketRole::Listener => event::ACCEPT,
            WindowsSocketRole::Connecting | WindowsSocketRole::Connected => event::READ,
        };
    }
    if mask & vfs::POLL_PRI != 0 { events |= event::OOB; }
    if mask & vfs::POLL_OUT != 0 {
        events |= match role {
            WindowsSocketRole::Connecting => event::CONNECT,
            WindowsSocketRole::Listener | WindowsSocketRole::Connected => event::WRITE,
        };
    }
    if mask & (vfs::POLL_HUP | vfs::POLL_RDHUP | vfs::POLL_ERR) != 0 {
        events |= match role {
            WindowsSocketRole::Connecting => event::CONNECT,
            WindowsSocketRole::Listener | WindowsSocketRole::Connected => event::CLOSE,
        };
    }
    events
}

#[cfg(test)]
mod tests {
    use super::{event, from_poll_mask, WindowsSocketRole};

    #[test]
    fn listener_readiness_is_accept_not_read() {
        assert_eq!(from_poll_mask(vfs::POLL_IN, WindowsSocketRole::Listener), event::ACCEPT);
    }

    #[test]
    fn connected_readiness_preserves_read_write_oob_and_close() {
        let mask = vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_PRI | vfs::POLL_RDHUP;
        assert_eq!(from_poll_mask(mask, WindowsSocketRole::Connected),
            event::READ | event::WRITE | event::OOB | event::CLOSE);
    }

    #[test]
    fn connecting_writable_and_error_are_connect_events() {
        assert_eq!(from_poll_mask(vfs::POLL_OUT | vfs::POLL_ERR,
            WindowsSocketRole::Connecting), event::CONNECT);
    }

    #[test]
    fn empty_readiness_has_no_network_event() {
        assert_eq!(from_poll_mask(0, WindowsSocketRole::Connected), 0);
    }
}
