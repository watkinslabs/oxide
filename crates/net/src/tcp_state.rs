// TCP state machine per `25§7` / RFC 9293. Pure data type + the
// transition table that drives socket state mutations elsewhere; the
// segment-handling code that calls `transition` lands alongside the
// socket impl.

/// `25§7` 11 states.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TcpState {
    Closed      = 0,
    Listen      = 1,
    SynSent     = 2,
    SynRecv     = 3,
    Established = 4,
    FinWait1    = 5,
    FinWait2    = 6,
    CloseWait   = 7,
    Closing     = 8,
    LastAck     = 9,
    TimeWait    = 10,
}

/// Externally-driven transitions per RFC 9293. `Active*` events come
/// from the socket calls (`connect`, `close`); `Recv*` events come
/// from the segment handler.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpEvent {
    /// `listen()` syscall on a CLOSED socket.
    PassiveOpen,
    /// `connect()` syscall — sends SYN.
    ActiveOpen,
    /// Received SYN.
    RecvSyn,
    /// Received SYN+ACK after `ActiveOpen`.
    RecvSynAck,
    /// Received ACK that completes the three-way handshake.
    RecvAckEstablish,
    /// Local `close()` while ESTABLISHED.
    LocalClose,
    /// Remote sent FIN.
    RecvFin,
    /// ACK of our FIN.
    RecvFinAck,
    /// 2-MSL timer expired in TIME_WAIT.
    TimeWaitExpired,
    /// Local `RST` send or remote-RST receipt.
    Reset,
}

/// Drive one transition. Returns `None` if the event isn't valid in
/// the current state per RFC 9293 figure 6 — caller must surface
/// that as a protocol-error on the receive path.
/// # C: O(1)
pub const fn transition(s: TcpState, e: TcpEvent) -> Option<TcpState> {
    use TcpEvent::*;
    use TcpState::*;
    match (s, e) {
        (_,           Reset)            => Some(Closed),
        (Closed,      PassiveOpen)      => Some(Listen),
        (Closed,      ActiveOpen)       => Some(SynSent),
        (Listen,      RecvSyn)          => Some(SynRecv),
        (SynSent,     RecvSynAck)       => Some(Established),
        (SynSent,     RecvSyn)          => Some(SynRecv), // simultaneous open
        (SynRecv,     RecvAckEstablish) => Some(Established),
        (Established, LocalClose)       => Some(FinWait1),
        (Established, RecvFin)          => Some(CloseWait),
        (FinWait1,    RecvFinAck)       => Some(FinWait2),
        (FinWait1,    RecvFin)          => Some(Closing),
        (FinWait2,    RecvFin)          => Some(TimeWait),
        (CloseWait,   LocalClose)       => Some(LastAck),
        (LastAck,     RecvFinAck)       => Some(Closed),
        (Closing,     RecvFinAck)       => Some(TimeWait),
        (TimeWait,    TimeWaitExpired)  => Some(Closed),
        _                                => None,
    }
}

impl TcpState {
    /// True iff the connection is fully open (data-transfer phase).
    /// # C: O(1)
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }
    /// True iff a peer can no longer receive data on this socket.
    /// # C: O(1)
    pub const fn is_closing(self) -> bool {
        matches!(self,
            Self::FinWait1 | Self::FinWait2 | Self::Closing |
            Self::CloseWait | Self::LastAck | Self::TimeWait)
    }
}
