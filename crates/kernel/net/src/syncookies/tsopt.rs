// The options a cookie handshake smuggles through the peer's timestamp echo.
//
// The cookie itself has no room for the negotiated options: its 24 usable bits
// are spent on the MSS index and the concealment term. So when the peer offers
// timestamps, the SYN-ACK's own TSval is built with its low six bits carrying
// them, and the peer echoes the whole value back on the acknowledgement:
//
//   MSB                               LSB
//   | 31 ...   6 |  5  |  4   | 3 2 1 0 |
//   |  Timestamp | ECN | SACK | WScale  |
//
// A window scale of 0xf is not a legal scale (the maximum is 14), so it is the
// sentinel for "the original SYN offered no window scaling at all". There is
// no bit for timestamps themselves: an acknowledgement carrying a timestamp
// option proves the exchange negotiated them.
//
// Rounding the clock down to a multiple of 64 ms and then subtracting a tick
// when the result would exceed the current time keeps the value no later than
// the ordinary timestamp clock, so the connection's later timestamps never
// appear to go backwards.
//
// No target gate: this is the observable contract with the peer.

/// Bits of the timestamp the options occupy.
pub const TSBITS: u32 = 6;
/// Window-scale field, whose all-ones value means "none was offered".
pub const TS_OPT_WSCALE_MASK: u32 = 0xf;
/// The peer permitted selective acknowledgement.
pub const TS_OPT_SACK: u32 = 1 << 4;
/// The handshake negotiated explicit congestion notification.
pub const TS_OPT_ECN: u32 = 1 << 5;

/// Largest legal window scale, so the sentinel can never be a real one.
pub const MAX_WSCALE: u8 = 14;

/// The TSval a cookie SYN-ACK carries, before this connection's timestamp
/// offset is added. `wscale` is what the peer's SYN offered, or `None` when it
/// offered no window scaling. # C: O(1)
pub fn init_timestamp(now_ms: u32, wscale: Option<u8>, sack: bool, ecn: bool) -> u32 {
    let mut options = match wscale {
        Some(scale) => core::cmp::min(scale, MAX_WSCALE) as u32 & TS_OPT_WSCALE_MASK,
        None => TS_OPT_WSCALE_MASK,
    };
    if sack { options |= TS_OPT_SACK; }
    if ecn { options |= TS_OPT_ECN; }
    let ts = ((now_ms >> TSBITS) << TSBITS) | options;
    if ts > now_ms { ts.wrapping_sub(1 << TSBITS) } else { ts }
}

/// What the host permits at all. A decoded option the host has turned off is
/// not silently dropped — the whole acknowledgement is refused, because the
/// SYN-ACK already promised it and a connection built without it would
/// disagree with the peer about the wire format.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Permitted {
    pub timestamps: bool,
    pub sack: bool,
    pub window_scaling: bool,
}

impl Permitted {
    /// Every option permitted. This namespace has no knob that turns any of
    /// the three off, so this is what the live decision is taken under; the
    /// parameter exists so the refusal path is still expressible and tested.
    pub const ALL: Self = Self { timestamps: true, sack: true, window_scaling: true };
}

/// The options one cookie handshake negotiated.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Decoded {
    pub tstamp_ok: bool,
    pub sack_ok: bool,
    pub wscale: Option<u8>,
    pub ecn_ok: bool,
}

/// Recover the options from the acknowledgement's echoed timestamp. `tsecr`
/// must already have this connection's timestamp offset removed. An
/// acknowledgement carrying no timestamp option is not an error: it means the
/// original SYN offered none, so the connection is rebuilt with every option
/// off. # C: O(1)
pub fn decode(saw_tstamp: bool, tsecr: u32, permitted: Permitted) -> Option<Decoded> {
    if !saw_tstamp { return Some(Decoded::default()); }
    if !permitted.timestamps { return None; }
    let sack_ok = (tsecr & TS_OPT_SACK) != 0;
    if sack_ok && !permitted.sack { return None; }
    let ecn_ok = (tsecr & TS_OPT_ECN) != 0;
    if (tsecr & TS_OPT_WSCALE_MASK) == TS_OPT_WSCALE_MASK {
        return Some(Decoded { tstamp_ok: true, sack_ok, wscale: None, ecn_ok });
    }
    if !permitted.window_scaling { return None; }
    Some(Decoded { tstamp_ok: true, sack_ok, wscale: Some((tsecr & TS_OPT_WSCALE_MASK) as u8), ecn_ok })
}
