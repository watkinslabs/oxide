//! UDP tracker. There is no state machine: the only question is whether the
//! flow has seen a reply, and whether it has been running long enough to be
//! called a stream.

/// Timeout index: no reply seen yet.
pub const UDP_CT_UNREPLIED: usize = 0;
/// Timeout index: reply seen.
pub const UDP_CT_REPLIED:   usize = 1;
pub const UDP_CT_MAX:       usize = 2;

/// Default timeouts, seconds.
pub const UDP_TIMEOUTS: [u32; UDP_CT_MAX] = [30, 120];

/// Seconds a replied flow must keep flowing before it counts as a stream and
/// earns the longer timeout plus the assured bit.
pub const UDP_STREAM_SECS: u32 = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UdpSysctl { pub timeouts: [u32; UDP_CT_MAX] }

impl Default for UdpSysctl {
    fn default() -> Self { Self { timeouts: UDP_TIMEOUTS } }
}

/// Per-entry UDP state: when the flow first became bidirectional.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct UdpTrack {
    /// Timestamp, seconds, at which the flow qualifies as a stream. Zero
    /// before a reply has been seen.
    pub stream_ts: u64,
}

/// Outcome of one UDP packet.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UdpResult { pub timeout: u32, pub set_assured: bool }

/// Track one UDP packet. `seen_reply` and `assured` are the entry's current
/// status bits; `now` is the current time in seconds.
/// # C: O(1)
pub fn packet(track: &mut UdpTrack, seen_reply: bool, assured: bool, now: u64,
              sysctl: &UdpSysctl) -> UdpResult
{
    if !seen_reply {
        // Arm the stream clock the moment a reply could next arrive, so the
        // grace period is measured from first bidirectional contact rather
        // than from the flow's birth.
        track.stream_ts = now + UDP_STREAM_SECS as u64;
        return UdpResult { timeout: sysctl.timeouts[UDP_CT_UNREPLIED], set_assured: false };
    }
    if now > track.stream_ts {
        UdpResult { timeout: sysctl.timeouts[UDP_CT_REPLIED], set_assured: !assured }
    } else {
        UdpResult { timeout: sysctl.timeouts[UDP_CT_UNREPLIED], set_assured: false }
    }
}
