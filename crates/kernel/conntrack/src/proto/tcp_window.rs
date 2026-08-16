//! TCP window tracking. Sequence arithmetic is modulo 2^32, so every
//! comparison goes through `before`/`after` — a plain `<` on wrapped sequence
//! numbers silently inverts near the wrap and turns an in-window segment into
//! an invalid one (and the reverse, which is the security-relevant direction).

use super::tcp_state::*;

/// Per-direction window state.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpDirState {
    /// Highest `seq + len` this side has sent.
    pub td_end: u32,
    /// Highest sequence this side is permitted to reach.
    pub td_maxend: u32,
    /// Largest window this side has advertised, scaled.
    pub td_maxwin: u32,
    /// Highest ACK this side has emitted.
    pub td_maxack: u32,
    /// Window scale this side announced.
    pub td_scale: u8,
    /// `IP_CT_TCP_FLAG_*`.
    pub flags: u8,
}

/// Whole-connection TCP tracking state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TcpTrack {
    pub seen: [TcpDirState; 2],
    pub state: u8,
    /// Flag class of the last packet accepted or ignored.
    pub last_index: usize,
    pub last_dir: u8,
    pub last_seq: u32,
    pub last_ack: u32,
    pub last_end: u32,
    pub last_win: u16,
    pub last_wscale: u8,
    pub last_flags: u8,
    pub retrans: u8,
}

impl Default for TcpTrack {
    fn default() -> Self {
        Self { seen: [TcpDirState::default(); 2], state: TCP_CONNTRACK_NONE,
               last_index: TCP_NONE_SET, last_dir: 0, last_seq: 0, last_ack: 0,
               last_end: 0, last_win: 0, last_wscale: 0, last_flags: 0, retrans: 0 }
    }
}

/// One segment, as the tracker needs it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TcpSeg<'a> {
    pub seq: u32,
    pub ack: u32,
    pub win: u16,
    pub flags: u8,
    /// Payload byte count, excluding the TCP header.
    pub datalen: u32,
    /// Raw option bytes following the fixed 20-byte header.
    pub options: &'a [u8],
}

impl TcpSeg<'_> {
    /// Sequence one past the last byte this segment occupies. SYN and FIN each
    /// consume one sequence number; omitting them makes a bare SYN look
    /// zero-length and its ACK look out of window. # C: O(1)
    pub fn end(&self) -> u32 {
        let syn = u32::from(self.flags & TCPHDR_SYN != 0);
        let fin = u32::from(self.flags & TCPHDR_FIN != 0);
        self.seq.wrapping_add(self.datalen).wrapping_add(syn).wrapping_add(fin)
    }
}

/// Modulo-2^32 `a < b`. # C: O(1)
pub fn before(a: u32, b: u32) -> bool { (a.wrapping_sub(b) as i32) < 0 }
/// Modulo-2^32 `a > b`. # C: O(1)
pub fn after(a: u32, b: u32) -> bool { before(b, a) }

/// Outcome of the window check.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpAction {
    /// Pass the packet through without advancing state.
    Ignore,
    /// Refuse it.
    Invalid,
    /// In window; apply the state transition.
    Accept,
}

/// Options the tracker extracts.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpOptions { pub scale: u8, pub flags: u8 }

/// Parse the window-scale and SACK-permitted options. A malformed option list
/// stops the walk rather than being guessed at. # C: O(len(options))
pub fn parse_options(options: &[u8]) -> TcpOptions {
    let mut out = TcpOptions::default();
    let mut i = 0;
    while i < options.len() {
        let opcode = options[i];
        if opcode == TCPOPT_EOL { break; }
        if opcode == TCPOPT_NOP { i += 1; continue; }
        if i + 1 >= options.len() { break; }
        let opsize = options[i + 1];
        if opsize < 2 || (i + opsize as usize) > options.len() { break; }
        if opcode == TCPOPT_SACK_PERM && opsize == TCPOLEN_SACK_PERM {
            out.flags |= IP_CT_TCP_FLAG_SACK_PERM;
        } else if opcode == TCPOPT_WINDOW && opsize == TCPOLEN_WINDOW {
            out.scale = core::cmp::min(options[i + 2], TCP_MAX_WSCALE);
            out.flags |= IP_CT_TCP_FLAG_WINDOW_SCALE;
        }
        i += opsize as usize;
    }
    out
}

/// Highest right edge across every SACK block, or `ack` when there are none.
/// A SACK block acknowledges data beyond the cumulative ACK; ignoring it makes
/// the receiver's `td_end` lag and later segments fail the upper-bound check.
/// # C: O(len(options))
pub fn sack_right_edge(options: &[u8], ack: u32) -> u32 {
    let mut sack = ack;
    let mut i = 0;
    while i < options.len() {
        let opcode = options[i];
        if opcode == TCPOPT_EOL { break; }
        if opcode == TCPOPT_NOP { i += 1; continue; }
        if i + 1 >= options.len() { break; }
        let opsize = options[i + 1] as usize;
        if opsize < 2 || i + opsize > options.len() { break; }
        if opcode == TCPOPT_SACK && opsize >= 10 && (opsize - 2) % 8 == 0 {
            let mut p = i + 2;
            while p + 8 <= i + opsize {
                let end = u32::from_be_bytes([options[p + 4], options[p + 5],
                                              options[p + 6], options[p + 7]]);
                if after(end, sack) { sack = end; }
                p += 8;
            }
        }
        i += opsize;
    }
    sack
}

fn maxackwindow(sender: &TcpDirState) -> u32 {
    if sender.td_maxwin > MAXACKWINCONST { sender.td_maxwin } else { MAXACKWINCONST }
}

fn init_sender(sender: &mut TcpDirState, receiver: &mut TcpDirState,
               seg: &TcpSeg, end: u32, win: u32) {
    sender.td_end = end;
    let opts = parse_options(seg.options);
    sender.flags = (sender.flags & IP_CT_TCP_FLAG_BE_LIBERAL) | opts.flags;
    sender.td_scale = opts.scale;
    let swin = win << sender.td_scale;
    sender.td_maxwin = if swin == 0 { 1 } else { swin };
    sender.td_maxend = end.wrapping_add(sender.td_maxwin);
    // Both ends must announce window scaling for either to use it.
    if sender.flags & IP_CT_TCP_FLAG_WINDOW_SCALE == 0
        || receiver.flags & IP_CT_TCP_FLAG_WINDOW_SCALE == 0
    {
        sender.td_scale = 0;
        receiver.td_scale = 0;
    }
}

/// Window check for one segment, updating both directions' state. `dir` is the
/// direction the segment arrived in.
/// # C: O(len(options))
pub fn in_window(track: &mut TcpTrack, dir: u8, index: usize, seg: &TcpSeg,
                 be_liberal: bool) -> TcpAction
{
    let (sender_ix, receiver_ix) = (dir as usize, 1 - dir as usize);
    let mut sender = track.seen[sender_ix];
    let mut receiver = track.seen[receiver_ix];

    let mut seq = seg.seq;
    let mut ack = seg.ack;
    let win_raw = seg.win;
    let mut win = win_raw as u32;
    let mut end = seg.end();
    let mut sack = if receiver.flags & IP_CT_TCP_FLAG_SACK_PERM != 0 {
        sack_right_edge(seg.options, seg.ack)
    } else { seg.ack };

    if sender.td_maxwin == 0 {
        if seg.flags & TCPHDR_SYN != 0 {
            init_sender(&mut sender, &mut receiver, seg, end, win);
            if seg.flags & TCPHDR_ACK == 0 {
                track.seen[sender_ix] = sender;
                track.seen[receiver_ix] = receiver;
                return TcpAction::Accept; // simultaneous open
            }
        } else {
            // Mid-connection pickup: seed from the packet itself.
            sender.td_end = end;
            let swin = win << sender.td_scale;
            sender.td_maxwin = if swin == 0 { 1 } else { swin };
            sender.td_maxend = end.wrapping_add(sender.td_maxwin);
            if receiver.td_maxwin == 0 {
                receiver.td_end = sack;
                receiver.td_maxend = sack;
            } else if sack == receiver.td_end.wrapping_add(1) {
                receiver.td_end = receiver.td_end.wrapping_add(1);
            }
        }
    } else if seg.flags & TCPHDR_SYN != 0 && after(end, sender.td_end)
        && (track.state == TCP_CONNTRACK_SYN_SENT || track.state == TCP_CONNTRACK_SYN_RECV)
    {
        // Reinitialised connection: the peer restarted with fresh sequence
        // numbers, which RFC 793 permits.
        init_sender(&mut sender, &mut receiver, seg, end, win);
        if dir == 1 && seg.flags & TCPHDR_ACK == 0 {
            track.seen[sender_ix] = sender;
            track.seen[receiver_ix] = receiver;
            return TcpAction::Accept;
        }
    }

    if seg.flags & TCPHDR_ACK == 0 {
        ack = receiver.td_end;
        sack = receiver.td_end;
    } else if seg.flags & (TCPHDR_ACK | TCPHDR_RST) == (TCPHDR_ACK | TCPHDR_RST) && ack == 0 {
        // Stacks that set ACK on a RST but leave the field zero.
        ack = receiver.td_end;
        sack = receiver.td_end;
    }

    if seg.flags & TCPHDR_RST != 0 && seq == 0 && track.state == TCP_CONNTRACK_SYN_SENT {
        seq = sender.td_end;
        end = sender.td_end;
    }

    let liberal = be_liberal || sender.flags & IP_CT_TCP_FLAG_BE_LIBERAL != 0;
    let seq_ok = before(seq, sender.td_maxend.wrapping_add(1));
    if !seq_ok {
        let overshot = end.wrapping_sub(sender.td_maxend).wrapping_add(1);
        let ack_ok = after(sack, receiver.td_end.wrapping_sub(maxackwindow(&sender))
                                 .wrapping_sub(1));
        let in_recv_win = receiver.td_maxwin != 0
            && after(end, sender.td_end.wrapping_sub(receiver.td_maxwin).wrapping_sub(1));
        if in_recv_win && ack_ok && overshot <= receiver.td_maxwin
            && before(sack, receiver.td_end.wrapping_add(1))
        {
            // A peer that sent past its allowed window. Record the new end so a
            // later ACK for that data can still be matched, but do not advance
            // the state machine on it.
            sender.td_end = end;
            sender.flags |= IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED;
            track.seen[sender_ix] = sender;
            track.seen[receiver_ix] = receiver;
            return if liberal { TcpAction::Accept } else { TcpAction::Ignore };
        }
        return if liberal { TcpAction::Accept } else { TcpAction::Invalid };
    }

    if !before(sack, receiver.td_end.wrapping_add(1)) {
        return if liberal { TcpAction::Accept } else { TcpAction::Invalid };
    }
    let in_recv_win = receiver.td_maxwin == 0
        || after(end, sender.td_end.wrapping_sub(receiver.td_maxwin).wrapping_sub(1));
    if !in_recv_win {
        return if liberal { TcpAction::Accept } else { TcpAction::Ignore };
    }
    if !after(sack, receiver.td_end.wrapping_sub(maxackwindow(&sender)).wrapping_sub(1)) {
        return if liberal { TcpAction::Accept } else { TcpAction::Ignore };
    }

    if seg.flags & TCPHDR_SYN == 0 { win <<= sender.td_scale; }

    let swin = win.wrapping_add(sack.wrapping_sub(ack));
    if sender.td_maxwin < swin { sender.td_maxwin = swin; }
    if after(end, sender.td_end) {
        sender.td_end = end;
        sender.flags |= IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED;
    }
    if seg.flags & TCPHDR_ACK != 0 {
        if sender.flags & IP_CT_TCP_FLAG_MAXACK_SET == 0 {
            sender.td_maxack = ack;
            sender.flags |= IP_CT_TCP_FLAG_MAXACK_SET;
        } else if after(ack, sender.td_maxack) {
            sender.td_maxack = ack;
        }
    }

    if receiver.td_maxwin != 0 && after(end, sender.td_maxend) {
        receiver.td_maxwin = receiver.td_maxwin
            .wrapping_add(end.wrapping_sub(sender.td_maxend));
    }
    if after(sack.wrapping_add(win), receiver.td_maxend.wrapping_sub(1)) {
        receiver.td_maxend = sack.wrapping_add(win);
        if win == 0 { receiver.td_maxend = receiver.td_maxend.wrapping_add(1); }
    }
    if ack == receiver.td_end { receiver.flags &= !IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED; }

    track.seen[sender_ix] = sender;
    track.seen[receiver_ix] = receiver;

    if index == TCP_ACK_SET {
        if track.last_dir == dir && track.last_seq == seq && track.last_ack == ack
            && track.last_end == end && track.last_win == win_raw
        {
            track.retrans = track.retrans.saturating_add(1);
        } else {
            track.last_dir = dir;
            track.last_seq = seq;
            track.last_ack = ack;
            track.last_end = end;
            track.last_win = win_raw;
            track.retrans = 0;
        }
    }
    TcpAction::Accept
}
