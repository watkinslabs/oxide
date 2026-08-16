//! TCP tracker: takes a segment plus the current tracking state and returns
//! the verdict, the new state, and the timeout to arm. Every decision here is
//! a pure function of the arguments so the whole state machine is testable
//! without a packet path.

use super::tcp_state::*;
use super::tcp_window::{TcpAction, TcpSeg, TcpTrack, after, before, in_window, parse_options};
use crate::uapi::{IPS_ASSURED, IPS_FIXED_TIMEOUT, IPS_SEEN_REPLY};

/// What the tracker decided about one segment.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpVerdict {
    /// Pass, arm `timeout` seconds, and apply the accumulated state.
    Accept { timeout: u32 },
    /// Pass without touching state or timeout.
    Ignore,
    /// Refuse the packet; the flow keeps its current state.
    Invalid,
    /// Kill the entry and re-look-up: a closed connection is being reopened.
    Repeat,
    /// Kill the entry — a reply RST to a never-established flow.
    Kill,
}

/// Tunables the TCP tracker reads.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TcpSysctl {
    pub timeouts: [u32; TCP_CONNTRACK_TIMEOUT_MAX],
    pub max_retrans: u8,
    /// Accept mid-connection pickups (no SYN seen).
    pub loose: bool,
    /// Never mark a segment invalid on window grounds.
    pub be_liberal: bool,
    /// Accept a RST whose sequence precedes the peer's highest ACK.
    pub ignore_invalid_rst: bool,
}

impl Default for TcpSysctl {
    fn default() -> Self {
        Self { timeouts: TCP_TIMEOUTS, max_retrans: TCP_MAX_RETRANS,
               loose: true, be_liberal: false, ignore_invalid_rst: false }
    }
}

/// Seed a fresh entry from its first segment. `false` means the segment cannot
/// open a connection — an out-of-the-blue ACK with pickup disabled, or a flag
/// combination the table calls invalid from `NONE`.
/// # C: O(len(options))
pub fn new_conn(track: &mut TcpTrack, seg: &TcpSeg, sysctl: &TcpSysctl) -> bool {
    if !valid_flags(seg.flags) { return false; }
    let index = conntrack_index(seg.flags);
    let next = TCP_CONNTRACKS[0][index][TCP_CONNTRACK_NONE as usize];
    if next >= TCP_CONNTRACK_MAX { return false; }
    *track = TcpTrack::default();
    if next == TCP_CONNTRACK_SYN_SENT {
        track.seen[0].td_end = seg.end();
        track.seen[0].td_maxwin = if seg.win == 0 { 1 } else { seg.win as u32 };
        track.seen[0].td_maxend = track.seen[0].td_end;
        let opts = parse_options(seg.options);
        track.seen[0].td_scale = opts.scale;
        track.seen[0].flags = opts.flags;
    } else if !sysctl.loose {
        return false;
    } else {
        track.seen[0].td_end = seg.end();
        track.seen[0].td_maxwin = if seg.win == 0 { 1 } else { seg.win as u32 };
        track.seen[0].td_maxend = track.seen[0].td_end
            .wrapping_add(track.seen[0].td_maxwin);
        // History is lost, so assume both SACK and a liberal window rather than
        // rejecting every segment of a connection that predates us.
        track.seen[0].flags = IP_CT_TCP_FLAG_SACK_PERM | IP_CT_TCP_FLAG_BE_LIBERAL;
        track.seen[1].flags = IP_CT_TCP_FLAG_SACK_PERM | IP_CT_TCP_FLAG_BE_LIBERAL;
    }
    track.last_index = TCP_NONE_SET;
    true
}

/// Timeout to arm for `new_state`, applying every shortening rule: excessive
/// retransmissions, a RST, unacknowledged data, and a zero window each cap the
/// timeout below the per-state default. # C: O(1)
pub fn select_timeout(track: &TcpTrack, new_state: u8, index: usize,
                      sysctl: &TcpSysctl) -> u32
{
    let t = &sysctl.timeouts;
    let base = t[new_state as usize];
    if track.retrans >= sysctl.max_retrans
        && base > t[TCP_CONNTRACK_RETRANS as usize] { return t[TCP_CONNTRACK_RETRANS as usize]; }
    if index == TCP_RST_SET { return t[TCP_CONNTRACK_CLOSE as usize]; }
    if (track.seen[0].flags | track.seen[1].flags) & IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED != 0
        && base > t[TCP_CONNTRACK_UNACK as usize] { return t[TCP_CONNTRACK_UNACK as usize]; }
    if track.last_win == 0 && base > t[TCP_CONNTRACK_RETRANS as usize] {
        return t[TCP_CONNTRACK_RETRANS as usize];
    }
    base
}

/// Status-bit updates a tracker run implies. The caller owns `status`, so the
/// tracker reports the transitions rather than reaching into the entry.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpStatusDelta { pub set_assured: bool, pub protoinfo_changed: bool }

/// Run one segment through the tracker. `status` is the entry's current
/// `IPS_*` word; `confirmed` says whether the entry is already in the table.
/// # C: O(len(options))
pub fn packet(track: &mut TcpTrack, dir: u8, seg: &TcpSeg, status: u32,
              confirmed: bool, sysctl: &TcpSysctl)
    -> (TcpVerdict, TcpStatusDelta)
{
    let mut delta = TcpStatusDelta::default();
    if !valid_flags(seg.flags) { return (TcpVerdict::Invalid, delta); }
    if !confirmed && !new_conn(track, seg, sysctl) {
        return (TcpVerdict::Invalid, delta);
    }

    let old_state = track.state;
    let index = conntrack_index(seg.flags);
    let mut new_state = TCP_CONNTRACKS[dir as usize][index][old_state as usize];
    let mut skip_window = false;
    let mut effective_old = old_state;

    match new_state {
        TCP_CONNTRACK_SYN_SENT if old_state >= TCP_CONNTRACK_TIME_WAIT => {
            // A SYN reopening a closed or aborted connection: the entry
            // describes a conversation that no longer exists.
            if (track.seen[dir as usize].flags | track.seen[1 - dir as usize].flags)
                & IP_CT_TCP_FLAG_CLOSE_INIT != 0
                || (track.last_dir == dir && track.last_index == TCP_RST_SET)
            {
                return (TcpVerdict::Repeat, delta);
            }
            match ignore_path(track, dir, index, seg, old_state, &mut new_state,
                              &mut effective_old) {
                Some(v) => return (v, delta),
                None => { skip_window = false; }
            }
        }
        TCP_CONNTRACK_IGNORE => {
            match ignore_path(track, dir, index, seg, old_state, &mut new_state,
                              &mut effective_old) {
                Some(v) => return (v, delta),
                None => {}
            }
        }
        TCP_CONNTRACK_MAX => return (TcpVerdict::Invalid, delta),
        TCP_CONNTRACK_TIME_WAIT => {
            // A challenge-ACK answering a spurious SYN must not be read as the
            // ACK that completes a close.
            if old_state == TCP_CONNTRACK_LAST_ACK && index == TCP_ACK_SET
                && track.last_dir != dir && track.last_index == TCP_SYN_SET
                && track.last_flags & IP_CT_EXP_CHALLENGE_ACK != 0
            {
                track.last_flags &= !IP_CT_EXP_CHALLENGE_ACK;
                return (TcpVerdict::Accept { timeout: sysctl.timeouts[old_state as usize] },
                        delta);
            }
        }
        TCP_CONNTRACK_SYN_SENT2 => { track.last_flags |= IP_CT_TCP_SIMULTANEOUS_OPEN; }
        TCP_CONNTRACK_SYN_RECV => {
            if dir == 1 && index == TCP_ACK_SET
                && track.last_flags & IP_CT_TCP_SIMULTANEOUS_OPEN != 0
            {
                new_state = TCP_CONNTRACK_ESTABLISHED;
            }
        }
        TCP_CONNTRACK_CLOSE if index == TCP_RST_SET => {
            skip_window = rst_path(track, dir, seg, old_state, status, sysctl,
                                   &mut new_state);
        }
        _ => {}
    }

    if !skip_window {
        match in_window(track, dir, index, seg, sysctl.be_liberal) {
            TcpAction::Ignore  => return (TcpVerdict::Ignore, delta),
            TcpAction::Invalid => return (TcpVerdict::Invalid, delta),
            TcpAction::Accept  => {}
        }
    }

    track.last_index = index;
    track.last_dir = dir;
    track.state = new_state;
    if effective_old != new_state && new_state == TCP_CONNTRACK_FIN_WAIT {
        track.seen[dir as usize].flags |= IP_CT_TCP_FLAG_CLOSE_INIT;
    }
    delta.protoinfo_changed = new_state != effective_old;

    let mut timeout = select_timeout(track, new_state, index, sysctl);
    if status & IPS_SEEN_REPLY == 0 {
        // A flow whose only reply is a RST never established; drop it now
        // rather than holding a dead entry for the close timeout.
        if seg.flags & TCPHDR_RST != 0 { return (TcpVerdict::Kill, delta); }
        if index == TCP_SYN_SET && effective_old == TCP_CONNTRACK_SYN_SENT {
            // A SYN retransmit must not renew the timeout, or a client (or a
            // NAT in front of one) can hold a binding open indefinitely.
            return (TcpVerdict::Ignore, delta);
        }
        if new_state == TCP_CONNTRACK_ESTABLISHED
            && timeout > sysctl.timeouts[TCP_CONNTRACK_UNACK as usize]
        {
            timeout = sysctl.timeouts[TCP_CONNTRACK_UNACK as usize];
        }
    } else if status & IPS_ASSURED == 0
        && (effective_old == TCP_CONNTRACK_SYN_RECV
            || effective_old == TCP_CONNTRACK_ESTABLISHED)
        && new_state == TCP_CONNTRACK_ESTABLISHED
    {
        delta.set_assured = true;
    }
    if status & IPS_FIXED_TIMEOUT != 0 { timeout = 0; }
    (TcpVerdict::Accept { timeout }, delta)
}

/// The IGNORE arm. Returns `Some(verdict)` when the packet is genuinely
/// ignored, or `None` when the recorded SYN lets the tracker resynchronise and
/// fall through to the window check.
fn ignore_path(track: &mut TcpTrack, dir: u8, index: usize, seg: &TcpSeg,
               old_state: u8, new_state: &mut u8, effective_old: &mut u8)
    -> Option<TcpVerdict>
{
    if index == TCP_SYNACK_SET && track.last_index == TCP_SYN_SET
        && track.last_dir != dir && seg.ack == track.last_end
    {
        // This SYN/ACK answers the SYN annotated earlier: both peers agree and
        // only the tracker was behind. Adopt the recorded values.
        *effective_old = TCP_CONNTRACK_SYN_SENT;
        *new_state = TCP_CONNTRACK_SYN_RECV;
        let ld = track.last_dir as usize;
        track.seen[ld].td_end = track.last_end;
        track.seen[ld].td_maxend = track.last_end;
        track.seen[ld].td_maxwin = if track.last_win == 0 { 1 } else { track.last_win as u32 };
        track.seen[ld].td_scale = track.last_wscale;
        track.last_flags &= !IP_CT_EXP_CHALLENGE_ACK;
        track.seen[ld].flags = track.last_flags;
        let d = dir as usize;
        track.seen[d].td_end = 0;
        track.seen[d].td_maxend = 0;
        track.seen[d].td_maxwin = 0;
        track.seen[d].td_maxack = 0;
        track.seen[d].td_scale = 0;
        track.seen[d].flags &= IP_CT_TCP_FLAG_BE_LIBERAL;
        return None;
    }
    track.last_index = index;
    track.last_dir = dir;
    track.last_seq = seg.seq;
    track.last_end = seg.end();
    track.last_win = seg.win;
    if index == TCP_SYN_SET && dir == 0 {
        track.last_flags = 0;
        track.last_wscale = 0;
        let opts = parse_options(seg.options);
        if opts.flags & IP_CT_TCP_FLAG_WINDOW_SCALE != 0 {
            track.last_flags |= IP_CT_TCP_FLAG_WINDOW_SCALE;
            track.last_wscale = opts.scale;
        }
        if opts.flags & IP_CT_TCP_FLAG_SACK_PERM != 0 {
            track.last_flags |= IP_CT_TCP_FLAG_SACK_PERM;
        }
        // From LAST_ACK a bare ACK is ambiguous: it may complete the close or
        // be a challenge answering this SYN. Record which so the TIME_WAIT arm
        // can tell them apart.
        if old_state == TCP_CONNTRACK_LAST_ACK {
            track.last_flags |= IP_CT_EXP_CHALLENGE_ACK;
        }
    }
    if old_state == TCP_CONNTRACK_SYN_SENT && index == TCP_ACK_SET && dir == 1 {
        track.last_ack = seg.ack;
    }
    Some(TcpVerdict::Ignore)
}

/// The RST arm. Returns whether the window check should be skipped.
fn rst_path(track: &TcpTrack, dir: u8, seg: &TcpSeg, old_state: u8, status: u32,
            sysctl: &TcpSysctl, new_state: &mut u8) -> bool
{
    if can_early_drop(old_state) { return true; }
    let peer = track.seen[1 - dir as usize];
    if peer.flags & IP_CT_TCP_FLAG_MAXACK_SET != 0 && track.last_index != TCP_SYN_SET {
        let established = old_state == TCP_CONNTRACK_ESTABLISHED;
        if seg.seq == 0 && !established { return false; }
        if before(seg.seq, peer.td_maxack) && !sysctl.ignore_invalid_rst {
            // A RST below the peer's highest ACK is a blind injection attempt.
            *new_state = u8::from(TCP_CONNTRACK_MAX);
            return false;
        }
        if !established || seg.seq == peer.td_maxack { return false; }
        if track.last_index == TCP_ACK_SET && track.last_dir == dir
            && seg.seq == track.last_end { return false; }
        // The sequence is off but plausible; hold the state so a challenge ACK
        // can still arrive.
        *new_state = old_state;
    }
    if ((status & IPS_SEEN_REPLY != 0 && track.last_index == TCP_SYN_SET
         && track.last_dir != dir)
        || (status & IPS_ASSURED == 0 && track.last_index == TCP_ACK_SET))
        && seg.ack == track.last_end
    { return true; }
    if old_state == TCP_CONNTRACK_SYN_SENT && track.last_index == TCP_ACK_SET
        && track.last_dir == 1 && seg.seq == track.last_ack
    { return true; }
    false
}

/// Whether `after` reports a strict ordering — re-exported so callers testing
/// sequence comparisons use the same arithmetic the tracker does. # C: O(1)
pub fn seq_after(a: u32, b: u32) -> bool { after(a, b) }
