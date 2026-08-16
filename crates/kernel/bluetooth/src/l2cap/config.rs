//! The BR/EDR configuration state machine: what to propose, how to answer a
//! proposal, and how to fold the answer to ours back into the channel.
//!
//! Each direction settles separately. Our proposal being accepted sets the
//! output side done; accepting the peer's sets the input side done; the channel
//! opens only when both are.

extern crate alloc;
use alloc::vec::Vec;

use super::chan::{Channel, CONF_EWS_RECV, CONF_INPUT_DONE, CONF_LOC_CONF_PEND, CONF_MODE_DONE, CONF_MTU_DONE, CONF_OUTPUT_DONE, CONF_RECV_NO_FCS, CONF_STATE2_DEVICE, FLAG_EFS_ENABLE, FLAG_EXT_CTRL};
use super::sig_bredr::select_mode;
use super::sig_conf::{parse_opts, Efs, RawOpt, Rfc};
use crate::uapi::l2cap as u;

/// What the link the channel runs over can do: the payload one packet carries,
/// and the feature mask the peer reported.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LinkCaps {
    /// Largest payload one packet on this link carries.
    pub mtu: u16,
    /// Extended feature mask the peer reported.
    pub feat_mask: u32,
}

impl LinkCaps {
    /// Whether the peer supports the extended window. # C: O(1)
    pub fn ews(&self) -> bool { self.feat_mask & u::FEAT_EXT_WINDOW != 0 }
    /// Whether the peer supports the extended flow specification. # C: O(1)
    pub fn efs(&self) -> bool { self.feat_mask & u::FEAT_EXT_FLOW != 0 }
    /// Whether the peer supports the frame check sequence option. # C: O(1)
    pub fn fcs(&self) -> bool { self.feat_mask & u::FEAT_FCS != 0 }
}

/// The channel cannot be configured on terms both ends accept, and must be
/// torn down rather than answered again.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Refused;

/// Largest PDU that fits one packet on this link once the widest possible
/// framing overhead is taken off. Sizing against the widest header rather than
/// the one currently in force keeps a later switch to the extended field from
/// making an already-agreed PDU too large. # C: O(1)
pub fn max_pdu_for_link(link_mtu: u16) -> u16 {
    let overhead = (u::EXT_HDR_SIZE + u::SDULEN_SIZE + u::FCS_SIZE) as u16;
    let room = link_mtu.saturating_sub(overhead);
    if room < u::DEFAULT_MAX_PDU_SIZE { room } else { u::DEFAULT_MAX_PDU_SIZE }
}

/// The options to propose for this channel. Called once per configuration
/// round; a second round proposes only what the peer's answer changed, which is
/// why the mode selection is skipped once any round has completed. # C: O(1)
pub fn build_conf_req(chan: &mut Channel, link: LinkCaps) -> Vec<RawOpt> {
    let first = chan.num_conf_req == 0 && chan.num_conf_rsp == 0;
    if first {
        match chan.mode {
            u::MODE_STREAMING | u::MODE_ERTM if chan.conf(CONF_STATE2_DEVICE) => {}
            u::MODE_STREAMING | u::MODE_ERTM => {
                if link.efs() { chan.set_flag(FLAG_EFS_ENABLE); }
                chan.mode = select_mode(chan.mode, link.feat_mask);
            }
            _ => { chan.mode = select_mode(chan.mode, link.feat_mask); }
        }
    }

    let mut opts = Vec::new();
    if chan.imtu != u::DEFAULT_MTU { opts.push(RawOpt::le16(u::CONF_MTU, chan.imtu)); }

    match chan.mode {
        u::MODE_BASIC => {
            if link.feat_mask & (u::FEAT_ERTM | u::FEAT_STREAMING) != 0 {
                opts.push(Rfc::basic().opt());
            }
        }
        u::MODE_ERTM => {
            chan.txwin_setup(link.ews());
            let rfc = Rfc {
                mode: u::MODE_ERTM,
                txwin_size: core::cmp::min(chan.tx_win, u::DEFAULT_TX_WINDOW) as u8,
                max_transmit: chan.max_tx,
                retrans_timeout: u::DEFAULT_RETRANS_TO,
                monitor_timeout: u::DEFAULT_MONITOR_TO,
                max_pdu_size: max_pdu_for_link(link.mtu),
            };
            opts.push(rfc.opt());
            if chan.flag(FLAG_EFS_ENABLE) { opts.push(local_efs(chan).opt()); }
            if chan.flag(FLAG_EXT_CTRL) { opts.push(RawOpt::le16(u::CONF_EWS, chan.tx_win)); }
            if link.fcs() && (chan.fcs == u::FCS_NONE || chan.conf(CONF_RECV_NO_FCS)) {
                chan.fcs = u::FCS_NONE;
                opts.push(RawOpt::byte(u::CONF_FCS, chan.fcs));
            }
        }
        u::MODE_STREAMING => {
            chan.txwin_setup(link.ews());
            let rfc = Rfc { mode: u::MODE_STREAMING, max_pdu_size: max_pdu_for_link(link.mtu), ..Rfc::default() };
            opts.push(rfc.opt());
            if chan.flag(FLAG_EFS_ENABLE) { opts.push(local_efs(chan).opt()); }
            if link.fcs() && (chan.fcs == u::FCS_NONE || chan.conf(CONF_RECV_NO_FCS)) {
                chan.fcs = u::FCS_NONE;
                opts.push(RawOpt::byte(u::CONF_FCS, chan.fcs));
            }
        }
        _ => {}
    }
    opts
}

/// The flow specification this end offers, which differs by mode in the
/// latency and flush figures it claims. # C: O(1)
fn local_efs(chan: &Channel) -> Efs {
    match chan.mode {
        u::MODE_STREAMING => Efs {
            id: u::BESTEFFORT_ID, stype: u::SERV_BESTEFFORT, msdu: chan.local_msdu,
            sdu_itime: chan.local_sdu_itime, acc_lat: 0, flush_to: 0,
        },
        _ => Efs {
            id: chan.local_id, stype: chan.local_stype, msdu: chan.local_msdu,
            sdu_itime: chan.local_sdu_itime, acc_lat: u::DEFAULT_ACC_LAT,
            flush_to: u::EFS_DEFAULT_FLUSH_TO,
        },
    }
}

/// Everything one configuration request proposed, after width checks. An option
/// whose value is the wrong width for its type is ignored rather than acted on,
/// which is what stops a malformed option from silently changing a parameter.
struct Proposal {
    mtu: Option<u16>,
    rfc: Rfc,
    efs: Option<Efs>,
    unknown: Vec<u8>,
}

/// Read the proposal out of an option list. An extended-window option is a
/// refusal: this end does not accept a peer-driven window widening in a
/// configuration request. # C: O(n)
fn read_proposal(chan: &mut Channel, buf: &[u8]) -> Result<Proposal, Refused> {
    let mut p = Proposal { mtu: None, rfc: Rfc::basic(), efs: None, unknown: Vec::new() };
    for o in parse_opts(buf).opts {
        match o.otype {
            u::CONF_MTU => { if let Some(v) = o.as_le16() { p.mtu = Some(v); } }
            u::CONF_FLUSH_TO => { if let Some(v) = o.as_le16() { chan.flush_to = v; } }
            u::CONF_QOS => {}
            u::CONF_RFC => { if let Some(v) = Rfc::decode(&o.val) { p.rfc = v; } }
            u::CONF_FCS => { if let Some(v) = o.as_byte() { if v == u::FCS_NONE { chan.set_conf(CONF_RECV_NO_FCS); } } }
            u::CONF_EFS => { if let Some(v) = Efs::decode(&o.val) { p.efs = Some(v); } }
            u::CONF_EWS => { if o.val.len() == u::CONF_EWS_LEN { return Err(Refused); } }
            _ => { if !o.hint { p.unknown.push(o.otype); } }
        }
    }
    Ok(p)
}

/// The answer to a peer's configuration request: the verdict and the options
/// that qualify it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfAnswer {
    pub result: u16,
    pub opts: Vec<RawOpt>,
}

/// Answer a complete configuration request. The channel's output direction is
/// marked done only when the whole proposal is acceptable. # C: O(n)
pub fn parse_conf_req(chan: &mut Channel, link: LinkCaps, buf: &[u8]) -> Result<ConfAnswer, Refused> {
    let p = read_proposal(chan, buf)?;
    let mut out: Vec<RawOpt> = Vec::new();
    let mut result = u::CONF_SUCCESS;
    for t in &p.unknown { result = u::CONF_UNKNOWN; out.push(RawOpt::byte(*t, *t)); }

    if chan.num_conf_rsp == 0 && chan.num_conf_req <= 1 {
        match chan.mode {
            u::MODE_STREAMING | u::MODE_ERTM => {
                if !chan.conf(CONF_STATE2_DEVICE) {
                    chan.mode = select_mode(p.rfc.mode, link.feat_mask);
                } else {
                    if p.efs.is_some() {
                        if link.efs() { chan.set_flag(FLAG_EFS_ENABLE); } else { return Err(Refused); }
                    }
                    if chan.mode != p.rfc.mode { return Err(Refused); }
                }
            }
            _ => {}
        }
    }

    let mut rfc = p.rfc;
    if chan.mode != rfc.mode {
        result = u::CONF_UNACCEPT;
        rfc.mode = chan.mode;
        if chan.num_conf_rsp == 1 { return Err(Refused); }
        out.push(rfc.opt());
    }

    if result == u::CONF_SUCCESS {
        // An absent MTU means the peer implied the default. Adjusting to a
        // previously agreed output MTU is only safe on the sequence-numbered
        // mode, where the peer can detect the adjustment.
        let mut mtu = p.mtu.unwrap_or(0);
        if mtu == 0 {
            mtu = if chan.mode == u::MODE_ERTM && chan.omtu != 0 && chan.omtu != u::DEFAULT_MTU { chan.omtu }
                  else { u::DEFAULT_MTU };
        }
        if mtu < u::DEFAULT_MIN_MTU { result = u::CONF_UNACCEPT; }
        else { chan.omtu = mtu; chan.set_conf(CONF_MTU_DONE); }
        out.push(RawOpt::le16(u::CONF_MTU, chan.omtu));

        if let Some(efs) = p.efs {
            if chan.local_stype != u::SERV_NOTRAFIC && efs.stype != u::SERV_NOTRAFIC && efs.stype != chan.local_stype {
                result = u::CONF_UNACCEPT;
                if chan.num_conf_req >= 1 { return Err(Refused); }
                out.push(efs.opt());
            } else {
                result = u::CONF_PENDING;
                chan.set_conf(CONF_LOC_CONF_PEND);
            }
        }

        match rfc.mode {
            u::MODE_BASIC => { chan.fcs = u::FCS_NONE; chan.set_conf(CONF_MODE_DONE); }
            u::MODE_ERTM => {
                if !chan.conf(CONF_EWS_RECV) { chan.remote_tx_win = rfc.txwin_size as u16; }
                else { rfc.txwin_size = u::DEFAULT_TX_WINDOW as u8; }
                chan.remote_max_tx = rfc.max_transmit;
                let size = core::cmp::min(rfc.max_pdu_size, max_pdu_for_link(link.mtu));
                rfc.max_pdu_size = size;
                chan.remote_mps = size;
                rfc.retrans_timeout = u::DEFAULT_RETRANS_TO;
                rfc.monitor_timeout = u::DEFAULT_MONITOR_TO;
                chan.set_conf(CONF_MODE_DONE);
                out.push(rfc.opt());
                if let Some(efs) = p.efs {
                    if chan.flag(FLAG_EFS_ENABLE) {
                        chan.remote_id = efs.id;
                        chan.remote_stype = efs.stype;
                        chan.remote_msdu = efs.msdu;
                        chan.remote_flush_to = efs.flush_to;
                        chan.remote_acc_lat = efs.acc_lat;
                        chan.remote_sdu_itime = efs.sdu_itime;
                        out.push(efs.opt());
                    }
                }
            }
            u::MODE_STREAMING => {
                let size = core::cmp::min(rfc.max_pdu_size, max_pdu_for_link(link.mtu));
                rfc.max_pdu_size = size;
                chan.remote_mps = size;
                chan.set_conf(CONF_MODE_DONE);
                out.push(rfc.opt());
            }
            _ => {
                result = u::CONF_UNACCEPT;
                out.push(Rfc { mode: chan.mode, ..Rfc::default() }.opt());
            }
        }

        if result == u::CONF_SUCCESS { chan.set_conf(CONF_OUTPUT_DONE); }
    }

    Ok(ConfAnswer { result, opts: out })
}

/// Fold a response to our proposal back into the channel, producing the options
/// of the follow-up request when the peer did not accept outright. `result` is
/// the verdict the peer sent, updated to unacceptable when a value it named is
/// one this end cannot use. # C: O(n)
pub fn parse_conf_rsp(chan: &mut Channel, buf: &[u8], result: &mut u16) -> Result<Vec<RawOpt>, Refused> {
    let mut out: Vec<RawOpt> = Vec::new();
    let mut rfc = Rfc::basic();
    let mut efs = None;

    for o in parse_opts(buf).opts {
        match o.otype {
            u::CONF_MTU => {
                let Some(v) = o.as_le16() else { continue };
                if v < u::DEFAULT_MIN_MTU { *result = u::CONF_UNACCEPT; chan.imtu = u::DEFAULT_MIN_MTU; }
                else { chan.imtu = v; }
                out.push(RawOpt::le16(u::CONF_MTU, chan.imtu));
            }
            u::CONF_FLUSH_TO => {
                let Some(v) = o.as_le16() else { continue };
                chan.flush_to = v;
                out.push(RawOpt::le16(u::CONF_FLUSH_TO, chan.flush_to));
            }
            u::CONF_RFC => {
                let Some(v) = Rfc::decode(&o.val) else { continue };
                rfc = v;
                if chan.conf(CONF_STATE2_DEVICE) && rfc.mode != chan.mode { return Err(Refused); }
                chan.fcs = u::FCS_NONE;
                out.push(rfc.opt());
            }
            u::CONF_EWS => {
                let Some(v) = o.as_le16() else { continue };
                chan.ack_win = core::cmp::min(v, chan.ack_win);
                out.push(RawOpt::le16(u::CONF_EWS, chan.tx_win));
            }
            u::CONF_EFS => {
                let Some(v) = Efs::decode(&o.val) else { continue };
                if chan.local_stype != u::SERV_NOTRAFIC && v.stype != u::SERV_NOTRAFIC && v.stype != chan.local_stype {
                    return Err(Refused);
                }
                efs = Some(v);
                out.push(v.opt());
            }
            u::CONF_FCS => {
                let Some(v) = o.as_byte() else { continue };
                if *result == u::CONF_PENDING && v == u::FCS_NONE { chan.set_conf(CONF_RECV_NO_FCS); }
            }
            _ => {}
        }
    }

    // A basic-mode channel cannot be talked into another mode by a response.
    if chan.mode == u::MODE_BASIC && chan.mode != rfc.mode { return Err(Refused); }
    chan.mode = rfc.mode;

    if *result == u::CONF_SUCCESS || *result == u::CONF_PENDING {
        match rfc.mode {
            u::MODE_ERTM => {
                chan.retrans_timeout = rfc.retrans_timeout;
                chan.monitor_timeout = rfc.monitor_timeout;
                chan.mps = rfc.max_pdu_size;
                if !chan.flag(FLAG_EXT_CTRL) { chan.ack_win = core::cmp::min(chan.ack_win, rfc.txwin_size as u16); }
                if chan.flag(FLAG_EFS_ENABLE) {
                    if let Some(e) = efs {
                        chan.local_msdu = e.msdu;
                        chan.local_sdu_itime = e.sdu_itime;
                        chan.local_acc_lat = e.acc_lat;
                        chan.local_flush_to = e.flush_to;
                    }
                }
            }
            u::MODE_STREAMING => { chan.mps = rfc.max_pdu_size; }
            _ => {}
        }
    }

    Ok(out)
}

/// Apply the parameters a successful response confirmed. Only the two
/// sequence-numbered modes carry any; a peer that answered success without
/// naming them is taken to have accepted sane defaults rather than zeroes.
/// # C: O(n)
pub fn conf_rfc_get(chan: &mut Channel, buf: &[u8]) {
    if chan.mode != u::MODE_ERTM && chan.mode != u::MODE_STREAMING { return; }
    let mut txwin_ext = chan.ack_win;
    let mut rfc = Rfc {
        mode: chan.mode,
        txwin_size: core::cmp::min(chan.ack_win, u::DEFAULT_TX_WINDOW) as u8,
        max_transmit: 0,
        retrans_timeout: u::DEFAULT_RETRANS_TO,
        monitor_timeout: u::DEFAULT_MONITOR_TO,
        max_pdu_size: chan.imtu,
    };
    for o in parse_opts(buf).opts {
        match o.otype {
            u::CONF_RFC => { if let Some(v) = Rfc::decode(&o.val) { rfc = v; } }
            u::CONF_EWS => { if let Some(v) = o.as_le16() { txwin_ext = v; } }
            _ => {}
        }
    }
    match rfc.mode {
        u::MODE_ERTM => {
            chan.retrans_timeout = rfc.retrans_timeout;
            chan.monitor_timeout = rfc.monitor_timeout;
            chan.mps = rfc.max_pdu_size;
            chan.ack_win = if chan.flag(FLAG_EXT_CTRL) { core::cmp::min(chan.ack_win, txwin_ext) }
                           else { core::cmp::min(chan.ack_win, rfc.txwin_size as u16) };
        }
        u::MODE_STREAMING => { chan.mps = rfc.max_pdu_size; }
        _ => {}
    }
}

/// What answering a configuration request produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReqHandled {
    /// The request declared more options to follow; the options so far are
    /// buffered and an empty success acknowledges the part received.
    Continuation,
    /// The request is complete and this is the answer to it.
    Answer(ConfAnswer),
    /// The buffered options would exceed what a channel accumulates; the
    /// request is rejected outright.
    TooLarge,
}

/// Take one configuration request. A multi-part request is accumulated until
/// its last part arrives, so the answer is decided against the whole proposal
/// and never against a fragment of it. # C: O(n)
pub fn conf_req_received(chan: &mut Channel, link: LinkCaps, flags: u16, opts: &[u8]) -> Result<ReqHandled, Refused> {
    if chan.conf_req.len() + opts.len() > super::chan::CONF_BUF_SIZE { return Ok(ReqHandled::TooLarge); }
    chan.conf_req.extend_from_slice(opts);
    if flags & u::CONF_FLAG_CONTINUATION != 0 { return Ok(ReqHandled::Continuation); }
    let buf = core::mem::take(&mut chan.conf_req);
    let answer = parse_conf_req(chan, link, &buf)?;
    if chan.num_conf_rsp < u::CONF_MAX_CONF_RSP { chan.num_conf_rsp += 1; }
    Ok(ReqHandled::Answer(answer))
}

/// What taking a configuration response produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RspHandled {
    /// The peer accepted; our side of the configuration is settled.
    InputDone,
    /// The peer disagreed; these options go out as a further request.
    Retry(Vec<RawOpt>),
    /// The peer answered pending, or declared more to follow; nothing settles
    /// yet.
    Pending,
}

/// Take one configuration response. A disagreement is answered with a further
/// request, but only within the round limit: past it the peer and this end
/// cannot agree and the channel goes down rather than negotiating forever.
/// # C: O(n)
pub fn conf_rsp_received(chan: &mut Channel, flags: u16, result: u16, opts: &[u8]) -> Result<RspHandled, Refused> {
    match result {
        u::CONF_SUCCESS => {
            conf_rfc_get(chan, opts);
            chan.clear_conf(super::chan::CONF_REM_CONF_PEND);
        }
        u::CONF_PENDING => {
            chan.set_conf(super::chan::CONF_REM_CONF_PEND);
            if chan.conf(CONF_LOC_CONF_PEND) {
                let mut r = result;
                let out = parse_conf_rsp(chan, opts, &mut r)?;
                chan.clear_conf(CONF_LOC_CONF_PEND);
                chan.set_conf(CONF_OUTPUT_DONE);
                return Ok(RspHandled::Retry(out));
            }
            return Ok(RspHandled::Pending);
        }
        u::CONF_UNKNOWN | u::CONF_UNACCEPT => {
            if chan.num_conf_rsp > u::CONF_MAX_CONF_RSP { return Err(Refused); }
            let mut r = u::CONF_SUCCESS;
            let out = parse_conf_rsp(chan, opts, &mut r)?;
            chan.num_conf_req = chan.num_conf_req.saturating_add(1);
            if r != u::CONF_SUCCESS { return Ok(RspHandled::Retry(out)); }
            return Ok(RspHandled::Retry(out));
        }
        _ => return Err(Refused),
    }
    if flags & u::CONF_FLAG_CONTINUATION != 0 { return Ok(RspHandled::Pending); }
    chan.set_conf(CONF_INPUT_DONE);
    Ok(RspHandled::InputDone)
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
