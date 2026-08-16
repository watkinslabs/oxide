//! The multiplexer session: one control channel and the DLCs multiplexed onto
//! it.
//!
//! Which end initiated the session decides the direction bit of every DLCI it
//! opens and which end stamps the command bit on an address byte, so the same
//! server channel on the two ends is two different DLCIs and the two ends never
//! collide.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::bt::{BT_CLOSED, BT_CONFIG, BT_CONNECT, BT_CONNECT2, BT_CONNECTED, BT_DISCONN, BT_OPEN};
use crate::uapi::rfcomm as u;
use super::dlc::Dlc;
use super::frame::{self, Frame, FrameError};
use super::link::{DlcEvent, L2capTx, SessionHost};
use super::mcc::{self, Mcc};

/// One multiplexer session.
pub struct Session {
    pub initiator: bool,
    pub state: u8,
    /// Session-wide credit-flow decision, adopted from the first DLC to
    /// negotiate and applied to every later one.
    pub cfc: i16,
    /// Ceiling this end imposes on any DLC's negotiated MTU.
    pub mtu: u16,
    /// Set by a flow-off command: every DLC stops transmitting.
    pub tx_throttled: bool,
    pub dlcs: Vec<Dlc>,
    pub events: Vec<DlcEvent>,
}

impl Session {
    /// A session in the open state, before the control channel is established.
    /// # C: O(1)
    pub fn new(initiator: bool) -> Session {
        Session {
            initiator,
            state: BT_OPEN,
            cfc: u::RFCOMM_CFC_UNKNOWN,
            mtu: u::RFCOMM_DEFAULT_MTU,
            tx_throttled: false,
            dlcs: Vec::new(),
            events: Vec::new(),
        }
    }

    /// The direction bit this session's own DLCIs carry. # C: O(1)
    pub fn dir(&self) -> u8 { u::session_dir(self.initiator) }

    /// The DLCI of a server channel on this session. # C: O(1)
    pub fn dlci_of(&self, channel: u8) -> u8 { u::dlci(self.dir(), channel) }

    /// The address byte of a command this end sends. # C: O(1)
    pub fn cmd_addr(&self, dlci: u8) -> u8 { u::addr(self.initiator, dlci) }

    /// The address byte of a response this end sends, which carries the
    /// opposite command bit. # C: O(1)
    pub fn rsp_addr(&self, dlci: u8) -> u8 { u::addr(!self.initiator, dlci) }

    /// The DLC with this DLCI. # C: O(n)
    pub fn dlc(&self, dlci: u8) -> Option<&Dlc> { self.dlcs.iter().find(|d| d.dlci == dlci) }

    /// Mutable access to the DLC with this DLCI. # C: O(n)
    pub fn dlc_mut(&mut self, dlci: u8) -> Option<&mut Dlc> {
        self.dlcs.iter_mut().find(|d| d.dlci == dlci)
    }

    /// Drop a DLC from the session. # C: O(n)
    pub fn unlink(&mut self, dlci: u8) {
        if let Some(i) = self.dlcs.iter().position(|d| d.dlci == dlci) { self.dlcs.remove(i); }
    }

    /// Record a state change for the layer above. # C: O(1)
    pub fn note_state(&mut self, dlci: u8, state: u8, err: i32) {
        self.events.push(DlcEvent::StateChange { dlci, state, err });
    }

    /// Open a DLC on a server channel. The channel must name a data channel and
    /// must not already be open on this session; a session that is already up
    /// starts the negotiation immediately. # C: O(n)
    pub fn open<H: SessionHost>(&mut self, channel: u8, host: &mut H) -> Result<u8, Errno> {
        if !u::channel_valid(channel) { return Err(Errno::Einval); }
        let dlci = self.dlci_of(channel);
        if self.dlc(dlci).is_some() { return Err(Errno::Ebusy); }
        let mut d = Dlc::new(dlci, self.cmd_addr(dlci));
        d.out = true;
        d.state = BT_CONFIG;
        d.mtu = self.mtu;
        if self.cfc != u::RFCOMM_CFC_UNKNOWN { d.credit.cfc = self.cfc; }
        self.dlcs.push(d);
        if self.state == BT_CONNECTED { self.start_dlc(dlci, host); }
        Ok(dlci)
    }

    /// Begin a DLC's negotiation, after checking the link is secure enough for
    /// the level it asked for. # C: O(n)
    pub fn start_dlc<H: SessionHost>(&mut self, dlci: u8, host: &mut H) {
        let (sec_level, mtu) = match self.dlc(dlci) { Some(d) => (d.sec_level, self.mtu), None => return };
        if host.check_security(dlci, sec_level) {
            let cfc = self.cfc;
            let pn = match self.dlc_mut(dlci) {
                Some(d) => { d.mtu = mtu; d.pn(true, cfc, mtu) }
                None => return,
            };
            self.send_mcc(true, &Mcc::Pn(pn), host);
        } else if let Some(d) = self.dlc_mut(dlci) {
            d.set_flag(u::RFCOMM_AUTH_PENDING);
        }
    }

    /// Establish the control channel. # C: O(1)
    pub fn connect<H: L2capTx>(&mut self, host: &mut H) {
        self.state = BT_CONNECT;
        self.send_cmd(0, u::RFCOMM_SABM, host);
    }

    /// Send a link-control frame addressed as a command. # C: O(1)
    pub fn send_cmd<H: L2capTx>(&mut self, dlci: u8, ftype: u8, host: &mut H) {
        let f = frame::encode_cmd(self.cmd_addr(dlci), ftype, true);
        let _ = host.send(&f);
    }

    /// Send a link-control frame addressed as a response. # C: O(1)
    pub fn send_rsp<H: L2capTx>(&mut self, dlci: u8, ftype: u8, host: &mut H) {
        let f = frame::encode_cmd(self.rsp_addr(dlci), ftype, true);
        let _ = host.send(&f);
    }

    /// Send a multiplexer command on the control channel. # C: O(n)
    pub fn send_mcc<H: L2capTx>(&mut self, cr: bool, cmd: &Mcc, host: &mut H) {
        let f = mcc::encode(self.cmd_addr(0), cr, cmd);
        let _ = host.send(&f);
    }

    /// Hand a credit grant to the peer on a DLC. The grant rides a frame with no
    /// payload beyond the credit byte itself. # C: O(1)
    pub fn send_credits<H: L2capTx>(&mut self, addr: u8, credits: u8, host: &mut H) {
        let f = frame::encode_uih(addr, true, &[credits]);
        let _ = host.send(&f);
    }

    /// Accept a DLC the peer opened: answer it, mark it connected and report
    /// this end's signals. # C: O(n)
    pub fn accept<H: SessionHost>(&mut self, dlci: u8, host: &mut H) {
        self.send_rsp(dlci, u::RFCOMM_UA, host);
        let v24 = match self.dlc_mut(dlci) {
            Some(d) => { d.state = BT_CONNECTED; d.clear_flag(u::RFCOMM_DEFER_SETUP); d.v24_sig }
            None => return,
        };
        self.note_state(dlci, BT_CONNECTED, 0);
        self.send_mcc(true, &Mcc::Msc(super::mcc::Msc { dlci, v24_sig: v24 }), host);
    }

    /// Decide what to do with a DLC the peer is opening: hand it to userspace,
    /// accept it, or park it until a security procedure completes. # C: O(n)
    pub fn check_accept<H: SessionHost>(&mut self, dlci: u8, host: &mut H) {
        let (sec_level, channel) = match self.dlc(dlci) { Some(d) => (d.sec_level, d.channel()), None => return };
        if !host.check_security(dlci, sec_level) {
            if let Some(d) = self.dlc_mut(dlci) { d.set_flag(u::RFCOMM_AUTH_PENDING); }
            return;
        }
        if host.defer_setup(channel) {
            if let Some(d) = self.dlc_mut(dlci) {
                d.defer_setup = true;
                d.set_flag(u::RFCOMM_DEFER_SETUP);
                d.state = BT_CONNECT2;
            }
            self.note_state(dlci, BT_CONNECT2, 0);
        } else {
            self.accept(dlci, host);
        }
    }

    /// Close a DLC, reporting `err` to the layer above. A DLC that is up is
    /// disconnected on the wire first; one that never got that far is simply
    /// dropped. # C: O(n)
    pub fn close_dlc<H: L2capTx>(&mut self, dlci: u8, err: i32, host: &mut H) {
        let state = match self.dlc(dlci) { Some(d) => d.state, None => return };
        match state {
            BT_CONNECT | BT_CONNECTED => {
                if let Some(d) = self.dlc_mut(dlci) { d.state = BT_DISCONN; }
                self.send_cmd(dlci, u::RFCOMM_DISC, host);
            }
            _ => {
                if let Some(d) = self.dlc_mut(dlci) { d.state = BT_CLOSED; d.tx_queue.clear(); }
                self.note_state(dlci, BT_CLOSED, err);
                self.unlink(dlci);
            }
        }
    }

    /// Tear the whole session down, reporting `err` on every DLC it carried.
    /// # C: O(n)
    pub fn close(&mut self, err: i32) {
        let dlcis: Vec<u8> = self.dlcs.iter().map(|d| d.dlci).collect();
        for dlci in dlcis {
            if let Some(d) = self.dlc_mut(dlci) { d.state = BT_CLOSED; }
            self.note_state(dlci, BT_CLOSED, err);
        }
        self.dlcs.clear();
        self.state = BT_CLOSED;
    }

    /// Take one frame off the channel below and act on it. A frame whose check
    /// byte is wrong is reported rather than acted on. # C: O(n)
    pub fn recv<H: SessionHost>(&mut self, buf: &[u8], host: &mut H) -> Result<(), FrameError> {
        let f = frame::decode(buf)?;
        let dlci = f.dlci();
        let ftype = f.ftype();
        let pf = f.pf();
        match ftype {
            u::RFCOMM_SABM => { if pf { self.recv_sabm(dlci, host); } }
            u::RFCOMM_DISC => { if pf { self.recv_disc(dlci, host); } }
            u::RFCOMM_UA   => { if pf { self.recv_ua(dlci, host); } }
            u::RFCOMM_DM   => self.recv_dm(dlci),
            u::RFCOMM_UIH  => {
                if dlci != 0 { self.recv_data(dlci, pf, f.payload, host); }
                else { self.recv_mcc(&f, host); }
            }
            _ => {}
        }
        Ok(())
    }

    /// Set-asynchronous-balanced-mode: the peer is opening the control channel
    /// or a DLC. # C: O(n)
    fn recv_sabm<H: SessionHost>(&mut self, dlci: u8, host: &mut H) {
        if dlci == 0 {
            self.send_rsp(0, u::RFCOMM_UA, host);
            if self.state == BT_OPEN {
                self.state = BT_CONNECTED;
                self.process_connect(host);
            }
            return;
        }
        if let Some(d) = self.dlc(dlci) {
            if d.state == BT_OPEN { self.check_accept(dlci, host); }
            return;
        }
        let channel = u::srv_channel(dlci);
        if host.connect_ind(channel) {
            let d = Dlc::new(dlci, self.cmd_addr(dlci));
            self.dlcs.push(d);
            self.check_accept(dlci, host);
        } else {
            self.send_rsp(dlci, u::RFCOMM_DM, host);
        }
    }

    /// Unnumbered acknowledgement: the peer answered something this end sent.
    /// # C: O(n)
    fn recv_ua<H: SessionHost>(&mut self, dlci: u8, host: &mut H) {
        if dlci == 0 {
            match self.state {
                BT_CONNECT => { self.state = BT_CONNECTED; self.process_connect(host); }
                BT_DISCONN => self.close(Errno::Econnreset.as_i32()),
                _ => {}
            }
            return;
        }
        let state = match self.dlc(dlci) { Some(d) => d.state, None => { self.send_rsp(dlci, u::RFCOMM_DM, host); return; } };
        match state {
            BT_CONNECT => {
                let v24 = match self.dlc_mut(dlci) { Some(d) => { d.state = BT_CONNECTED; d.v24_sig } None => return };
                self.note_state(dlci, BT_CONNECTED, 0);
                self.send_mcc(true, &Mcc::Msc(super::mcc::Msc { dlci, v24_sig: v24 }), host);
            }
            BT_DISCONN => {
                if let Some(d) = self.dlc_mut(dlci) { d.state = BT_CLOSED; }
                self.note_state(dlci, BT_CLOSED, 0);
                self.unlink(dlci);
                if self.dlcs.is_empty() {
                    self.state = BT_DISCONN;
                    self.send_cmd(0, u::RFCOMM_DISC, host);
                }
            }
            _ => {}
        }
    }

    /// Disconnected mode: the peer refused, or reported a channel it does not
    /// have. A refusal during setup is a connection refused; later it is a
    /// reset. # C: O(n)
    fn recv_dm(&mut self, dlci: u8) {
        if dlci == 0 {
            let err = if self.state == BT_CONNECT { Errno::Econnrefused } else { Errno::Econnreset };
            self.close(err.as_i32());
            return;
        }
        let state = match self.dlc(dlci) { Some(d) => d.state, None => return };
        let err = if state == BT_CONNECT || state == BT_CONFIG { Errno::Econnrefused } else { Errno::Econnreset };
        if let Some(d) = self.dlc_mut(dlci) { d.state = BT_CLOSED; }
        self.note_state(dlci, BT_CLOSED, err.as_i32());
        self.unlink(dlci);
    }

    /// Disconnect: the peer is closing a DLC or the whole session. # C: O(n)
    fn recv_disc<H: SessionHost>(&mut self, dlci: u8, host: &mut H) {
        if dlci == 0 {
            self.send_rsp(0, u::RFCOMM_UA, host);
            let err = if self.state == BT_CONNECT { Errno::Econnrefused } else { Errno::Econnreset };
            self.close(err.as_i32());
            return;
        }
        let state = match self.dlc(dlci) { Some(d) => d.state, None => { self.send_rsp(dlci, u::RFCOMM_DM, host); return; } };
        self.send_rsp(dlci, u::RFCOMM_UA, host);
        let err = if state == BT_CONNECT || state == BT_CONFIG { Errno::Econnrefused } else { Errno::Econnreset };
        if let Some(d) = self.dlc_mut(dlci) { d.state = BT_CLOSED; }
        self.note_state(dlci, BT_CLOSED, err.as_i32());
        self.unlink(dlci);
    }

    /// Data on a DLC. A frame with the poll/final bit set leads with a credit
    /// grant, which is consumed here and never reaches the reader. # C: O(n)
    fn recv_data<H: SessionHost>(&mut self, dlci: u8, pf: bool, payload: &[u8], host: &mut H) {
        let Some(d) = self.dlc_mut(dlci) else { self.send_rsp(dlci, u::RFCOMM_DM, host); return; };
        let Some(rest) = d.credit.take_grant(pf, payload) else { return; };
        if rest.is_empty() || d.state != BT_CONNECTED { return; }
        d.credit.on_frame_received();
        let data = rest.to_vec();
        self.events.push(DlcEvent::Data { dlci, data });
    }

    /// Start every DLC that was waiting for the control channel. # C: O(n)
    pub fn process_connect<H: SessionHost>(&mut self, host: &mut H) {
        let pending: Vec<u8> = self.dlcs.iter().filter(|d| d.state == BT_CONFIG).map(|d| d.dlci).collect();
        for dlci in pending { self.start_dlc(dlci, host); }
    }
}

/// The frame a session would decode, for a caller that wants to inspect one
/// without driving a session. # C: O(1)
pub fn peek(buf: &[u8]) -> Result<Frame<'_>, FrameError> { frame::decode(buf) }
