//! Multiplexer command handling.
//!
//! Every command arrives on DLCI 0 and every one of them is answered: a command
//! this end does not implement is refused by type rather than dropped, because
//! a peer that gets no answer waits out its timeout instead of falling back.

use crate::uapi::bt::{BT_CONFIG, BT_CONNECT, BT_CONNECTED, BT_OPEN};
use crate::uapi::rfcomm as u;
use super::dlc::Dlc;
use super::frame::Frame;
use super::link::{DlcEvent, SessionHost};
use super::mcc::{self, Mcc, Msc, Pn};
use super::rpn;
use super::session::Session;

impl Session {
    /// Dispatch one multiplexer command. # C: O(n)
    pub(super) fn recv_mcc<H: SessionHost>(&mut self, f: &Frame<'_>, host: &mut H) {
        let Some(m) = mcc::decode(f.payload) else { return; };
        match m.cmd {
            Mcc::Pn(pn) => self.recv_pn(m.cr, &pn, host),
            Mcc::Rpn(r) => {
                if !m.cr { return; }
                let reply = rpn::negotiate(&r);
                if let Some(d) = self.dlc_mut(r.dlci) { d.port.apply(&r); }
                self.send_mcc(false, &Mcc::Rpn(reply), host);
            }
            Mcc::RpnQuery(dlci) => {
                if !m.cr { return; }
                let reply = rpn::query_reply(dlci);
                self.send_mcc(false, &Mcc::Rpn(reply), host);
            }
            Mcc::Rls(r) => {
                if !m.cr { return; }
                self.events.push(DlcEvent::LineStatus { dlci: r.dlci, status: r.status });
                self.send_mcc(false, &Mcc::Rls(r), host);
            }
            Mcc::Msc(msc) => self.recv_msc(m.cr, &msc, host),
            Mcc::Fcoff => {
                if !m.cr { return; }
                self.tx_throttled = true;
                self.send_mcc(false, &Mcc::Fcoff, host);
            }
            Mcc::Fcon => {
                if !m.cr { return; }
                self.tx_throttled = false;
                self.send_mcc(false, &Mcc::Fcon, host);
            }
            Mcc::Test(pattern) => {
                if !m.cr { return; }
                self.send_mcc(false, &Mcc::Test(pattern), host);
            }
            Mcc::Nsc(_) => {}
            Mcc::Unknown(ty) => {
                let refused = u::mcc_type(m.cr, ty);
                self.send_mcc(false, &Mcc::Nsc(refused), host);
            }
        }
    }

    /// Parameter negotiation. A request for a DLC that does not exist is the
    /// peer opening a channel; a response advances a DLC this end opened.
    /// # C: O(n)
    fn recv_pn<H: SessionHost>(&mut self, cr: bool, pn: &Pn, host: &mut H) {
        let dlci = pn.dlci;
        if dlci == 0 { return; }
        if self.dlc(dlci).is_some() {
            if cr {
                self.apply_pn(dlci, cr, pn);
                let cfc = self.cfc;
                let Some(d) = self.dlc(dlci) else { return; };
                let reply = d.pn(false, cfc, d.mtu);
                self.send_mcc(false, &Mcc::Pn(reply), host);
            } else if self.dlc(dlci).map(|d| d.state) == Some(BT_CONFIG) {
                self.apply_pn(dlci, cr, pn);
                if let Some(d) = self.dlc_mut(dlci) { d.state = BT_CONNECT; }
                self.send_cmd(dlci, u::RFCOMM_SABM, host);
            }
            return;
        }
        if !cr { return; }
        let channel = u::srv_channel(dlci);
        if host.connect_ind(channel) {
            let d = Dlc::new(dlci, self.cmd_addr(dlci));
            self.dlcs.push(d);
            self.apply_pn(dlci, cr, pn);
            let cfc = self.cfc;
            if let Some(d) = self.dlc_mut(dlci) { d.state = BT_OPEN; }
            let Some(d) = self.dlc(dlci) else { return; };
            let reply = d.pn(false, cfc, d.mtu);
            self.send_mcc(false, &Mcc::Pn(reply), host);
        } else {
            self.send_rsp(dlci, u::RFCOMM_DM, host);
        }
    }

    /// Adopt a negotiated parameter set. The MTU a request asks for is capped by
    /// this end's ceiling; a response's is taken as agreed. The first DLC to
    /// settle credit flow settles it for the session. # C: O(n)
    pub(super) fn apply_pn(&mut self, dlci: u8, cr: bool, pn: &Pn) {
        let session_cfc = self.cfc;
        let session_mtu = self.mtu;
        let dlc_cfc = match self.dlc_mut(dlci) {
            Some(d) => {
                let c = d.credit.apply_pn(pn, session_cfc);
                d.priority = pn.priority;
                d.mtu = pn.mtu;
                if cr && d.mtu > session_mtu { d.mtu = session_mtu; }
                c
            }
            None => return,
        };
        if self.cfc == u::RFCOMM_CFC_UNKNOWN { self.cfc = dlc_cfc; }
    }

    /// Modem status. A request updates this end's view of the peer's signals,
    /// is answered, and — when credit flow is off — carries the peer's flow
    /// stop and start. Both directions must be seen before data may flow.
    /// # C: O(n)
    fn recv_msc<H: SessionHost>(&mut self, cr: bool, msc: &Msc, host: &mut H) {
        let dlci = msc.dlci;
        if self.dlc(dlci).is_none() { return; }
        if !cr {
            if let Some(d) = self.dlc_mut(dlci) { d.mscex |= u::RFCOMM_MSCEX_TX; }
            return;
        }
        if let Some(d) = self.dlc_mut(dlci) {
            let fc = msc.v24_sig & u::RFCOMM_V24_FC != 0;
            d.credit.tx_throttled = fc && !d.credit.enabled();
            d.remote_v24_sig = msc.v24_sig;
            d.mscex |= u::RFCOMM_MSCEX_RX;
        }
        self.events.push(DlcEvent::ModemStatus { dlci, v24_sig: msc.v24_sig });
        self.send_mcc(false, &Mcc::Msc(Msc { dlci, v24_sig: msc.v24_sig }), host);
    }

    /// Report this end's signals to the peer, which is also how a change to the
    /// local modem lines reaches it. # C: O(n)
    pub fn send_modem_status<H: SessionHost>(&mut self, dlci: u8, v24_sig: u8, host: &mut H) {
        if let Some(d) = self.dlc_mut(dlci) { d.v24_sig = v24_sig; }
        self.send_mcc(true, &Mcc::Msc(Msc { dlci, v24_sig }), host);
    }

    /// Report a line-status condition to the peer. # C: O(n)
    pub fn send_line_status<H: SessionHost>(&mut self, dlci: u8, status: u8, host: &mut H) {
        self.send_mcc(true, &Mcc::Rls(super::mcc::Rls { dlci, status }), host);
    }

    /// Ask the peer to negotiate a port's parameters. # C: O(n)
    pub fn send_port_negotiation<H: SessionHost>(&mut self, dlci: u8, mask: u16, host: &mut H) {
        let settings = match self.dlc(dlci) { Some(d) => d.port, None => return };
        self.send_mcc(true, &Mcc::Rpn(settings.to_rpn(dlci, mask)), host);
    }

    /// Whether a DLC is up and both directions of the modem-status exchange
    /// have completed. # C: O(n)
    pub fn dlc_ready(&self, dlci: u8) -> bool {
        matches!(self.dlc(dlci), Some(d) if d.state == BT_CONNECTED && d.mscex_complete())
    }
}
