//! The transmit pump: what a session does when it is asked to make progress.
//!
//! Nothing is written to the channel below from a send call. A send builds
//! frames and queues them; a pass over the session drains what the credit
//! accounting allows. That is what makes "out of credits" a state rather than a
//! blocking wait, and what lets a grant release exactly the queued frames it
//! pays for.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::bt::{BT_CLOSED, BT_CONNECTED, BT_DISCONN};
use crate::uapi::rfcomm as u;
use super::frame;
use super::link::SessionHost;
use super::mcc::{Mcc, Msc};
use super::session::Session;

impl Session {
    /// Queue data for a DLC, split into frames no larger than its negotiated
    /// MTU. Returns the number of bytes queued. # C: O(n)
    pub fn send_data(&mut self, dlci: u8, data: &[u8]) -> Result<usize, Errno> {
        let (addr, mtu) = match self.dlc(dlci) {
            Some(d) if d.state == BT_CONNECTED => (d.addr, d.mtu as usize),
            Some(_) => return Err(Errno::Enotconn),
            None => return Err(Errno::Enotconn),
        };
        if mtu == 0 { return Err(Errno::Einval); }
        let Some(d) = self.dlc_mut(dlci) else { return Err(Errno::Enotconn); };
        if data.is_empty() {
            d.tx_queue.push_back(frame::encode_uih(addr, false, data));
            return Ok(0);
        }
        for chunk in data.chunks(mtu) {
            d.tx_queue.push_back(frame::encode_uih(addr, false, chunk));
        }
        Ok(data.len())
    }

    /// Queue a disconnect behind whatever is already waiting, so a close does
    /// not overtake the data it follows. # C: O(n)
    pub fn queue_disc(&mut self, dlci: u8) {
        let addr = match self.dlc(dlci) { Some(d) => d.addr, None => return };
        if let Some(d) = self.dlc_mut(dlci) {
            d.state = BT_DISCONN;
            d.tx_queue.push_back(frame::encode_cmd(addr, u::RFCOMM_DISC, true));
        }
    }

    /// Drive one DLC: settle a pending modem status, top the peer's credits
    /// back up, then send what the credit allowance pays for. Returns the number
    /// of frames still queued. # C: O(n)
    pub fn process_tx<H: SessionHost>(&mut self, dlci: u8, host: &mut H) -> usize {
        let pending_msc = match self.dlc_mut(dlci) {
            Some(d) => if d.clear_flag(u::RFCOMM_MSC_PENDING) { Some(d.v24_sig) } else { None },
            None => return 0,
        };
        if let Some(v24) = pending_msc {
            self.send_mcc(true, &Mcc::Msc(Msc { dlci, v24_sig: v24 }), host);
        }

        let grant = match self.dlc_mut(dlci) {
            Some(d) => { if d.credit.enabled() { d.credit.topup() } else { d.credit.refill_noncfc(); None } }
            None => return 0,
        };
        if let Some(g) = grant {
            let addr = match self.dlc(dlci) { Some(d) => d.addr, None => return 0 };
            self.send_credits(addr, g, host);
        }

        loop {
            let Some(d) = self.dlc_mut(dlci) else { return 0; };
            if !d.credit.can_send() { break; }
            let Some(f) = d.tx_queue.pop_front() else { break; };
            if host.send(&f).is_err() {
                if let Some(d) = self.dlc_mut(dlci) { d.tx_queue.push_front(f); }
                break;
            }
            if let Some(d) = self.dlc_mut(dlci) { d.credit.on_frame_sent(); }
        }
        self.dlc(dlci).map(|d| d.tx_queue.len()).unwrap_or(0)
    }

    /// Drive every DLC on the session: retire the ones a timeout or a security
    /// verdict finished, then pump the ones that are ready. A session-wide flow
    /// stop suspends the pumping without touching the queues. # C: O(n)
    pub fn process<H: SessionHost>(&mut self, host: &mut H) {
        let dlcis: Vec<u8> = self.dlcs.iter().map(|d| d.dlci).collect();
        for dlci in dlcis {
            let Some(d) = self.dlc(dlci) else { continue; };
            if d.flag(u::RFCOMM_TIMED_OUT) { self.close_dlc(dlci, Errno::Etimedout.as_i32(), host); continue; }
            if d.flag(u::RFCOMM_ENC_DROP) { self.close_dlc(dlci, Errno::Econnrefused.as_i32(), host); continue; }

            let accept = self.dlc_mut(dlci).map(|d| d.clear_flag(u::RFCOMM_AUTH_ACCEPT)).unwrap_or(false);
            if accept {
                let out = self.dlc(dlci).map(|d| d.out).unwrap_or(false);
                if out { self.start_dlc(dlci, host); } else { self.check_accept(dlci, host); }
                continue;
            }
            let reject = self.dlc_mut(dlci).map(|d| d.clear_flag(u::RFCOMM_AUTH_REJECT)).unwrap_or(false);
            if reject {
                let out = self.dlc(dlci).map(|d| d.out).unwrap_or(false);
                if !out { self.send_rsp(dlci, u::RFCOMM_DM, host); }
                if let Some(d) = self.dlc_mut(dlci) { d.state = BT_CLOSED; }
                self.close_dlc(dlci, Errno::Econnrefused.as_i32(), host);
                continue;
            }

            let Some(d) = self.dlc(dlci) else { continue; };
            if d.flag(u::RFCOMM_SEC_PENDING) { continue; }
            if self.tx_throttled { continue; }
            let ready = matches!(d.state, BT_CONNECTED | BT_DISCONN) && d.mscex_complete();
            if ready { self.process_tx(dlci, host); }
        }
    }

    /// Record that the security procedure a DLC was waiting on succeeded. The
    /// DLC advances on the next pass rather than here, so one code path decides
    /// what an accepted DLC does. # C: O(n)
    pub fn auth_accept(&mut self, dlci: u8) {
        if let Some(d) = self.dlc_mut(dlci) {
            d.clear_flag(u::RFCOMM_AUTH_PENDING);
            d.set_flag(u::RFCOMM_AUTH_ACCEPT);
        }
    }

    /// Record that the security procedure a DLC was waiting on failed.
    /// # C: O(n)
    pub fn auth_reject(&mut self, dlci: u8) {
        if let Some(d) = self.dlc_mut(dlci) {
            d.clear_flag(u::RFCOMM_AUTH_PENDING);
            d.set_flag(u::RFCOMM_AUTH_REJECT);
        }
    }

    /// Mark a DLC's timer as having expired. # C: O(n)
    pub fn timed_out(&mut self, dlci: u8) {
        if let Some(d) = self.dlc_mut(dlci) { d.set_flag(u::RFCOMM_TIMED_OUT); }
    }

    /// Ask for this end's modem status to be reported on the next pass.
    /// # C: O(n)
    pub fn queue_modem_status(&mut self, dlci: u8, v24_sig: u8) {
        if let Some(d) = self.dlc_mut(dlci) { d.v24_sig = v24_sig; d.set_flag(u::RFCOMM_MSC_PENDING); }
    }
}
