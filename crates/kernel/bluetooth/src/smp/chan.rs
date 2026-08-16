//! Frame dispatch and the two ways a pairing starts.
//!
//! Every frame is checked against the set of codes the exchange expects next.
//! A frame that is not expected is dropped rather than acted on, except the
//! three key-distribution frames, which are refused explicitly so a peer
//! learns its key was not taken.

use crate::uapi::bt::{BT_SECURITY_HIGH, BT_SECURITY_MEDIUM};
use crate::uapi::smp::*;
use super::dist;
use super::legacy;
use super::level::{KeyPref, authreq_to_seclevel, check_enc_key_size, seclevel_to_authreq,
                   sufficient_security};
use super::method::{JUST_CFM, JUST_WORKS, table_method};
use super::pdu::{DecodeErr, PairingCmd, Pdu, decode, err_reason};
use super::sc;
use super::session::{Entropy, Events, Smp, SmpEvent, auth_req_mask};

/// The inputs a step needs from outside the session.
pub struct Step<'a> {
    pub now_ms: u64,
    /// Level the link currently satisfies.
    pub current_level: u8,
    /// Whether the link is encrypted with a pairing key rather than a stored one.
    pub stk_encrypted: bool,
    /// Whether a stored long-term key exists for the peer.
    pub have_ltk: bool,
    pub ent: &'a Entropy,
}

/// The requirements this host asks for when it starts a pairing.
///
/// A device with any way to interact asks for authentication even at a level
/// that does not demand it, because the ask costs nothing and refusing later
/// costs a round trip. # C: O(1)
pub fn authreq_for(smp: &Smp, sec_level: u8) -> u8 {
    let mut authreq = seclevel_to_authreq(sec_level);
    if smp.cfg.sc_enabled {
        authreq |= SMP_AUTH_SC;
        if smp.cfg.cross_transport { authreq |= SMP_AUTH_CT2; }
    }
    if smp.cfg.io_capability != SMP_IO_NO_INPUT_OUTPUT || sec_level > BT_SECURITY_MEDIUM {
        authreq |= SMP_AUTH_MITM;
    }
    authreq
}

impl Smp {
    /// Install this host's key pair for a secure-connections exchange.
    /// `false` means the supplied private key is unusable and the caller
    /// should draw again. # C: O(1)
    pub fn set_keypair(&mut self, sk_lsb: &[u8; SMP_DHKEY_LEN]) -> bool {
        match sc::local_keypair(sk_lsb) {
            Some((sk, pk)) => { self.local_sk = Some(sk); self.local_pk = pk; true }
            None => false,
        }
    }
}

/// Begin a pairing as the initiator. # C: O(1)
pub fn start_pairing(smp: &mut Smp, sec_level: u8, ent: &Entropy, out: &mut Events) {
    smp.initiator = true;
    smp.prnd = ent.nonce;
    if sec_level > smp.pending_sec_level { smp.pending_sec_level = sec_level; }
    let cmd = smp.build_pairing_cmd(authreq_for(smp, sec_level), None);
    smp.set_preq(&cmd);
    out.push(SmpEvent::Send(Pdu::PairingReq(cmd)));
    smp.allow_only(SMP_CMD_PAIRING_RSP);
}

/// Ask the peer, which is the initiator, to start a pairing. # C: O(1)
pub fn send_security_request(smp: &mut Smp, sec_level: u8, out: &mut Events) {
    smp.initiator = false;
    if sec_level > smp.pending_sec_level { smp.pending_sec_level = sec_level; }
    out.push(SmpEvent::Send(Pdu::SecurityReq(authreq_for(smp, sec_level))));
    smp.allow_only(SMP_CMD_PAIRING_REQ);
}

/// Whether a code is one whose refusal the peer is told about. # C: O(1)
fn refusal_is_explicit(code: u8) -> bool {
    matches!(code, SMP_CMD_IDENT_INFO | SMP_CMD_IDENT_ADDR_INFO | SMP_CMD_SIGN_INFO)
}

/// Decode and act on a frame.
///
/// `Ok(false)` means the frame was dropped without effect. An error carries
/// the failure reason to send. # C: O(len)
pub fn receive(smp: &mut Smp, frame: &[u8], step: &Step, out: &mut Events) -> Result<bool, u8> {
    let pdu = match decode(frame) {
        Ok(p) => p,
        Err(DecodeErr::Unknown) | Err(DecodeErr::Empty) => return Ok(false),
        Err(e) => return Err(err_reason(e).unwrap_or(SMP_INVALID_PARAMS)),
    };
    smp.touch(step.now_ms);

    let code = pdu.code();
    // The two frames that open an exchange are always acceptable; everything
    // else must have been permitted by the step before it.
    let opening = code == SMP_CMD_PAIRING_REQ || code == SMP_CMD_SECURITY_REQ;
    if !opening && !smp.take_allowed(code) {
        if refusal_is_explicit(code) { return Err(SMP_KEY_REJECTED); }
        return Ok(false);
    }

    handle(smp, pdu, step, out)?;
    Ok(true)
}

/// Act on a decoded frame that has already passed the ordering check.
/// # C: O(1)
pub fn handle(smp: &mut Smp, pdu: Pdu, step: &Step, out: &mut Events) -> Result<(), u8> {
    match pdu {
        Pdu::PairingReq(req) => on_pairing_req(smp, req, step, out),
        Pdu::PairingRsp(rsp) => on_pairing_rsp(smp, rsp, step, out),
        Pdu::Confirm(c) => on_confirm(smp, c, step, out),
        Pdu::Random(r) => on_random(smp, r, step, out),
        Pdu::Fail(_) => Ok(()),
        Pdu::PublicKey { x, y } => on_public_key(smp, x, y, step, out),
        Pdu::DhkeyCheck(e) => sc::on_dhkey_check(smp, e, out),
        Pdu::EncryptInfo(k) => { dist::on_encrypt_info(smp, k); Ok(()) }
        Pdu::InitiatorIdent { ediv, rand } => {
            dist::on_initiator_ident(smp, ediv, rand, step.current_level, step.ent, out);
            Ok(())
        }
        Pdu::IdentInfo(k) => { dist::on_ident_info(smp, k); Ok(()) }
        Pdu::IdentAddrInfo { addr_type, addr } => {
            dist::on_ident_addr_info(smp, addr_type, addr, step.current_level, step.ent, out);
            Ok(())
        }
        Pdu::SignInfo(k) => {
            dist::on_sign_info(smp, k, step.current_level, step.ent, out);
            Ok(())
        }
        Pdu::SecurityReq(auth) => on_security_req(smp, auth, step, out),
        Pdu::KeypressNotify(v) => {
            if v > SMP_KEYPRESS_MAX { return Err(SMP_INVALID_PARAMS); }
            Ok(())
        }
    }
}

fn on_pairing_req(smp: &mut Smp, req: PairingCmd, step: &Step, out: &mut Events)
    -> Result<(), u8>
{
    smp.initiator = false;
    smp.set_preq(&req);
    if req.oob_flag == SMP_OOB_PRESENT && smp.cfg.local_oob { smp.local_oob = true; }

    let auth = req.auth_req & auth_req_mask(smp.cfg.sc_enabled);
    let rsp = smp.build_pairing_cmd(auth, Some(&req));
    smp.sc = rsp.auth_req & SMP_AUTH_SC != 0 && auth & SMP_AUTH_SC != 0;
    smp.ct2 = smp.sc && rsp.auth_req & SMP_AUTH_CT2 != 0 && auth & SMP_AUTH_CT2 != 0;

    // A device that cannot interact cannot reach an authenticated level
    // whatever the peer asked for, so its expectation is capped here rather
    // than discovered when the method turns out to be interaction-free.
    let want = if smp.cfg.io_capability == SMP_IO_NO_INPUT_OUTPUT {
        BT_SECURITY_MEDIUM
    } else {
        authreq_to_seclevel(auth)
    };
    if want > smp.pending_sec_level { smp.pending_sec_level = want; }

    if smp.pending_sec_level >= BT_SECURITY_HIGH {
        let m = table_method(smp.sc, smp.cfg.io_capability, req.io_capability);
        if m == JUST_WORKS || m == JUST_CFM { return Err(SMP_AUTH_REQUIREMENTS); }
    }

    let key_size = req.max_key_size.min(rsp.max_key_size);
    smp.enc_key_size = check_enc_key_size(smp.pending_sec_level, key_size, smp.cfg.max_key_size)?;

    smp.prnd = step.ent.nonce;
    smp.set_prsp(&rsp);
    out.push(SmpEvent::Send(Pdu::PairingRsp(rsp)));

    if smp.sc {
        smp.remote_key_dist &= !SMP_SC_NO_DIST;
        smp.allow(SMP_CMD_PUBLIC_KEY);
        smp.allow(SMP_CMD_PAIRING_CONFIRM);
        return Ok(());
    }

    smp.allow(SMP_CMD_PAIRING_CONFIRM);
    legacy::tk_setup(smp, auth, rsp.io_capability, req.io_capability, step.ent, out);
    Ok(())
}

fn on_pairing_rsp(smp: &mut Smp, rsp: PairingCmd, step: &Step, out: &mut Events)
    -> Result<(), u8>
{
    if !smp.initiator { return Err(SMP_CMD_NOTSUPP); }
    smp.set_prsp(&rsp);
    let req = smp.req();

    let key_size = req.max_key_size.min(rsp.max_key_size);
    let auth = rsp.auth_req & auth_req_mask(smp.cfg.sc_enabled);
    if rsp.oob_flag == SMP_OOB_PRESENT && smp.cfg.local_oob { smp.local_oob = true; }

    smp.remote_key_dist &= rsp.resp_key_dist;
    smp.sc = req.auth_req & SMP_AUTH_SC != 0 && auth & SMP_AUTH_SC != 0;
    smp.ct2 = smp.sc && req.auth_req & SMP_AUTH_CT2 != 0 && auth & SMP_AUTH_CT2 != 0;
    if !smp.sc && smp.pending_sec_level > BT_SECURITY_HIGH {
        smp.pending_sec_level = BT_SECURITY_HIGH;
    }

    if smp.pending_sec_level >= BT_SECURITY_HIGH {
        let m = table_method(smp.sc, req.io_capability, rsp.io_capability);
        if m == JUST_WORKS || m == JUST_CFM { return Err(SMP_AUTH_REQUIREMENTS); }
    }

    smp.enc_key_size = check_enc_key_size(smp.pending_sec_level, key_size, smp.cfg.max_key_size)?;

    if smp.sc {
        smp.remote_key_dist &= !SMP_SC_NO_DIST;
        smp.allow(SMP_CMD_PUBLIC_KEY);
        out.push(SmpEvent::Send(Pdu::PublicKey {
            x: super::session::coord_x(&smp.local_pk),
            y: super::session::coord_y(&smp.local_pk),
        }));
        return Ok(());
    }

    let combined = auth | req.auth_req;
    let ready = legacy::tk_setup(smp, combined, req.io_capability, rsp.io_capability,
                                 step.ent, out);
    smp.cfm_pending = true;
    if ready { legacy::send_confirm(smp, out); }
    Ok(())
}

fn on_confirm(smp: &mut Smp, c: [u8; SMP_KEY_LEN], step: &Step, out: &mut Events)
    -> Result<(), u8>
{
    smp.pcnf = c;
    if smp.sc { return sc_confirm(smp, step, out); }
    legacy::on_confirm(smp, c, out);
    Ok(())
}

fn sc_confirm(smp: &mut Smp, step: &Step, out: &mut Events) -> Result<(), u8> {
    use super::method::{DSP_PASSKEY, REQ_PASSKEY};
    if smp.method == REQ_PASSKEY || smp.method == DSP_PASSKEY {
        return sc::passkey_round(smp, SMP_CMD_PAIRING_CONFIRM, step.ent, out);
    }
    if smp.initiator {
        out.push(SmpEvent::Send(Pdu::Random(smp.prnd)));
        smp.allow(SMP_CMD_PAIRING_RANDOM);
    }
    Ok(())
}

fn on_random(smp: &mut Smp, r: [u8; SMP_RAND_LEN], step: &Step, out: &mut Events)
    -> Result<(), u8>
{
    if !smp.sc { return legacy::on_random(smp, r, out); }
    use super::method::{DSP_PASSKEY, REQ_PASSKEY};
    smp.rrnd = r;
    if smp.method == REQ_PASSKEY || smp.method == DSP_PASSKEY {
        return sc::passkey_round(smp, SMP_CMD_PAIRING_RANDOM, step.ent, out);
    }
    sc::on_random(smp, r, out)
}

fn on_public_key(
    smp: &mut Smp,
    x: [u8; SMP_PUBKEY_COORD_LEN],
    y: [u8; SMP_PUBKEY_COORD_LEN],
    step: &Step,
    out: &mut Events,
) -> Result<(), u8> {
    let mut pk = [0u8; SMP_PUBLIC_KEY_LEN];
    pk[..SMP_PUBKEY_COORD_LEN].copy_from_slice(&x);
    pk[SMP_PUBKEY_COORD_LEN..].copy_from_slice(&y);
    let sk = smp.local_sk.ok_or(SMP_UNSPECIFIED)?;
    sc::on_public_key(smp, &pk, &sk, step.ent, out)
}

fn on_security_req(smp: &mut Smp, authreq: u8, step: &Step, out: &mut Events)
    -> Result<(), u8>
{
    // Only the side that established the link may be asked to pair.
    if !smp.initiator && smp.preq[0] != 0 { return Err(SMP_CMD_NOTSUPP); }
    let auth = authreq & auth_req_mask(smp.cfg.sc_enabled);
    let want = if smp.cfg.io_capability == SMP_IO_NO_INPUT_OUTPUT {
        BT_SECURITY_MEDIUM
    } else {
        authreq_to_seclevel(auth)
    };

    if sufficient_security(step.current_level, step.stk_encrypted, step.have_ltk,
                           want, KeyPref::UseLtk) {
        return Ok(());
    }
    if want > smp.pending_sec_level { smp.pending_sec_level = want; }
    start_pairing(smp, smp.pending_sec_level, step.ent, out);
    Ok(())
}

/// Answer a user prompt with a passkey. # C: O(1)
pub fn user_passkey(smp: &mut Smp, passkey: u32, ent: &Entropy, out: &mut Events)
    -> Result<(), u8>
{
    smp.wait_user = false;
    if smp.sc {
        smp.passkey = passkey % SMP_PASSKEY_MODULUS;
        smp.passkey_round = 0;
        let op = if smp.cfm_pending { SMP_CMD_PAIRING_CONFIRM } else { 0 };
        smp.cfm_pending = false;
        return sc::passkey_round(smp, op, ent, out);
    }
    legacy::user_passkey(smp, passkey);
    if smp.cfm_pending || !smp.initiator { legacy::send_confirm(smp, out); }
    Ok(())
}

/// Answer a user confirmation prompt. # C: O(1)
pub fn user_confirm(smp: &mut Smp, accept: bool, out: &mut Events) -> Result<(), u8> {
    smp.wait_user = false;
    if !accept {
        let reason = if smp.sc { SMP_NUMERIC_COMP_FAILED } else { SMP_PASSKEY_ENTRY_FAILED };
        out.push(SmpEvent::Fail(reason));
        return Ok(());
    }
    if smp.sc {
        if smp.initiator {
            sc::send_dhkey_check(smp, out);
            smp.allow(SMP_CMD_DHKEY_CHECK);
        } else if smp.dhkey_pending {
            smp.dhkey_pending = false;
            sc::send_dhkey_check(smp, out);
            sc::add_ltk(smp, out);
        }
        return Ok(());
    }
    if smp.cfm_pending || !smp.initiator { legacy::send_confirm(smp, out); }
    Ok(())
}

/// The level a completed pairing leaves the link at. # C: O(1)
pub fn completed_level(smp: &Smp) -> u8 { smp.pending_sec_level }
