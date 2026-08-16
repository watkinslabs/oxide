//! Legacy pairing: temporary key selection, the confirm exchange and the
//! short-term key.
//!
//! The temporary key is what the whole exchange rests on, and for the
//! interaction-free method it is zero — which is why a legacy pairing without
//! a man-in-the-middle requirement can never be called authenticated however
//! it completes.

use crate::uapi::bt::{BT_SECURITY_HIGH, BT_SECURITY_MEDIUM};
use crate::uapi::smp::*;
use super::crypto::{c1, s1};
use super::keys::{Ltk, role_of};
use super::method::{
    CFM_PASSKEY, DSP_PASSKEY, JUST_CFM, JUST_WORKS, REQ_PASSKEY, legacy_method,
    method_is_authenticated,
};
use super::pdu::Pdu;
use super::session::{Entropy, Events, Smp, SmpEvent};

/// Place a passkey into the temporary key: its low four bytes hold the value
/// least significant first, the rest are zero. # C: O(1)
pub fn tk_from_passkey(passkey: u32) -> [u8; SMP_KEY_LEN] {
    let mut tk = [0u8; SMP_KEY_LEN];
    tk[..4].copy_from_slice(&(passkey % SMP_PASSKEY_MODULUS).to_le_bytes());
    tk
}

/// Choose the method, set the temporary key and ask the user for whatever the
/// method needs.
///
/// Returns whether the temporary key is already final. It is not when the user
/// still has to supply a passkey, and sending a confirm before then would
/// commit to a key nobody has chosen. # C: O(1)
pub fn tk_setup(
    smp: &mut Smp,
    auth: u8,
    local_io: u8,
    remote_io: u8,
    ent: &Entropy,
    out: &mut Events,
) -> bool {
    smp.tk = [0u8; SMP_KEY_LEN];
    smp.method = legacy_method(auth, local_io, remote_io, smp.initiator);

    if method_is_authenticated(smp.method) && smp.pending_sec_level < BT_SECURITY_HIGH {
        smp.pending_sec_level = BT_SECURITY_HIGH;
    }

    match smp.method {
        JUST_WORKS => {
            smp.wait_user = true;
            out.push(SmpEvent::UserConfirm { passkey: 0, hint: true });
            true
        }
        JUST_CFM => {
            smp.wait_user = true;
            out.push(SmpEvent::UserConfirm { passkey: 0, hint: true });
            false
        }
        CFM_PASSKEY => {
            let passkey = ent.passkey % SMP_PASSKEY_MODULUS;
            smp.passkey = passkey;
            smp.tk = tk_from_passkey(passkey);
            out.push(SmpEvent::UserConfirm { passkey, hint: false });
            true
        }
        REQ_PASSKEY => {
            smp.wait_user = true;
            out.push(SmpEvent::UserPasskeyRequest);
            false
        }
        _ => {
            // A display-only method has nothing to wait for beyond showing
            // the number.
            let passkey = ent.passkey % SMP_PASSKEY_MODULUS;
            smp.passkey = passkey;
            smp.tk = tk_from_passkey(passkey);
            out.push(SmpEvent::UserPasskeyNotify(passkey));
            true
        }
    }
}

/// Accept a passkey the user typed and finalise the temporary key. # C: O(1)
pub fn user_passkey(smp: &mut Smp, passkey: u32) {
    smp.passkey = passkey % SMP_PASSKEY_MODULUS;
    smp.tk = tk_from_passkey(smp.passkey);
    smp.wait_user = false;
}

/// This host's confirm value over its own nonce. # C: O(1)
pub fn own_confirm(smp: &Smp) -> [u8; SMP_KEY_LEN] {
    confirm_over(smp, &smp.prnd)
}

/// The confirm value the peer should have sent for its nonce. # C: O(1)
pub fn peer_confirm(smp: &Smp) -> [u8; SMP_KEY_LEN] {
    confirm_over(smp, &smp.rrnd)
}

fn confirm_over(smp: &Smp, nonce: &[u8; SMP_RAND_LEN]) -> [u8; SMP_KEY_LEN] {
    c1(&smp.tk, nonce, &smp.preq, &smp.prsp,
       smp.addrs.init_addr_type, &smp.addrs.init_addr,
       smp.addrs.resp_addr_type, &smp.addrs.resp_addr)
}

/// Send this host's confirm value and permit the peer's next frame. # C: O(1)
pub fn send_confirm(smp: &mut Smp, out: &mut Events) {
    out.push(SmpEvent::Send(Pdu::Confirm(own_confirm(smp))));
    smp.cfm_pending = false;
    if smp.initiator { smp.allow(SMP_CMD_PAIRING_CONFIRM); }
    else { smp.allow(SMP_CMD_PAIRING_RANDOM); }
}

/// A confirm value arrived. The initiator answers with its nonce; the
/// responder answers with its own confirm, or defers when the user has not
/// finished choosing the temporary key. # C: O(1)
pub fn on_confirm(smp: &mut Smp, cnf: [u8; SMP_KEY_LEN], out: &mut Events) {
    smp.pcnf = cnf;
    if smp.initiator {
        out.push(SmpEvent::Send(Pdu::Random(smp.prnd)));
        smp.allow(SMP_CMD_PAIRING_RANDOM);
        return;
    }
    if smp.wait_user { smp.cfm_pending = true; return; }
    send_confirm(smp, out);
}

/// A nonce arrived. Verifying the peer's confirm against it is the step that
/// makes the temporary key binding, and a mismatch means the peer did not know
/// the key that was agreed. # C: O(1)
pub fn on_random(smp: &mut Smp, rrnd: [u8; SMP_RAND_LEN], out: &mut Events) -> Result<(), u8> {
    smp.rrnd = rrnd;
    if peer_confirm(smp) != smp.pcnf { return Err(SMP_CONFIRM_FAILED); }

    if smp.initiator {
        // The initiator's short-term key takes the responder nonce first.
        let stk = s1(&smp.tk, &smp.rrnd, &smp.prnd);
        out.push(SmpEvent::StartEncryption {
            ltk: stk, ediv: 0, rand: 0, key_size: smp.enc_key_size,
        });
    } else {
        out.push(SmpEvent::Send(Pdu::Random(smp.prnd)));
        // The responder's takes its own nonce first, which is the same
        // ordering seen from the other end.
        let stk = s1(&smp.tk, &smp.prnd, &smp.rrnd);
        let authenticated = method_is_authenticated(smp.method);
        out.push(SmpEvent::StoreLtk(Ltk {
            peer: smp.peer,
            key_type: SMP_STK,
            authenticated,
            val: stk,
            enc_size: smp.enc_key_size,
            ediv: 0,
            rand: 0,
        }));
    }
    Ok(())
}

/// The level a completed legacy pairing reached. # C: O(1)
pub fn completed_level(method: u8) -> u8 {
    if method_is_authenticated(method) { BT_SECURITY_HIGH } else { BT_SECURITY_MEDIUM }
}

/// The role a stored short-term key belongs to. # C: O(1)
pub fn stk_role(smp: &Smp) -> u8 { role_of(smp.initiator) }

/// Whether a method displays a passkey rather than asking for one. # C: O(1)
pub fn method_displays_passkey(method: u8) -> bool {
    method == DSP_PASSKEY || method == CFM_PASSKEY
}
