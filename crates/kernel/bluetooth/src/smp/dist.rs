//! Key distribution, the third phase.
//!
//! The responder sends its keys first, so an initiator with keys to receive
//! waits before sending its own. Each key is one frame and the next expected
//! frame is permitted only once the previous arrived, which is what keeps a
//! peer from injecting an identity key in the middle of an encryption key
//! exchange.

use crate::uapi::bt::{BT_SECURITY_HIGH, BT_SECURITY_MEDIUM, BdAddr};
use crate::uapi::smp::*;
use super::keys::{Csrk, Irk, LinkKey, Ltk};
use super::pdu::Pdu;
use super::session::{Entropy, Events, Smp, SmpEvent};
use super::xtransport::ltk_to_link_key;

/// Permit the first key frame still expected from the peer. # C: O(1)
pub fn allow_next(smp: &mut Smp) {
    if smp.remote_key_dist & SMP_DIST_ENC_KEY != 0 { smp.allow(SMP_CMD_ENCRYPT_INFO); }
    else if smp.remote_key_dist & SMP_DIST_ID_KEY != 0 { smp.allow(SMP_CMD_IDENT_INFO); }
    else if smp.remote_key_dist & SMP_DIST_SIGN != 0 { smp.allow(SMP_CMD_SIGN_INFO); }
}

/// Whether any key is still expected from the peer. # C: O(1)
pub fn awaiting_keys(smp: &Smp) -> bool { smp.remote_key_dist & SMP_KEY_DIST_MASK != 0 }

/// Send this host's keys, or wait if the peer's are due first.
///
/// The distribution bits are the intersection of what each side asked for and
/// what the other offered; sending a key neither side agreed on would leak it
/// for nothing. # C: O(1)
pub fn distribute(smp: &mut Smp, current_level: u8, ent: &Entropy, out: &mut Events) {
    if smp.initiator && awaiting_keys(smp) {
        allow_next(smp);
        return;
    }

    let req = smp.req();
    let rsp = smp.rsp();
    let mut keydist = if smp.initiator {
        rsp.init_key_dist & req.init_key_dist
    } else {
        rsp.resp_key_dist & req.resp_key_dist
    };

    if smp.sc {
        // A secure-connections pairing derives the other transport's key
        // rather than sending it, so those bits never go on the wire.
        if keydist & SMP_DIST_LINK_KEY != 0 {
            let val = ltk_to_link_key(&smp.tk, smp.ct2);
            out.push(SmpEvent::StoreLinkKey(LinkKey {
                addr: smp.peer.addr, val, key_type: SMP_LTK_P256,
            }));
        }
        keydist &= !SMP_SC_NO_DIST;
    }

    if keydist & SMP_DIST_ENC_KEY != 0 {
        // Only the negotiated number of bytes is significant; the rest are
        // zero so a peer cannot be handed more key than it agreed to.
        let mut ltk = [0u8; SMP_KEY_LEN];
        let n = smp.enc_key_size as usize;
        ltk[..n].copy_from_slice(&ent.ltk[..n]);

        out.push(SmpEvent::Send(Pdu::EncryptInfo(ltk)));
        out.push(SmpEvent::StoreLtk(Ltk {
            peer: smp.peer,
            key_type: SMP_LTK_RESPONDER,
            authenticated: current_level == BT_SECURITY_HIGH,
            val: ltk,
            enc_size: smp.enc_key_size,
            ediv: ent.ediv,
            rand: ent.rand,
        }));
        out.push(SmpEvent::Send(Pdu::InitiatorIdent { ediv: ent.ediv, rand: ent.rand }));
        keydist &= !SMP_DIST_ENC_KEY;
    }

    if keydist & SMP_DIST_ID_KEY != 0 {
        out.push(SmpEvent::SendIdentAddr);
        keydist &= !SMP_DIST_ID_KEY;
    }

    if keydist & SMP_DIST_SIGN != 0 {
        out.push(SmpEvent::Send(Pdu::SignInfo(ent.ltk)));
        out.push(SmpEvent::StoreCsrk(Csrk {
            peer: smp.peer,
            val: ent.ltk,
            authenticated: current_level > BT_SECURITY_MEDIUM,
            counter: 0,
        }));
    }

    if awaiting_keys(smp) { allow_next(smp); return; }
    out.push(SmpEvent::Complete);
}

/// An encryption key arrived; the identifiers that go with it follow.
/// # C: O(1)
pub fn on_encrypt_info(smp: &mut Smp, ltk: [u8; SMP_KEY_LEN]) {
    smp.tk = ltk;
    smp.allow(SMP_CMD_INITIATOR_IDENT);
}

/// The identifiers arrived, completing the encryption key. # C: O(1)
pub fn on_initiator_ident(
    smp: &mut Smp,
    ediv: u16,
    rand: u64,
    current_level: u8,
    ent: &Entropy,
    out: &mut Events,
) {
    smp.remote_key_dist &= !SMP_DIST_ENC_KEY;
    out.push(SmpEvent::StoreLtk(Ltk {
        peer: smp.peer,
        key_type: SMP_LTK,
        authenticated: current_level == BT_SECURITY_HIGH,
        val: smp.tk,
        enc_size: smp.enc_key_size,
        ediv,
        rand,
    }));
    if awaiting_keys(smp) { allow_next(smp); return; }
    distribute(smp, current_level, ent, out);
}

/// An identity resolving key arrived; the address it belongs to follows.
/// # C: O(1)
pub fn on_ident_info(smp: &mut Smp, irk: [u8; SMP_KEY_LEN]) {
    smp.tk = irk;
    smp.allow(SMP_CMD_IDENT_ADDR_INFO);
}

/// The peer's identity address arrived. It replaces the address the link was
/// established on, which may have been a resolvable one that will not be seen
/// again. # C: O(1)
pub fn on_ident_addr_info(
    smp: &mut Smp,
    addr_type: u8,
    addr: BdAddr,
    current_level: u8,
    ent: &Entropy,
    out: &mut Events,
) {
    smp.remote_key_dist &= !SMP_DIST_ID_KEY;
    smp.peer.addr = addr;
    smp.peer.addr_type = addr_type;
    out.push(SmpEvent::StoreIrk(Irk { peer: smp.peer, val: smp.tk }));
    if awaiting_keys(smp) { allow_next(smp); return; }
    distribute(smp, current_level, ent, out);
}

/// A signing key arrived, which is the last key any side sends. # C: O(1)
pub fn on_sign_info(
    smp: &mut Smp,
    csrk: [u8; SMP_KEY_LEN],
    current_level: u8,
    ent: &Entropy,
    out: &mut Events,
) {
    smp.remote_key_dist &= !SMP_DIST_SIGN;
    out.push(SmpEvent::StoreCsrk(Csrk {
        peer: smp.peer,
        val: csrk,
        authenticated: current_level > BT_SECURITY_MEDIUM,
        counter: 0,
    }));
    if awaiting_keys(smp) { allow_next(smp); return; }
    distribute(smp, current_level, ent, out);
}
