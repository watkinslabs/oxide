//! Secure connections: the public key exchange, the shared secret, and the
//! confirm and check values built on it.
//!
//! Two things here are load-bearing beyond their size. The peer's public key
//! is validated before it reaches the scalar multiplication, because a point
//! off the curve turns the exchange into a way to extract the private key. And
//! the check value is computed one way to send and the other way to verify —
//! using the same ordering for both would accept a value the peer never
//! produced.

use p256::{PublicKey, SecretKey};

use crate::uapi::bt::{BT_SECURITY_FIPS, BT_SECURITY_MEDIUM};
use crate::uapi::smp::*;
use super::crypto::{f4, f5, f6, g2, swap};
use super::keys::Ltk;
use super::method::{
    DSP_PASSKEY, JUST_CFM, JUST_WORKS, REQ_OOB, REQ_PASSKEY, sc_method,
};
use super::pdu::Pdu;
use super::session::{Entropy, Events, Smp, SmpEvent, coord_x, coord_y};

/// The public key the specification publishes so a debugging tool can follow
/// an exchange, least-significant-byte-first as the protocol carries it. A
/// pairing that uses it is marked, because it provides no secrecy at all.
pub const DEBUG_PUBLIC_KEY: [u8; SMP_PUBLIC_KEY_LEN] = [
    0xe6, 0x9d, 0x35, 0x0e, 0x48, 0x01, 0x03, 0xcc,
    0xdb, 0xfd, 0xf4, 0xac, 0x11, 0x91, 0xf4, 0xef,
    0xb9, 0xa5, 0xf9, 0xe9, 0xa7, 0x83, 0x2c, 0x5e,
    0x2c, 0xbe, 0x97, 0xf2, 0xd2, 0x03, 0xb0, 0x20,
    0x8b, 0xd2, 0x89, 0x15, 0xd0, 0x8e, 0x1c, 0x74,
    0x24, 0x30, 0xed, 0x8f, 0xc2, 0x45, 0x63, 0x76,
    0x5c, 0x15, 0x52, 0x5a, 0xbf, 0x9a, 0x32, 0x63,
    0x6d, 0xeb, 0x2a, 0x65, 0x49, 0x9c, 0x80, 0xdc,
];

/// The matching private key, likewise least-significant-first.
pub const DEBUG_PRIVATE_KEY: [u8; SMP_DHKEY_LEN] = [
    0xbd, 0x1a, 0x3c, 0xcd, 0xa6, 0xb8, 0x99, 0x58,
    0x99, 0xb7, 0x40, 0xeb, 0x7b, 0x60, 0xff, 0x4a,
    0x50, 0x3f, 0x10, 0xd2, 0xe3, 0xb3, 0xc9, 0x74,
    0x38, 0x5f, 0xc5, 0xa3, 0xd4, 0xf6, 0x49, 0x3f,
];

/// The value a passkey round confirms: the round's passkey bit with the high
/// bit set, which keeps the twenty confirms distinct from the single one the
/// other methods use.
pub const PASSKEY_ROUND_BASE: u8 = 0x80;

/// Convert a wire public key into the curve library's byte order and validate
/// it. `None` means the key is unusable — not on the curve, a coordinate that
/// is not a residue, or the point at infinity. # C: O(1)
pub fn parse_peer_key(pk: &[u8; SMP_PUBLIC_KEY_LEN]) -> Option<PublicKey> {
    let mut be = [0u8; SMP_PUBLIC_KEY_LEN];
    be[..SMP_PUBKEY_COORD_LEN].copy_from_slice(&swap(&coord_x(pk)));
    be[SMP_PUBKEY_COORD_LEN..].copy_from_slice(&swap(&coord_y(pk)));
    PublicKey::from_bytes(&be)
}

/// Convert a private key from wire order and derive its public key in wire
/// order. `None` when the supplied bytes are outside the usable range, which
/// means the caller should draw again. # C: O(1)
pub fn local_keypair(sk_lsb: &[u8; SMP_DHKEY_LEN])
    -> Option<(SecretKey, [u8; SMP_PUBLIC_KEY_LEN])>
{
    let sk = SecretKey::from_entropy(&swap(sk_lsb))?;
    let be = sk.public_key().to_bytes();
    let mut pk = [0u8; SMP_PUBLIC_KEY_LEN];
    let mut x = [0u8; SMP_PUBKEY_COORD_LEN];
    let mut y = [0u8; SMP_PUBKEY_COORD_LEN];
    x.copy_from_slice(&be[..SMP_PUBKEY_COORD_LEN]);
    y.copy_from_slice(&be[SMP_PUBKEY_COORD_LEN..]);
    pk[..SMP_PUBKEY_COORD_LEN].copy_from_slice(&swap(&x));
    pk[SMP_PUBKEY_COORD_LEN..].copy_from_slice(&swap(&y));
    Some((sk, pk))
}

/// The shared secret in wire order. # C: O(1)
pub fn shared_secret(sk: &SecretKey, peer: &PublicKey) -> Option<[u8; SMP_DHKEY_LEN]> {
    Some(swap(&sk.diffie_hellman(peer)?.0))
}

/// Choose the method for a secure-connections exchange from the two pairing
/// frames. # C: O(1)
pub fn select_method(smp: &Smp) -> u8 {
    let (local, remote) = if smp.initiator { (smp.req(), smp.rsp()) } else { (smp.rsp(), smp.req()) };
    sc_method(
        local.io_capability, remote.io_capability,
        local.auth_req, remote.auth_req,
        smp.local_oob, smp.remote_oob,
        smp.initiator,
    )
}

/// The peer's public key arrived: validate it, derive the shared secret,
/// settle the method and take whichever first step it calls for. # C: O(1)
pub fn on_public_key(
    smp: &mut Smp,
    key: &[u8; SMP_PUBLIC_KEY_LEN],
    sk: &SecretKey,
    ent: &Entropy,
    out: &mut Events,
) -> Result<(), u8> {
    // A peer echoing our own key is either a reflection attack or a broken
    // stack; either way the exchange would derive a secret we already know.
    if !smp.debug_key && *key == smp.local_pk { return Err(SMP_DHKEY_CHECK_FAILED); }

    let peer = parse_peer_key(key).ok_or(SMP_DHKEY_CHECK_FAILED)?;
    smp.remote_pk = *key;

    if smp.remote_oob {
        let cfm = f4(&coord_x(&smp.remote_pk), &coord_x(&smp.remote_pk), &smp.rr, 0);
        if cfm != smp.pcnf { return Err(SMP_CONFIRM_FAILED); }
    }

    if !smp.initiator {
        out.push(SmpEvent::Send(Pdu::PublicKey {
            x: coord_x(&smp.local_pk), y: coord_y(&smp.local_pk),
        }));
    }

    smp.dhkey = shared_secret(sk, &peer).ok_or(SMP_DHKEY_CHECK_FAILED)?;
    smp.method = select_method(smp);
    smp.pending_sec_level = if smp.method == JUST_WORKS || smp.method == JUST_CFM {
        BT_SECURITY_MEDIUM
    } else {
        BT_SECURITY_FIPS
    };
    if *key == DEBUG_PUBLIC_KEY { smp.debug_key = true; }

    match smp.method {
        DSP_PASSKEY => {
            smp.passkey = ent.passkey % SMP_PASSKEY_MODULUS;
            smp.passkey_round = 0;
            out.push(SmpEvent::UserPasskeyNotify(smp.passkey));
            smp.allow(SMP_CMD_PAIRING_CONFIRM);
            passkey_round(smp, SMP_CMD_PUBLIC_KEY, ent, out)
        }
        REQ_OOB => {
            if smp.initiator { out.push(SmpEvent::Send(Pdu::Random(smp.prnd))); }
            smp.allow(SMP_CMD_PAIRING_RANDOM);
            Ok(())
        }
        REQ_PASSKEY => {
            smp.allow(SMP_CMD_PAIRING_CONFIRM);
            smp.wait_user = true;
            out.push(SmpEvent::UserPasskeyRequest);
            Ok(())
        }
        _ => {
            if smp.initiator {
                smp.allow(SMP_CMD_PAIRING_CONFIRM);
                return Ok(());
            }
            let cfm = f4(&coord_x(&smp.local_pk), &coord_x(&smp.remote_pk), &smp.prnd, 0);
            out.push(SmpEvent::Send(Pdu::Confirm(cfm)));
            smp.allow(SMP_CMD_PAIRING_RANDOM);
            Ok(())
        }
    }
}

/// The bit value a passkey round confirms. # C: O(1)
pub fn round_value(passkey: u32, round: u8) -> u8 {
    (((passkey >> round) & 1) as u8) | PASSKEY_ROUND_BASE
}

/// Send this host's confirm for the current passkey round with a fresh nonce.
/// # C: O(1)
pub fn passkey_send_confirm(smp: &mut Smp, ent: &Entropy, out: &mut Events) {
    let r = round_value(smp.passkey, smp.passkey_round);
    smp.prnd = ent.nonce;
    let cfm = f4(&coord_x(&smp.local_pk), &coord_x(&smp.remote_pk), &smp.prnd, r);
    out.push(SmpEvent::Send(Pdu::Confirm(cfm)));
}

/// Drive one step of the twenty-round passkey exchange.
///
/// Each round confirms one bit of the passkey, so a peer that guesses wrong
/// is caught on the round that bit differs rather than at the end. Rounds past
/// the twentieth are ignored rather than treated as an error, because a peer
/// resending is not an attack. # C: O(1)
pub fn passkey_round(smp: &mut Smp, op: u8, ent: &Entropy, out: &mut Events) -> Result<(), u8> {
    if smp.passkey_round >= SMP_PASSKEY_ROUNDS { return Ok(()); }

    match op {
        SMP_CMD_PAIRING_RANDOM => {
            let r = round_value(smp.passkey, smp.passkey_round);
            let cfm = f4(&coord_x(&smp.remote_pk), &coord_x(&smp.local_pk), &smp.rrnd, r);
            if cfm != smp.pcnf { return Err(SMP_CONFIRM_FAILED); }
            smp.passkey_round += 1;
            if smp.passkey_round == SMP_PASSKEY_ROUNDS { mackey_and_ltk(smp); }

            if !smp.initiator {
                out.push(SmpEvent::Send(Pdu::Random(smp.prnd)));
                if smp.passkey_round == SMP_PASSKEY_ROUNDS { smp.allow(SMP_CMD_DHKEY_CHECK); }
                else { smp.allow(SMP_CMD_PAIRING_CONFIRM); }
                return Ok(());
            }
            if smp.passkey_round != SMP_PASSKEY_ROUNDS {
                return passkey_round(smp, 0, ent, out);
            }
            send_dhkey_check(smp, out);
            smp.allow(SMP_CMD_DHKEY_CHECK);
            Ok(())
        }
        SMP_CMD_PAIRING_CONFIRM => {
            if smp.wait_user { smp.cfm_pending = true; return Ok(()); }
            smp.allow(SMP_CMD_PAIRING_RANDOM);
            if smp.initiator {
                out.push(SmpEvent::Send(Pdu::Random(smp.prnd)));
                return Ok(());
            }
            passkey_send_confirm(smp, ent, out);
            Ok(())
        }
        _ => {
            // Only the initiator opens a round.
            if !smp.initiator { return Ok(()); }
            smp.allow(SMP_CMD_PAIRING_CONFIRM);
            passkey_send_confirm(smp, ent, out);
            Ok(())
        }
    }
}

/// Derive the message authentication key and the long-term key. # C: O(1)
pub fn mackey_and_ltk(smp: &mut Smp) {
    let (na, nb) = smp.ordered_nonces();
    let (mackey, ltk) = f5(&smp.dhkey, &na, &nb, &smp.addrs.a1(), &smp.addrs.a2());
    smp.mackey = mackey;
    smp.tk = ltk;
}

/// The value mixed into a check: the passkey for a passkey method, the
/// out-of-band random for that one, zero otherwise. `local` selects whose
/// out-of-band value applies. # C: O(1)
pub fn check_r(smp: &Smp, local: bool) -> [u8; SMP_KEY_LEN] {
    let mut r = [0u8; SMP_KEY_LEN];
    if smp.method == REQ_PASSKEY || smp.method == DSP_PASSKEY {
        r[..4].copy_from_slice(&smp.passkey.to_le_bytes());
    } else if smp.method == REQ_OOB {
        r = if local { smp.lr } else { smp.rr };
    }
    r
}

/// Send this host's check value. # C: O(1)
pub fn send_dhkey_check(smp: &mut Smp, out: &mut Events) {
    let (local_addr, remote_addr) = smp.local_remote_addrs();
    let r = check_r(smp, false);
    let e = f6(&smp.mackey, &smp.prnd, &smp.rrnd, &r, &smp.local_io_cap(),
               &local_addr, &remote_addr);
    out.push(SmpEvent::Send(Pdu::DhkeyCheck(e)));
}

/// The check value the peer must have sent. Every argument that names a side
/// is the other way round from the sending path. # C: O(1)
pub fn expected_dhkey_check(smp: &Smp) -> [u8; SMP_KEY_LEN] {
    let (local_addr, remote_addr) = smp.local_remote_addrs();
    let r = check_r(smp, true);
    f6(&smp.mackey, &smp.rrnd, &smp.prnd, &r, &smp.remote_io_cap(),
       &remote_addr, &local_addr)
}

/// The number both users compare. # C: O(1)
pub fn numeric_value(smp: &Smp) -> u32 {
    let (pkax, pkbx) = smp.ordered_pk_x();
    let (na, nb) = smp.ordered_nonces();
    g2(&pkax, &pkbx, &na, &nb)
}

/// Record the long-term key a completed exchange produced. # C: O(1)
pub fn add_ltk(smp: &Smp, out: &mut Events) {
    let key_type = if smp.debug_key { SMP_LTK_P256_DEBUG } else { SMP_LTK_P256 };
    out.push(SmpEvent::StoreLtk(Ltk {
        peer: smp.peer,
        key_type,
        authenticated: smp.pending_sec_level == BT_SECURITY_FIPS,
        val: smp.tk,
        enc_size: smp.enc_key_size,
        ediv: 0,
        rand: 0,
    }));
}

/// A nonce arrived in a non-passkey secure-connections exchange. # C: O(1)
pub fn on_random(smp: &mut Smp, rrnd: [u8; SMP_RAND_LEN], out: &mut Events) -> Result<(), u8> {
    smp.rrnd = rrnd;

    if smp.method == REQ_OOB {
        if !smp.initiator { out.push(SmpEvent::Send(Pdu::Random(smp.prnd))); }
        smp.allow(SMP_CMD_DHKEY_CHECK);
        mackey_and_ltk(smp);
        if smp.initiator {
            send_dhkey_check(smp, out);
            smp.allow(SMP_CMD_DHKEY_CHECK);
        }
        return Ok(());
    }

    if smp.initiator {
        let cfm = f4(&coord_x(&smp.remote_pk), &coord_x(&smp.local_pk), &smp.rrnd, 0);
        if cfm != smp.pcnf { return Err(SMP_CONFIRM_FAILED); }
    } else {
        out.push(SmpEvent::Send(Pdu::Random(smp.prnd)));
        smp.allow(SMP_CMD_DHKEY_CHECK);
    }

    mackey_and_ltk(smp);

    let passkey = numeric_value(smp);
    // The interaction-free method still asks, because otherwise a relay can
    // pair silently; the answer is an acknowledgement rather than a comparison.
    let hint = smp.method == JUST_WORKS;
    out.push(SmpEvent::UserConfirm { passkey, hint });
    smp.wait_user = true;
    Ok(())
}

/// A check value arrived: verify it, answer if this host is the responder,
/// and store the key. # C: O(1)
pub fn on_dhkey_check(smp: &mut Smp, e: [u8; SMP_KEY_LEN], out: &mut Events) -> Result<(), u8> {
    if e != expected_dhkey_check(smp) { return Err(SMP_DHKEY_CHECK_FAILED); }

    if !smp.initiator {
        if smp.wait_user { smp.dhkey_pending = true; return Ok(()); }
        send_dhkey_check(smp, out);
    }

    add_ltk(smp, out);

    if smp.initiator {
        out.push(SmpEvent::StartEncryption {
            ltk: smp.tk, ediv: 0, rand: 0, key_size: smp.enc_key_size,
        });
    }
    Ok(())
}
