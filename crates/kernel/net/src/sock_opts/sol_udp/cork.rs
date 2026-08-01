// `UDP_CORK` accumulation. A corked socket pins one destination at its first
// append and holds every later payload against it until the cork is pushed,
// at which point the accumulated bytes leave as ONE datagram.
//
// Decisions only: the transmit that a push implies belongs to `emit`.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::NetError;
use crate::sock::InetSocket;

use super::state::{CorkDest, CorkPending};

/// What one `sendto` on a UDP socket must do about the cork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorkAction {
    /// Nothing is corked: build and send the datagram normally.
    Passthrough,
    /// The payload joined the cork; report this many bytes and send nothing.
    Held(usize),
    /// The cork is not engaged but held bytes: transmit `pending` as one
    /// datagram and report `accepted` bytes.
    Push { pending: CorkPending, accepted: usize },
}

/// Resolve the destination a first cork append pins. An explicit address wins;
/// otherwise the connected peer supplies it, and an unconnected socket with no
/// address is `EDESTADDRREQ`. # C: O(1)
pub fn pin(sock: &InetSocket, explicit: Option<CorkDest>) -> Result<CorkDest, NetError> {
    if let Some(dest) = explicit { return Ok(dest); }
    if sock.family.load(Ordering::Acquire) == crate::sock::AF_INET6 {
        let (ip, port) = sock.peer6.lock().ok_or(NetError::Edestaddrreq)?;
        let scope_id = sock.peer6_scope.load(Ordering::Acquire);
        return Ok(CorkDest::V6 { ip, port, scope_id });
    }
    let (ip, port) = sock.peer.lock().ok_or(NetError::Edestaddrreq)?;
    Ok(CorkDest::V4 { ip, port })
}

/// Append one payload to the cork, pinning the destination if this is the
/// first append. A later append that would cross address families against an
/// already-pinned destination is `EINVAL`; a matching one ignores the address
/// it was given and keeps the pinned route. # C: O(payload bytes)
pub fn append(sock: &InetSocket, explicit: Option<CorkDest>, payload: &[u8])
    -> Result<(), NetError>
{
    let mut pending = sock.opts.udp.pending.lock();
    match pending.as_mut() {
        Some(existing) => {
            // Only a family disagreement is visible; the address itself is
            // discarded because the route was fixed at cork time.
            if let Some(dest) = explicit {
                if dest.family() != existing.dest.family() { return Err(NetError::Einval); }
            }
            existing.payload.extend_from_slice(payload);
        }
        None => {
            let dest = pin(sock, explicit)?;
            *pending = Some(CorkPending { dest, payload: payload.to_vec() });
        }
    }
    Ok(())
}

/// Remove whatever the cork holds. # C: O(1)
pub fn take(sock: &InetSocket) -> Option<CorkPending> { sock.opts.udp.pending.lock().take() }

/// Discard a cork without transmitting — the close-time answer. # C: O(1)
pub fn discard(sock: &InetSocket) -> Vec<u8> {
    take(sock).map(|p| p.payload).unwrap_or_default()
}

/// The decision a UDP `sendto` runs before it builds a datagram: cork the
/// payload, push the accumulation, or leave the send alone.
/// # C: O(payload bytes)
pub fn decide(sock: &InetSocket, explicit: Option<CorkDest>, payload: &[u8])
    -> Result<CorkAction, NetError>
{
    let corked = sock.opts.udp.corked();
    if !corked && sock.opts.udp.pending.lock().is_none() { return Ok(CorkAction::Passthrough); }
    append(sock, explicit, payload)?;
    if corked { return Ok(CorkAction::Held(payload.len())); }
    let pending = take(sock).expect("append published a cork");
    Ok(CorkAction::Push { pending, accepted: payload.len() })
}
