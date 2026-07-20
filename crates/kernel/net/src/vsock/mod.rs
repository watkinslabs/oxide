// AF_VSOCK STREAM protocol engine. `hdr` owns wire format; `conn` owns
// table/listener state; `reservation` owns local bind identity.
// This module drives I/O and dispatches frames through transport hooks.
pub mod hdr;
pub mod conn;
mod accept;
mod emission;
mod reservation;
mod seqpacket;
mod io;
mod transaction;
#[cfg(any(test, feature = "hosted"))]
pub mod hosted_test;
#[cfg(test)]
pub(crate) mod tests;
pub use hdr::*;
pub use conn::*;
pub use reservation::{BindReservation, LAST_RESERVED_PORT};
pub use seqpacket::{SeqpacketDelivery, SeqpacketRecord, SeqpacketRx};
pub use io::{recv, send, send_seqpacket};
pub use accept::AcceptWait;
pub use transaction::{arm_connect_timeout, cancel_connect, cancel_connect_timeout, close,
    connect_from, connect_from_start, connect_from_start_owned, connect_wait, fail_connect,
    prepare_connect_owned, prepare_connect_owned_type, recv_seqpacket_with, recv_with, recv_with_offset,
    SeqpacketRecvWith, start_connect, RecvWith,
    VSOCK_CONNECT_TIMEOUT_NS};
#[cfg(target_os = "oxide-kernel")]
pub use transaction::arm_seqpacket_recv_wait;
#[cfg(not(target_os = "oxide-kernel"))]
pub use transaction::seqpacket_recv_wait_would_park;
use transaction::send_accept_response;
pub(crate) use emission::lock_emission;
#[cfg(test)]
pub(crate) use emission::inject_tail_credit_for_test;
use emission::send_credit_update;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::netdev::NetError;
use sync::{Spinlock, Socket as SockLockClass};
/// Process-global connection table. # C: O(1)
pub static TABLE: VsockTable = VsockTable::new();
/// TX hook: hand an owning device key plus a fully-encoded header + payload to
/// the driver, which builds a TX descriptor, kicks q1, and polls the used ring.
/// Returns true if the frame went out. # C: O(payload)
pub type TxFn = fn(VsockOwner, &[u8]) -> bool;
/// RX poll hook: let the owning transport drain completed RX descriptors.
/// This is an opportunistic progress hook for syscall waits; IRQ/softirq
/// remains the normal delivery path. # C: O(device RX completions)
pub type RxPollFn = fn(VsockOwner) -> usize;
struct Endpoint {
    owner: VsockOwner,
    guest_cid: u64,
    features: u64,
    tx_payload_limit: usize,
    tx: Option<TxFn>,
    rx_poll: Option<RxPollFn>,
}
static ENDPOINTS: Spinlock<Vec<Endpoint>, SockLockClass> = Spinlock::new(Vec::new());
static PRIMARY_OWNER: AtomicU32 = AtomicU32::new(VSOCK_OWNER_ANY_RAW);

/// Publish a changed socket-owned receive window through the virtio credit
/// owner. The wire buffer field is u32 even though the SOL_VSOCK ABI is u64.
/// # C: O(1) + one credit frame
pub fn publish_local_buf_alloc(conn: &VsockConn, bytes: u32) {
    conn.set_local_buf_alloc(bytes);
    send_credit_update(conn);
}
/// Hosted protocol fixtures have no DMA frame owner; they intentionally model
/// an unbounded transport while production endpoints must publish a real limit.
const HOSTED_UNBOUNDED_TX_PAYLOAD: usize = usize::MAX;
fn choose_primary_locked(endpoints: &[Endpoint]) -> u32 {
    endpoints.iter().find(|e| e.tx.is_some()).map(|e| e.owner)
        .or_else(|| endpoints.first().map(|e| e.owner))
        .map(VsockOwner::raw)
        .unwrap_or(VSOCK_OWNER_ANY_RAW)
}
fn refresh_primary_locked(endpoints: &[Endpoint]) {
    let current = PRIMARY_OWNER.load(Ordering::Acquire);
    if let Some(owner) = VsockOwner::from_raw(current) {
        if endpoints.iter().any(|e| e.owner == owner && e.tx.is_some()) { return; }
    }
    PRIMARY_OWNER.store(choose_primary_locked(endpoints), Ordering::Release);
}
fn primary_endpoint() -> Option<(VsockOwner, u64)> {
    let endpoints = ENDPOINTS.lock();
    let primary = VsockOwner::from_raw(PRIMARY_OWNER.load(Ordering::Acquire));
    endpoints.iter()
        .find(|e| Some(e.owner) == primary && e.tx.is_some())
        .or_else(|| endpoints.iter().find(|e| e.tx.is_some()))
        .map(|e| (e.owner, e.guest_cid))
}

fn endpoint_by_owner(owner: Option<VsockOwner>) -> Option<(VsockOwner, u64)> {
    let Some(owner) = owner else { return primary_endpoint(); };
    ENDPOINTS.lock().iter()
        .find(|e| e.owner == owner && e.tx.is_some())
        .map(|e| (e.owner, e.guest_cid))
}

/// Reserve a protocol endpoint for `owner` before the transport allocates and
/// pre-posts DMA state. Multiple owners may coexist; duplicate owner keys are
/// rejected so a later probe cannot overwrite an existing endpoint.
/// # C: O(N endpoints)
pub fn driver_reserve(owner: VsockOwner) -> bool {
    let mut endpoints = ENDPOINTS.lock();
    if endpoints.iter().any(|e| e.owner == owner) {
        return false;
    }
    endpoints.push(Endpoint { owner, guest_cid: 0, features: 0, tx_payload_limit: 0, tx: None, rx_poll: None });
    if PRIMARY_OWNER.load(Ordering::Acquire) == VSOCK_OWNER_ANY_RAW {
        PRIMARY_OWNER.store(owner.raw(), Ordering::Release);
    }
    true
}

/// Publish guest CID + install the TX hook after the transport context exists.
/// # C: O(N endpoints)
pub fn driver_publish_reserved(owner: VsockOwner, guest_cid: u64, features: u64, tx_payload_limit: usize,
    tx: TxFn, rx_poll: RxPollFn) -> bool
{
    if tx_payload_limit == 0 { return false; }
    let mut endpoints = ENDPOINTS.lock();
    if endpoints.iter().any(|e| e.owner != owner && e.tx.is_some() && e.guest_cid == guest_cid) {
        return false;
    }
    let Some(endpoint) = endpoints.iter_mut().find(|e| e.owner == owner) else {
        return false;
    };
    endpoint.guest_cid = guest_cid;
    endpoint.features = features;
    endpoint.tx_payload_limit = tx_payload_limit;
    endpoint.tx = Some(tx);
    endpoint.rx_poll = Some(rx_poll);
    refresh_primary_locked(&endpoints);
    true
}

/// Cancel a reservation that failed before the endpoint became live.
/// # C: O(N endpoints)
pub fn driver_cancel_reserved(owner: VsockOwner) -> bool {
    let mut endpoints = ENDPOINTS.lock();
    let before = endpoints.len();
    endpoints.retain(|e| e.owner != owner);
    if endpoints.len() == before {
        return false;
    }
    PRIMARY_OWNER.store(choose_primary_locked(&endpoints), Ordering::Release);
    true
}

/// Driver bring-up entry: reserve and publish in one step.
/// # C: O(N endpoints)
pub fn driver_install(owner: VsockOwner, guest_cid: u64, tx: TxFn, rx_poll: RxPollFn) -> bool {
    if !driver_reserve(owner) {
        return false;
    }
    if !driver_publish_reserved(owner, guest_cid, 0, HOSTED_UNBOUNDED_TX_PAYLOAD, tx, rx_poll) {
        let _ = driver_cancel_reserved(owner);
        return false;
    }
    true
}

/// Driver remove entry: stop new TX, reset CID, and close live connections.
/// # C: O(N endpoints + N conns)
pub fn driver_uninstall(owner: VsockOwner) -> bool {
    let removed = driver_cancel_reserved(owner);
    if removed {
        TABLE.close_owner(owner);
    }
    removed
}

/// Terminal shutdown entry: stop new TX/RX from reaching the transport before
/// the driver tears down queue state. This preserves endpoint ownership so a
/// late operation cannot reuse the same owner during shutdown, but makes the
/// endpoint unusable immediately.
/// # C: O(N endpoints + N conns)
pub fn driver_quiesce(owner: VsockOwner) -> bool {
    let mut endpoints = ENDPOINTS.lock();
    let Some(endpoint) = endpoints.iter_mut().find(|e| e.owner == owner) else {
        return false;
    };
    endpoint.tx = None;
    endpoint.rx_poll = None;
    endpoint.guest_cid = 0;
    endpoint.features = 0;
    endpoint.tx_payload_limit = 0;
    refresh_primary_locked(&endpoints);
    drop(endpoints);
    TABLE.close_owner(owner);
    true
}

/// Our guest CID (0 if no device). # C: O(1)
pub fn guest_cid() -> u64 { primary_endpoint().map(|(_, cid)| cid).unwrap_or(0) }

/// Guest CID for a specific owning driver instance. # C: O(N endpoints)
pub fn guest_cid_for(owner: VsockOwner) -> u64 {
    ENDPOINTS.lock().iter()
        .find(|e| e.owner == owner && e.tx.is_some())
        .map(|e| e.guest_cid)
        .unwrap_or(0)
}

/// Owning driver instance for a live local CID.
/// # C: O(N endpoints)
pub fn driver_owner_for_cid(cid: u64) -> Option<VsockOwner> {
    ENDPOINTS.lock().iter()
        .find(|e| e.guest_cid == cid && e.tx.is_some())
        .map(|e| e.owner)
}

/// Resolve a bind local CID to an endpoint owner. `VMADDR_CID_ANY` stays
/// wildcard owner 0; a specific CID must name a live endpoint.
/// # C: O(N endpoints)
pub fn bind_owner_for_cid(cid: u64) -> Result<Option<VsockOwner>, NetError> {
    if cid == VMADDR_CID_ANY {
        return Ok(None);
    }
    driver_owner_for_cid(cid).map(Some).ok_or(NetError::Eaddrnotavail)
}

/// Primary driver instance for the compatibility socket path.
/// # C: O(N endpoints)
pub fn driver_owner() -> Option<VsockOwner> {
    let endpoints = ENDPOINTS.lock();
    if let Some(primary) = VsockOwner::from_raw(PRIMARY_OWNER.load(Ordering::Acquire)) {
        if endpoints.iter().any(|e| e.owner == primary && e.tx.is_some()) { return Some(primary); }
    }
    endpoints
        .iter()
        .find(|endpoint| endpoint.tx.is_some())
        .map(|endpoint| endpoint.owner)
}

/// True iff a virtio-vsock device is installed and usable. # C: O(1)
pub fn driver_up() -> bool { primary_endpoint().is_some() }

/// True iff `owner` owns an installed and usable virtio-vsock endpoint.
/// # C: O(N endpoints)
pub fn driver_up_for(owner: VsockOwner) -> bool {
    ENDPOINTS.lock().iter().any(|e| e.owner == owner && e.tx.is_some())
}

/// True iff one live primary endpoint negotiated record transport. # C: O(N endpoints)
pub fn driver_supports_seqpacket() -> bool {
    let Some((owner, _)) = primary_endpoint() else { return false; };
    ENDPOINTS.lock().iter().any(|endpoint| endpoint.owner == owner && endpoint.tx.is_some()
        && endpoint.features & VIRTIO_VSOCK_F_SEQPACKET_MASK != 0)
}

/// True iff this exact live endpoint negotiated record transport. # C: O(N endpoints)
pub fn driver_supports_seqpacket_for(owner: VsockOwner) -> bool {
    ENDPOINTS.lock().iter().any(|endpoint| endpoint.owner == owner && endpoint.tx.is_some()
        && endpoint.features & VIRTIO_VSOCK_F_SEQPACKET_MASK != 0)
}

/// Maximum OP_RW payload accepted by an owning live driver frame. # C: O(N endpoints)
pub(crate) fn tx_payload_limit(owner: VsockOwner) -> Option<usize> {
    ENDPOINTS.lock().iter().find(|endpoint| endpoint.owner == owner && endpoint.tx.is_some())
        .map(|endpoint| endpoint.tx_payload_limit)
}

/// Emit one packet via the owning driver's TX hook. False if no driver.
/// # C: O(len)
pub fn tx_for(owner: VsockOwner, hdr: &VsockHdr, payload: &[u8]) -> bool {
    let f = {
        let endpoints = ENDPOINTS.lock();
        let Some(endpoint) = endpoints.iter().find(|e| e.owner == owner) else {
            return false;
        };
        let Some(tx) = endpoint.tx else {
            return false;
        };
        tx
    };
    let mut frame = Vec::with_capacity(VSOCK_HDR_LEN + payload.len());
    frame.extend_from_slice(&hdr.encode());
    frame.extend_from_slice(payload);
    f(owner, &frame)
}

/// Ask the owning transport to drain completed RX buffers, if it exposes a
/// poll hook. # C: O(device RX completions)
pub fn poll_rx_for(owner: VsockOwner) -> usize {
    let f = {
        let endpoints = ENDPOINTS.lock();
        let Some(endpoint) = endpoints.iter().find(|e| e.owner == owner) else {
            return 0;
        };
        let Some(rx_poll) = endpoint.rx_poll else {
            return 0;
        };
        rx_poll
    };
    f(owner)
}

/// Emit one packet via the installed endpoint. False if no driver. # C: O(len)
pub fn tx(hdr: &VsockHdr, payload: &[u8]) -> bool {
    let Some((owner, _)) = primary_endpoint() else {
        return false;
    };
    tx_for(owner, hdr, payload)
}

/// Dispatch one fully-received inbound packet (header + `payload`) onto
/// the matching connection / listener. Called by the driver's RX drain.
/// All credit fields in every inbound header are folded into our peer
/// view (virtio 1.2 §5.10.6.3: every packet carries live credit).
/// # C: O(N conns)
pub fn deliver_rx_from(owner: VsockOwner, h: &VsockHdr, payload: &[u8]) {
    // The packet's dst is us; src is the peer.
    let local_cid  = h.dst_cid;
    let local_port = h.dst_port;
    let peer_cid   = h.src_cid;
    let peer_port  = h.src_port;
    if !driver_up_for(owner) || local_cid != guest_cid_for(owner) {
        return;
    }
    let transport_type = match VsockTransportType::from_wire_type(h.typ) {
        Some(transport_type) => transport_type,
        None => return,
    };
    if transport_type == VsockTransportType::Seqpacket && !driver_supports_seqpacket_for(owner) {
        let rst = VsockHdr {
            src_cid: local_cid, dst_cid: peer_cid, src_port: local_port, dst_port: peer_port,
            len: 0, typ: h.typ, op: VIRTIO_VSOCK_OP_RST, flags: 0, buf_alloc: 0, fwd_cnt: 0,
        };
        let _ = tx_for(owner, &rst, &[]);
        return;
    }

    match h.op {
        VIRTIO_VSOCK_OP_REQUEST => {
            // Inbound connection attempt. Accept iff we listen on the
            // dst port; reply OP_RESPONSE and queue for accept(). Else RST.
            let c = alloc::sync::Arc::new(VsockConn::new_with_filter_type(owner, local_cid,
                local_port, peer_cid, peer_port, VsockState::Connected, transport_type,
                alloc::sync::Arc::new(crate::bpf_filter::SocketFilter::new())));
            c.tx.lock().credit.observe_peer(h.buf_alloc, h.fwd_cnt);
            if TABLE.publish_accept(owner, local_port, c.clone()) {
                if !send_accept_response(&c) || !TABLE.complete_accept(&c) {
                    let _ = TABLE.rollback_accept(&c);
                }
            } else {
                let rst = VsockHdr {
                    src_cid: local_cid, dst_cid: peer_cid,
                    src_port: local_port, dst_port: peer_port,
                    len: 0, typ: h.typ,
                    op: VIRTIO_VSOCK_OP_RST, flags: 0,
                    buf_alloc: 0, fwd_cnt: 0,
                };
                let _ = tx_for(owner, &rst, &[]);
            }
            return;
        }
        _ => {}
    }

    let Some(c) = TABLE.find_for_rx(owner, local_cid, local_port, peer_cid, peer_port)
        else {
            // Unknown connection (except RST which we ignore) → RST it.
            if h.op != VIRTIO_VSOCK_OP_RST {
                let rst = VsockHdr {
                    src_cid: local_cid, dst_cid: peer_cid,
                    src_port: local_port, dst_port: peer_port,
                    len: 0, typ: h.typ,
                    op: VIRTIO_VSOCK_OP_RST, flags: 0,
                    buf_alloc: 0, fwd_cnt: 0,
                };
                let _ = tx_for(owner, &rst, &[]);
            }
            return;
        };
    if c.transport_type != transport_type {
        let rst = VsockHdr {
            src_cid: local_cid, dst_cid: peer_cid,
            src_port: local_port, dst_port: peer_port,
            len: 0, typ: h.typ,
            op: VIRTIO_VSOCK_OP_RST, flags: 0,
            buf_alloc: 0, fwd_cnt: 0,
        };
        let _ = tx_for(owner, &rst, &[]);
        return;
    }

    // Credit and peer receive shutdown share OP_RW's admission gate.
    {
        let mut tx = c.tx.lock();
        tx.credit.observe_peer(h.buf_alloc, h.fwd_cnt);
        if (h.op == VIRTIO_VSOCK_OP_SHUTDOWN
            && (h.flags & VIRTIO_VSOCK_SHUTDOWN_RCV) != 0)
            || h.op == VIRTIO_VSOCK_OP_RST
        { tx.peer_shut = true; }
    }

    match h.op {
        VIRTIO_VSOCK_OP_RESPONSE => {
            let mut st = c.st.lock();
            if *st != VsockState::Closed {
                *st = VsockState::Connected;
                drop(st);
                cancel_connect_timeout(&c);
            }
        }
        VIRTIO_VSOCK_OP_RW => {
            let st = c.st.lock();
            if *st != VsockState::Closed {
                let packet = &payload[..payload.len().min(h.len as usize)];
                let verdict = c.bpf_filter.verdict(packet);
                let retained = packet.len().min(verdict as usize);
                match c.transport_type {
                    VsockTransportType::Stream => {
                        let mut rx = c.rx.lock();
                        if verdict != 0 { rx.extend(packet[..retained].iter().copied()); }
                    }
                    VsockTransportType::Seqpacket => {
                        let mut rx = c.seq_rx.lock();
                        if verdict != 0 {
                            rx.push_fragment(&packet[..retained], h.flags);
                        } else {
                            rx.drop_fragment(h.flags);
                        }
                    }
                }
            }
        }
        VIRTIO_VSOCK_OP_CREDIT_REQUEST => {
            send_credit_update(&c);
        }
        VIRTIO_VSOCK_OP_CREDIT_UPDATE => { /* view already folded above */ }
        VIRTIO_VSOCK_OP_SHUTDOWN => {
            let mut st = c.st.lock();
            if *st != VsockState::Closed && (h.flags & VIRTIO_VSOCK_SHUTDOWN_SEND) != 0 {
                *st = VsockState::RcvShutdown;
            }
            if (h.flags & (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND))
                == (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND) {
                *st = VsockState::Closed;
            }
        }
        VIRTIO_VSOCK_OP_RST => {
            if TABLE.rollback_accept(&c) { return; }
            if fail_connect(&c, NetError::Econnreset) { return; }
            *c.st.lock() = VsockState::Closed;
        }
        _ => {}
    }
    #[cfg(target_os = "oxide-kernel")]
    c.waiters.wake_all();
    c.notify_poll(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP | vfs::POLL_RDHUP);
}

/// Dispatch one inbound packet for the installed endpoint. # C: O(N conns)
pub fn deliver_rx(h: &VsockHdr, payload: &[u8]) {
    let Some((owner, _)) = primary_endpoint() else {
        return;
    };
    deliver_rx_from(owner, h, payload)
}

/// Client connect through the compatibility primary endpoint. # C: O(RTT)
pub fn connect(peer_cid: u64, peer_port: u32) -> Result<alloc::sync::Arc<VsockConn>, NetError>
{
    connect_from(None, None, peer_cid, peer_port)
}
