// AF_VSOCK (virtio-vsock STREAM) datapath. The wire format lives in
// `hdr`, the connection table + credit math in `conn`. This module is
// the protocol engine: it drives connect/send/recv/close, dispatches
// inbound packets onto connections (`deliver_rx`), and hands TX frames
// to the driver via an installed function-pointer hook (no net→driver
// crate dependency — mirrors `sock::set_iface_primary_ip_hook`).
//
// The `VsockSocket` vfs::Inode (in `sock`) is the per-fd object; it
// delegates here.

pub mod hdr;
pub mod conn;
#[cfg(test)]
mod tests;

pub use hdr::*;
pub use conn::*;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::netdev::NetError;
use sync::{Spinlock, Socket as SockLockClass};

/// Process-global connection table. # C: O(1)
pub static TABLE: VsockTable = VsockTable::new();

/// TX hook: hand an owning device key plus a fully-encoded header + payload to
/// the driver, which builds a TX descriptor, kicks q1, and polls the used ring.
/// Returns true if the frame went out. # C: O(payload)
pub type TxFn = fn(u32, &[u8]) -> bool;

struct Endpoint {
    owner: u32,
    guest_cid: u64,
    tx: Option<TxFn>,
}

static ENDPOINTS: Spinlock<Vec<Endpoint>, SockLockClass> = Spinlock::new(Vec::new());
static PRIMARY_OWNER: AtomicU32 = AtomicU32::new(0);

fn choose_primary_locked(endpoints: &[Endpoint]) -> u32 {
    endpoints.iter().find(|e| e.tx.is_some()).map(|e| e.owner)
        .or_else(|| endpoints.first().map(|e| e.owner))
        .unwrap_or(0)
}

fn refresh_primary_locked(endpoints: &[Endpoint]) {
    let current = PRIMARY_OWNER.load(Ordering::Acquire);
    if current != 0 && endpoints.iter().any(|e| e.owner == current && e.tx.is_some()) {
        return;
    }
    PRIMARY_OWNER.store(choose_primary_locked(endpoints), Ordering::Release);
}

fn primary_endpoint() -> Option<(u32, u64)> {
    let endpoints = ENDPOINTS.lock();
    let primary = PRIMARY_OWNER.load(Ordering::Acquire);
    endpoints.iter()
        .find(|e| e.owner == primary && e.tx.is_some())
        .or_else(|| endpoints.iter().find(|e| e.tx.is_some()))
        .map(|e| (e.owner, e.guest_cid))
}

fn endpoint_by_owner(owner: u32) -> Option<(u32, u64)> {
    if owner == 0 {
        return primary_endpoint();
    }
    ENDPOINTS.lock().iter()
        .find(|e| e.owner == owner && e.tx.is_some())
        .map(|e| (e.owner, e.guest_cid))
}

/// Reserve a protocol endpoint for `owner` before the transport allocates and
/// pre-posts DMA state. Multiple owners may coexist; duplicate owner keys are
/// rejected so a later probe cannot overwrite an existing endpoint.
/// # C: O(N endpoints)
pub fn driver_reserve(owner: u32) -> bool {
    if owner == 0 {
        return false;
    }
    let mut endpoints = ENDPOINTS.lock();
    if endpoints.iter().any(|e| e.owner == owner) {
        return false;
    }
    endpoints.push(Endpoint { owner, guest_cid: 0, tx: None });
    if PRIMARY_OWNER.load(Ordering::Acquire) == 0 {
        PRIMARY_OWNER.store(owner, Ordering::Release);
    }
    true
}

/// Publish guest CID + install the TX hook after the transport context exists.
/// # C: O(N endpoints)
pub fn driver_publish_reserved(owner: u32, guest_cid: u64, tx: TxFn) -> bool {
    let mut endpoints = ENDPOINTS.lock();
    if endpoints.iter().any(|e| e.owner != owner && e.tx.is_some() && e.guest_cid == guest_cid) {
        return false;
    }
    let Some(endpoint) = endpoints.iter_mut().find(|e| e.owner == owner) else {
        return false;
    };
    endpoint.guest_cid = guest_cid;
    endpoint.tx = Some(tx);
    refresh_primary_locked(&endpoints);
    true
}

/// Cancel a reservation that failed before the endpoint became live.
/// # C: O(N endpoints)
pub fn driver_cancel_reserved(owner: u32) -> bool {
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
pub fn driver_install(owner: u32, guest_cid: u64, tx: TxFn) -> bool {
    if !driver_reserve(owner) {
        return false;
    }
    if !driver_publish_reserved(owner, guest_cid, tx) {
        let _ = driver_cancel_reserved(owner);
        return false;
    }
    true
}

/// Driver remove entry: stop new TX, reset CID, and close live connections.
/// # C: O(N endpoints + N conns)
pub fn driver_uninstall(owner: u32) -> bool {
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
pub fn driver_quiesce(owner: u32) -> bool {
    let mut endpoints = ENDPOINTS.lock();
    let Some(endpoint) = endpoints.iter_mut().find(|e| e.owner == owner) else {
        return false;
    };
    endpoint.tx = None;
    endpoint.guest_cid = 0;
    refresh_primary_locked(&endpoints);
    TABLE.close_owner(owner);
    true
}

/// Our guest CID (0 if no device). # C: O(1)
pub fn guest_cid() -> u64 { primary_endpoint().map(|(_, cid)| cid).unwrap_or(0) }

/// Guest CID for a specific owning driver instance. # C: O(N endpoints)
pub fn guest_cid_for(owner: u32) -> u64 {
    ENDPOINTS.lock().iter()
        .find(|e| e.owner == owner && e.tx.is_some())
        .map(|e| e.guest_cid)
        .unwrap_or(0)
}

/// Owning driver instance for a live local CID.
/// # C: O(N endpoints)
pub fn driver_owner_for_cid(cid: u64) -> Option<u32> {
    ENDPOINTS.lock().iter()
        .find(|e| e.guest_cid == cid && e.tx.is_some())
        .map(|e| e.owner)
}

/// Primary driver instance for the compatibility socket path, or 0 if none.
/// # C: O(N endpoints)
pub fn driver_owner() -> u32 {
    let endpoints = ENDPOINTS.lock();
    let primary = PRIMARY_OWNER.load(Ordering::Acquire);
    if primary != 0 && endpoints.iter().any(|e| e.owner == primary && e.tx.is_some()) {
        return primary;
    }
    endpoints
        .iter()
        .find(|endpoint| endpoint.tx.is_some())
        .map(|endpoint| endpoint.owner)
        .unwrap_or(0)
}

/// True iff a virtio-vsock device is installed and usable. # C: O(1)
pub fn driver_up() -> bool { primary_endpoint().is_some() }

/// True iff `owner` owns an installed and usable virtio-vsock endpoint.
/// # C: O(N endpoints)
pub fn driver_up_for(owner: u32) -> bool {
    owner != 0 && ENDPOINTS.lock().iter().any(|e| e.owner == owner && e.tx.is_some())
}

/// Emit one packet via the owning driver's TX hook. False if no driver.
/// # C: O(len)
pub fn tx_for(owner: u32, hdr: &VsockHdr, payload: &[u8]) -> bool {
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

/// Emit one packet via the installed endpoint. False if no driver. # C: O(len)
pub fn tx(hdr: &VsockHdr, payload: &[u8]) -> bool {
    let Some((owner, _)) = primary_endpoint() else {
        return false;
    };
    tx_for(owner, hdr, payload)
}

/// Send a credit-update so the peer learns our fresh fwd_cnt after we
/// drained RX into userspace. # C: O(1)
fn send_credit_update(c: &VsockConn) {
    let h = c.make_hdr(VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0, 0);
    let _ = tx_for(c.owner, &h, &[]);
}

/// Dispatch one fully-received inbound packet (header + `payload`) onto
/// the matching connection / listener. Called by the driver's RX drain.
/// All credit fields in every inbound header are folded into our peer
/// view (virtio 1.2 §5.10.6.3: every packet carries live credit).
/// # C: O(N conns)
pub fn deliver_rx_from(owner: u32, h: &VsockHdr, payload: &[u8]) {
    // The packet's dst is us; src is the peer.
    let local_cid  = h.dst_cid;
    let local_port = h.dst_port;
    let peer_cid   = h.src_cid;
    let peer_port  = h.src_port;
    if !driver_up_for(owner) || local_cid != guest_cid_for(owner) {
        return;
    }

    match h.op {
        VIRTIO_VSOCK_OP_REQUEST => {
            // Inbound connection attempt. Accept iff we listen on the
            // dst port; reply OP_RESPONSE and queue for accept(). Else RST.
            if TABLE.is_listening(owner, local_port) {
                let c = alloc::sync::Arc::new(VsockConn::new(
                    owner, local_cid, local_port, peer_cid, peer_port,
                    VsockState::Connected));
                c.credit.lock().observe_peer(h.buf_alloc, h.fwd_cnt);
                let resp = c.make_hdr(VIRTIO_VSOCK_OP_RESPONSE, 0, 0);
                TABLE.insert(c.clone());
                let _ = tx_for(owner, &resp, &[]);
                TABLE.queue_accept(owner, local_port, c.key());
            } else {
                let rst = VsockHdr {
                    src_cid: local_cid, dst_cid: peer_cid,
                    src_port: local_port, dst_port: peer_port,
                    len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
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
                    len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
                    op: VIRTIO_VSOCK_OP_RST, flags: 0,
                    buf_alloc: 0, fwd_cnt: 0,
                };
                let _ = tx_for(owner, &rst, &[]);
            }
            return;
        };

    // Every inbound packet refreshes our peer-credit view.
    c.credit.lock().observe_peer(h.buf_alloc, h.fwd_cnt);

    match h.op {
        VIRTIO_VSOCK_OP_RESPONSE => {
            *c.st.lock() = VsockState::Connected;
        }
        VIRTIO_VSOCK_OP_RW => {
            let mut rx = c.rx.lock();
            for &b in &payload[..payload.len().min(h.len as usize)] {
                rx.push_back(b);
            }
        }
        VIRTIO_VSOCK_OP_CREDIT_REQUEST => {
            send_credit_update(&c);
        }
        VIRTIO_VSOCK_OP_CREDIT_UPDATE => { /* view already folded above */ }
        VIRTIO_VSOCK_OP_SHUTDOWN => {
            let mut st = c.st.lock();
            if (h.flags & VIRTIO_VSOCK_SHUTDOWN_SEND) != 0 {
                *st = VsockState::RcvShutdown;
            }
            if (h.flags & (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND))
                == (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND) {
                *st = VsockState::Closed;
            }
        }
        VIRTIO_VSOCK_OP_RST => {
            *c.st.lock() = VsockState::Closed;
        }
        _ => {}
    }
    #[cfg(target_os = "oxide-kernel")]
    c.waiters.wake_all();
}

/// Dispatch one inbound packet for the installed endpoint. # C: O(N conns)
pub fn deliver_rx(h: &VsockHdr, payload: &[u8]) {
    let Some((owner, _)) = primary_endpoint() else {
        return;
    };
    deliver_rx_from(owner, h, payload)
}

/// Client connect: allocate a local port, register the connection, send
/// OP_REQUEST, and (kernel) park until OP_RESPONSE / RST. Returns the
/// connection on success. # C: O(RTT)
pub fn connect_from(owner: u32, local_port: Option<u32>, peer_cid: u64, peer_port: u32)
    -> Result<alloc::sync::Arc<VsockConn>, NetError>
{
    let Some((owner, local_cid)) = endpoint_by_owner(owner) else {
        return Err(NetError::Enetunreach);
    };
    let local_port = local_port.unwrap_or_else(|| TABLE.alloc_port());
    let c = alloc::sync::Arc::new(VsockConn::new(
        owner, local_cid, local_port, peer_cid, peer_port, VsockState::Connecting));
    TABLE.insert(c.clone());
    let req = c.make_hdr(VIRTIO_VSOCK_OP_REQUEST, 0, 0);
    if !tx_for(owner, &req, &[]) {
        TABLE.remove(c.key());
        return Err(NetError::Enetunreach);
    }
    #[cfg(target_os = "oxide-kernel")]
    {
        let budget = crate::vsock::VSOCK_CONNECT_POLL_BUDGET;
        for _ in 0..budget {
            let st = *c.st.lock();
            match st {
                VsockState::Connected   => return Ok(c),
                VsockState::Closed      => { TABLE.remove(c.key()); return Err(NetError::Econnrefused); }
                _ => {}
            }
            // SAFETY: process ctx (sys_connect AF_VSOCK); runqueue installed;
            // preempt-off owned by the syscall stub; the driver RX drain
            // flips st + wakes via deliver_rx on OP_RESPONSE/OP_RST.
            unsafe { sched::live::tick_yield(); }
        }
        TABLE.remove(c.key());
        return Err(NetError::Eio);
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    Ok(c)
}

/// Client connect through the compatibility primary endpoint. # C: O(RTT)
pub fn connect(peer_cid: u64, peer_port: u32)
    -> Result<alloc::sync::Arc<VsockConn>, NetError>
{
    connect_from(0, None, peer_cid, peer_port)
}

/// Connect-poll budget (tick_yield iterations) before giving up. Named,
/// not a magic literal. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub const VSOCK_CONNECT_POLL_BUDGET: u32 = 2_000_000;

/// Send `buf` over `c` as OP_RW, respecting peer credit. Returns bytes
/// queued for transmit. Eagain if the peer has no credit (caller blocks).
/// # C: O(buf)
pub fn send(c: &VsockConn, buf: &[u8]) -> Result<usize, NetError> {
    match *c.st.lock() {
        VsockState::Connected => {}
        VsockState::Closed => return Err(NetError::Enotconn),
        _ => return Err(NetError::Enotconn),
    }
    let avail = c.credit.lock().peer_credit() as usize;
    if avail == 0 { return Err(NetError::Eagain); }
    // Cap one OP_RW to the driver TX bounce frame (4 KiB) minus the
    // 44-byte header, so a large credit window doesn't overflow the
    // single-frame copy in tx_packet. The caller loops for the rest.
    const MAX_RW_PAYLOAD: usize = 0x1000 - VSOCK_HDR_LEN;
    let n = buf.len().min(avail).min(MAX_RW_PAYLOAD);
    let h = c.make_hdr(VIRTIO_VSOCK_OP_RW, n as u32, 0);
    if !tx_for(c.owner, &h, &buf[..n]) { return Err(NetError::Eio); }
    {
        let mut cr = c.credit.lock();
        cr.tx_cnt = cr.tx_cnt.wrapping_add(n as u32);
    }
    Ok(n)
}

/// Deliver up to `buf.len()` buffered RX bytes into `buf`. Bumps our
/// fwd_cnt + sends a credit update so the peer's window reopens.
/// Returns 0 on a clean peer shutdown with an empty buffer (EOF),
/// Eagain when nothing is buffered but the conn is still live.
/// # C: O(min(buf, buffered))
pub fn recv(c: &VsockConn, buf: &mut [u8]) -> Result<usize, NetError> {
    let mut n = 0usize;
    {
        let mut rx = c.rx.lock();
        while n < buf.len() {
            match rx.pop_front() {
                Some(b) => { buf[n] = b; n += 1; }
                None => break,
            }
        }
    }
    if n > 0 {
        {
            let mut cr = c.credit.lock();
            cr.fwd_cnt = cr.fwd_cnt.wrapping_add(n as u32);
        }
        send_credit_update(c);
        return Ok(n);
    }
    match *c.st.lock() {
        VsockState::RcvShutdown | VsockState::Closed => Ok(0),
        _ => Err(NetError::Eagain),
    }
}

/// Close: send OP_SHUTDOWN(both) then OP_RST, mark Closed, remove from
/// the table. # C: O(1)
pub fn close(c: &VsockConn) {
    let was = *c.st.lock();
    if matches!(was, VsockState::Connected | VsockState::RcvShutdown) {
        let sh = c.make_hdr(VIRTIO_VSOCK_OP_SHUTDOWN, 0,
            VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND);
        let _ = tx_for(c.owner, &sh, &[]);
        let rst = c.make_hdr(VIRTIO_VSOCK_OP_RST, 0, 0);
        let _ = tx_for(c.owner, &rst, &[]);
    }
    *c.st.lock() = VsockState::Closed;
    TABLE.remove(c.key());
}
