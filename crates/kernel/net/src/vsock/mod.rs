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
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use crate::netdev::NetError;

/// Process-global connection table. # C: O(1)
pub static TABLE: VsockTable = VsockTable::new();

/// Our guest CID, published by the driver at bring-up. 0 = no device.
static GUEST_CID: AtomicU64 = AtomicU64::new(0);
/// True once a virtio-vsock device installed its TX hook.
static DRIVER_UP: AtomicBool = AtomicBool::new(false);

/// TX hook: hand a fully-encoded header + payload to the driver, which
/// builds a TX descriptor, kicks q1, and polls the used ring. Returns
/// true if the frame went out. # C: O(payload)
pub type TxFn = fn(&[u8]) -> bool;
static TX_HOOK: AtomicU64 = AtomicU64::new(0);

/// Driver bring-up entry: publish guest CID + install the TX hook.
/// Idempotent. # C: O(1)
pub fn driver_install(guest_cid: u64, tx: TxFn) {
    GUEST_CID.store(guest_cid, Ordering::Release);
    TX_HOOK.store(tx as usize as u64, Ordering::Release);
    DRIVER_UP.store(true, Ordering::Release);
}

/// Our guest CID (0 if no device). # C: O(1)
pub fn guest_cid() -> u64 { GUEST_CID.load(Ordering::Acquire) }

/// True iff a virtio-vsock device is installed. # C: O(1)
pub fn driver_up() -> bool { DRIVER_UP.load(Ordering::Acquire) }

/// Emit one packet via the driver TX hook. False if no driver. # C: O(len)
pub fn tx(hdr: &VsockHdr, payload: &[u8]) -> bool {
    let raw = TX_HOOK.load(Ordering::Acquire);
    if raw == 0 { return false; }
    // SAFETY: TX_HOOK only ever stores a `TxFn` (fn(&[u8]) -> bool) via
    // `driver_install`; the transmute reconstructs that exact fn pointer
    // shape, matching the install-site type. No other writer exists.
    let f: TxFn = unsafe { core::mem::transmute(raw as usize) };
    let mut frame = Vec::with_capacity(VSOCK_HDR_LEN + payload.len());
    frame.extend_from_slice(&hdr.encode());
    frame.extend_from_slice(payload);
    f(&frame)
}

/// Send a credit-update so the peer learns our fresh fwd_cnt after we
/// drained RX into userspace. # C: O(1)
fn send_credit_update(c: &VsockConn) {
    let h = c.make_hdr(VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0, 0);
    let _ = tx(&h, &[]);
}

/// Dispatch one fully-received inbound packet (header + `payload`) onto
/// the matching connection / listener. Called by the driver's RX drain.
/// All credit fields in every inbound header are folded into our peer
/// view (virtio 1.2 §5.10.6.3: every packet carries live credit).
/// # C: O(N conns)
pub fn deliver_rx(h: &VsockHdr, payload: &[u8]) {
    // The packet's dst is us; src is the peer.
    let local_cid  = h.dst_cid;
    let local_port = h.dst_port;
    let peer_cid   = h.src_cid;
    let peer_port  = h.src_port;

    match h.op {
        VIRTIO_VSOCK_OP_REQUEST => {
            // Inbound connection attempt. Accept iff we listen on the
            // dst port; reply OP_RESPONSE and queue for accept(). Else RST.
            if TABLE.is_listening(local_port) {
                let c = alloc::sync::Arc::new(VsockConn::new(
                    local_cid, local_port, peer_cid, peer_port,
                    VsockState::Connected));
                c.credit.lock().observe_peer(h.buf_alloc, h.fwd_cnt);
                let resp = c.make_hdr(VIRTIO_VSOCK_OP_RESPONSE, 0, 0);
                TABLE.insert(c.clone());
                let _ = tx(&resp, &[]);
                TABLE.queue_accept(local_port, c.key());
            } else {
                let rst = VsockHdr {
                    src_cid: local_cid, dst_cid: peer_cid,
                    src_port: local_port, dst_port: peer_port,
                    len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
                    op: VIRTIO_VSOCK_OP_RST, flags: 0,
                    buf_alloc: 0, fwd_cnt: 0,
                };
                let _ = tx(&rst, &[]);
            }
            return;
        }
        _ => {}
    }

    let Some(c) = TABLE.find_for_rx(local_cid, local_port, peer_cid, peer_port)
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
                let _ = tx(&rst, &[]);
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

/// Client connect: allocate a local port, register the connection, send
/// OP_REQUEST, and (kernel) park until OP_RESPONSE / RST. Returns the
/// connection on success. # C: O(RTT)
pub fn connect(peer_cid: u64, peer_port: u32)
    -> Result<alloc::sync::Arc<VsockConn>, NetError>
{
    if !driver_up() { return Err(NetError::Enetunreach); }
    let local_cid = guest_cid();
    let local_port = TABLE.alloc_port();
    let c = alloc::sync::Arc::new(VsockConn::new(
        local_cid, local_port, peer_cid, peer_port, VsockState::Connecting));
    TABLE.insert(c.clone());
    let req = c.make_hdr(VIRTIO_VSOCK_OP_REQUEST, 0, 0);
    if !tx(&req, &[]) {
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
    if !tx(&h, &buf[..n]) { return Err(NetError::Eio); }
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
        let _ = tx(&sh, &[]);
        let rst = c.make_hdr(VIRTIO_VSOCK_OP_RST, 0, 0);
        let _ = tx(&rst, &[]);
    }
    *c.st.lock() = VsockState::Closed;
    TABLE.remove(c.key());
}
