// F161: InetSocket::Drop — last-fd close path. Extracted from
// sock.rs to stay under the 1000-line per-file cap (docs/08§7).
// When the final Arc<InetSocket> drops, tell the peer: TCP emits
// FIN/RST via the TCB; UDP unbinds the port. AF_UNIX peer-EOF
// rides the existing UnixPair / queue Drop in unix_sock.

use crate::sock::{InetSocket, SockKind, drain_loopback, stack};

impl Drop for InetSocket {
    fn drop(&mut self) {
        let stk = stack();
        if let SockKind::TcpConn(entry) = &*self.kind.lock() {
            let (seg, src, dst) = {
                let mut c = entry.conn.lock();
                let s = c.drop_close();
                (s, c.local.ip, c.remote.ip)
            };
            if let Some(seg_bytes) = seg {
                let _ = stk.send_l4_over_ip(src, dst, crate::addr::IpProto::Tcp, &seg_bytes);
                drain_loopback();
            }
            #[cfg(target_os = "oxide-kernel")]
            entry.rx_waiters.wake_all();
        }
        if matches!(*self.kind.lock(), SockKind::Udp) {
            if let Some(p) = *self.local_port.lock() {
                stk.unbind_udp(p);
            }
        }
    }
}
