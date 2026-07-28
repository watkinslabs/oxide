// `setsockopt(SO_RCVBUF)` → TCP advertised receive window.
//
// Linux keeps the size on the `struct sock`, so it is already in force when the
// transport starts and `__tcp_select_window` reads it directly. Here the
// `TcpConn` is a separate object built at connect/accept time, so a size set
// BEFORE the connection existed has to be carried across explicitly — and a
// size set after has to be pushed down (`sync_tcp_rcvbuf` in the setsockopt
// shim). Without either, `rcv_autotune` grew the window to its 4 MiB ceiling
// no matter what the application asked for, so a small `SO_RCVBUF` produced no
// backpressure at all.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::types::InetSocket;
use crate::stack::TcpEntry;

/// Carry a locked `SO_RCVBUF` into a freshly built connection. No-op unless
/// the application actually named a size (Linux `SOCK_RCVBUF_LOCK`).
/// # C: O(1)
pub(crate) fn apply_tcp_rcvbuf_opt(sock: &InetSocket, entry: &Arc<TcpEntry>) {
    if !sock.opts.rcvbuf_locked.load(Ordering::Acquire) { return; }
    let bytes = sock.opts.rcvbuf.load(Ordering::Acquire).max(0) as u32;
    if bytes != 0 { entry.set_rcv_buf_cap(bytes); }
}
