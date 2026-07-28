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

/// Copy the listener's socket-buffer sizing onto an accepted child, the part
/// of Linux `sk_clone_lock` (`net/core/sock.c`) this kernel's readiness and
/// backpressure paths depend on: `sk_sndbuf`, `sk_rcvbuf` and the
/// `SOCK_RCVBUF_LOCK` userlock. Broader `SO_*` inheritance at accept is still
/// absent — tracked in `scratch/audit-net-sec.md`.
/// # C: O(1)
pub(crate) fn inherit_buffer_opts(listener: &InetSocket, child: &InetSocket) {
    child.opts.sndbuf.store(listener.opts.sndbuf.load(Ordering::Acquire), Ordering::Release);
    child.opts.rcvbuf.store(listener.opts.rcvbuf.load(Ordering::Acquire), Ordering::Release);
    child.opts.rcvbuf_locked.store(
        listener.opts.rcvbuf_locked.load(Ordering::Acquire), Ordering::Release);
}
