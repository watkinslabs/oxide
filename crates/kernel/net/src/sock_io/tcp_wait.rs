use crate::netdev::NetError;
use crate::sock::{drain_loopback, InetSocket};
use crate::stack::{TcpConnectWait, TcpEntry};

/// F159: blocking wait for TCP connect's SYN-ACK. # C: blocks until Established or Closed
pub(crate) fn connect_wait_established(
    sock: &InetSocket, entry: &alloc::sync::Arc<TcpEntry>) -> Result<(), NetError>
{
    let deadline_ns = crate::sock::compute_deadline_ns(
        sock.opts.sndtimeo_ns.load(core::sync::atomic::Ordering::Acquire));
    loop {
        drain_loopback();
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 { return Err(NetError::Eintr); }
        #[cfg(target_os = "oxide-kernel")]
        if deadline_ns != 0 && crate::sock_io::monotonic_ns_safe() >= deadline_ns {
            // Linux leaves the active open in progress when SO_SNDTIMEO
            // expires; the timed blocking call reports EINPROGRESS rather
            // than the generic would-block errno.
            return Err(NetError::Einprogress);
        }
        #[cfg(target_os = "oxide-kernel")]
        match entry.arm_connect_wait(deadline_ns) {
            TcpConnectWait::Established => return Ok(()),
            TcpConnectWait::Closed => {
                return Err(crate::sock_error::terminal_connect_error(
                    sock.take_pending_recv_error()));
            }
            TcpConnectWait::Parked => {
                // SAFETY: arm_connect_wait registered current under conn.
                unsafe { sched::live::schedule::schedule(); }
                entry.rx_waiters.remove_current();
            }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(NetError::Eio);
    }
}
