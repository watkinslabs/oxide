// F164: blocking-I/O helpers for AF_INET TCP sockets — extracted
// from sock.rs to stay under the 1000-line per-file cap (docs/08§7).
// Each helper parks the current task on `entry.rx_waiters`;
// `deliver_tcp.wake_all` and `tcp_retx_tick` are the wake sites.

use crate::stack::TcpEntry;
use crate::netdev::NetError;
use crate::sock::{drain_loopback, stack};

/// F159: blocking wait for TCP connect's SYN-ACK. Park on
/// `entry.rx_waiters`; `deliver_tcp` wakes after any input (state
/// transition to Established for normal path, to Closed on RST);
/// `tcp_retx_tick` wakes after flipping state to Closed for
/// retry-exhaustion. Returns Eio (ABI Etimedout) on abort, Ok on
/// Established. drain_loopback every iter so a self-loopback
/// connect doesn't depend on virtio's softirq.
/// # C: blocks until Established or Closed
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn connect_wait_established(
    entry: &alloc::sync::Arc<TcpEntry>,
) -> Result<(), NetError> {
    loop {
        drain_loopback();
        let st = entry.conn.lock().state;
        if st.is_established() { return Ok(()); }
        if st == crate::tcp_state::TcpState::Closed {
            return Err(NetError::Eio);
        }
        // SAFETY: process ctx (sys_connect); runqueue installed; preempt-off owned by syscall stub; park+schedule resume on deliver_tcp/retx_tick wake.
        #[cfg(target_os = "oxide-kernel")]
        unsafe {
            entry.rx_waiters.park();
            sched::live::schedule::schedule();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(NetError::Eio);
    }
}

/// F164: blocking TCP write. Repeatedly tcp_send into the conn,
/// parking on `entry.rx_waiters` (woken by `deliver_tcp` on every
/// input — ACKs that pop retx_q free up send-buffer headroom) until
/// either every byte is queued or the connection terminates.
/// Returns short on partial-write only after at least one byte
/// landed (POSIX short-write semantics — caller's libc retries).
/// # C: blocks until buf drained or peer dies
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn write_tcp_blocking(
    entry: &alloc::sync::Arc<TcpEntry>,
    buf: &[u8],
    sndbuf_cap: usize,
) -> vfs::KResult<usize> {
    let mut total = 0usize;
    while total < buf.len() {
        match stack().tcp_send(entry, &buf[total..], sndbuf_cap) {
            Ok(n) if n > 0 => {
                total += n;
                drain_loopback();
            }
            Ok(_) | Err(NetError::Eagain) => {
                // No space right now — park and re-check after wake.
                // First check if the conn is dead: no point waiting for
                // ACKs the peer will never send.
                let st = entry.conn.lock().state;
                if matches!(st,
                    crate::tcp_state::TcpState::Closed
                    | crate::tcp_state::TcpState::CloseWait
                    | crate::tcp_state::TcpState::LastAck
                    | crate::tcp_state::TcpState::Closing
                    | crate::tcp_state::TcpState::TimeWait
                    | crate::tcp_state::TcpState::FinWait1
                    | crate::tcp_state::TcpState::FinWait2
                ) {
                    // F166/F167: POSIX write to a closed/closing send
                    // side returns EPIPE AND raises SIGPIPE. Userspace
                    // that ignored SIGPIPE (signal(SIGPIPE, SIG_IGN))
                    // observes EPIPE; default disposition terminates
                    // the process. Short success then EPIPE on next
                    // call: surface the count now, peer hangup
                    // discovered next time.
                    #[cfg(target_os = "oxide-kernel")]
                    sched::live::send_signal_self(sched::live::Signum::Sigpipe);
                    if total > 0 { return Ok(total); }
                    return Err(vfs::VfsError::Epipe);
                }
                // SAFETY: process ctx (sys_write); runqueue installed; preempt-off owned by syscall stub; deliver_tcp's wake_all on ACK frees send_buf space.
                #[cfg(target_os = "oxide-kernel")]
                unsafe {
                    entry.rx_waiters.park();
                    sched::live::schedule::schedule();
                }
                #[cfg(not(target_os = "oxide-kernel"))]
                {
                    if total > 0 { return Ok(total); }
                    return Err(vfs::VfsError::Eagain);
                }
            }
            Err(_) => {
                if total > 0 { return Ok(total); }
                return Err(vfs::VfsError::Eio);
            }
        }
    }
    Ok(total)
}

/// F158: blocking TCP recv. Park on `entry.rx_waiters` until data
/// arrives in recv_buf or the connection reaches a terminal data
/// state (peer FIN'd → return Ok(0) for EOF, RST → Closed). Used
/// from `Inode::read` for SockKind::TcpConn. The non-blocking shim
/// `Inode::read_nonblock` does the immediate-Eagain version inline.
///
/// Drain loopback every iteration so the lo-path's TCP traffic
/// (test harness side) makes progress too — virtio-net's MSI-driven
/// softirq handles the off-host path and wakes us via wake_all.
/// # C: blocks until recv_buf non-empty or terminal state
/// # Lk: takes entry.conn briefly between yields; entry.rx_waiters during park
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn read_tcp_blocking(
    entry: &alloc::sync::Arc<TcpEntry>,
    buf: &mut [u8],
) -> vfs::KResult<usize> {
    loop {
        drain_loopback();
        let got = stack().tcp_recv(entry, buf.len());
        if !got.is_empty() {
            let n = got.len();
            buf[..n].copy_from_slice(&got);
            return Ok(n);
        }
        let st = entry.conn.lock().state;
        if st == crate::tcp_state::TcpState::Closed
            || st == crate::tcp_state::TcpState::CloseWait
            || st == crate::tcp_state::TcpState::LastAck
        {
            return Ok(0);
        }
        // Race-safe: we re-checked state and recv_buf under
        // entry.conn.lock; deliver_tcp mutates that same lock
        // before wake_all, so any wake between our check and
        // park sees post-mutation state on the next iter.
        // SAFETY: process ctx (sys_read); runqueue installed; preempt-off owned by syscall stub; park+schedule resume on deliver_tcp wake.
        #[cfg(target_os = "oxide-kernel")]
        unsafe {
            entry.rx_waiters.park();
            sched::live::schedule::schedule();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(vfs::VfsError::Eagain);
    }
}
