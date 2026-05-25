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
        // F168: surface -EINTR if a non-blocked signal arrived between
        // our last wake and now.
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 {
            return Err(NetError::Eintr);
        }
        // SAFETY: process ctx (sys_connect); runqueue installed; preempt-off owned by syscall stub; park+schedule resume on deliver_tcp/retx_tick wake / signal wake.
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
    deadline_ns: u64,
    nodelay: bool,
) -> vfs::KResult<usize> {
    let mut total = 0usize;
    while total < buf.len() {
        match stack().tcp_send(entry, &buf[total..], sndbuf_cap, nodelay) {
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
                // F168: signal-interruptible — return short success
                // if we already accepted some bytes, else EINTR.
                #[cfg(target_os = "oxide-kernel")]
                if sched::live::deliverable_signals_self() != 0 {
                    if total > 0 { return Ok(total); }
                    return Err(vfs::VfsError::Eintr);
                }
                // F169: SO_SNDTIMEO expiry → short success or Eagain.
                #[cfg(target_os = "oxide-kernel")]
                if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns {
                    if total > 0 { return Ok(total); }
                    return Err(vfs::VfsError::Eagain);
                }
                // SAFETY: process ctx (sys_write); runqueue installed; preempt-off owned by syscall stub; park_with_deadline + schedule resume on deliver_tcp / signal / timer wake.
                #[cfg(target_os = "oxide-kernel")]
                unsafe {
                    entry.rx_waiters.park_with_deadline(deadline_ns);
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
    deadline_ns: u64,
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
        // F168: any non-blocked pending signal aborts the wait with
        // -EINTR before parking — Linux semantic for slow syscalls.
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 {
            return Err(vfs::VfsError::Eintr);
        }
        // F169: SO_RCVTIMEO expiry → Eagain (POSIX).
        #[cfg(target_os = "oxide-kernel")]
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns {
            return Err(vfs::VfsError::Eagain);
        }
        // SAFETY: process ctx (sys_read); runqueue installed; preempt-off owned by syscall stub; park_with_deadline + schedule resume on deliver_tcp / signal / timer wake.
        #[cfg(target_os = "oxide-kernel")]
        unsafe {
            entry.rx_waiters.park_with_deadline(deadline_ns);
            sched::live::schedule::schedule();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(vfs::VfsError::Eagain);
    }
}

/// F171: blocking read on an AF_UNIX SOCK_STREAM pair. Park on
/// the per-ring read waitq until the writer pushes or closes;
/// return EOF (Ok(0)) when peer closed AND ring is empty. Honors
/// SO_RCVTIMEO via park_with_deadline (timer scanner wake → Eagain).
/// # C: blocks until ring non-empty or peer FIN/close
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn read_unix_stream_blocking(
    pair: &alloc::sync::Arc<crate::UnixPair>,
    end: crate::UnixEnd,
    buf: &mut [u8],
    deadline_ns: u64,
) -> vfs::KResult<usize> {
    loop {
        let got = pair.read(end, buf.len());
        if !got.is_empty() {
            let n = got.len();
            buf[..n].copy_from_slice(&got);
            return Ok(n);
        }
        if pair.is_eof(end) { return Ok(0); }
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 {
            return Err(vfs::VfsError::Eintr);
        }
        #[cfg(target_os = "oxide-kernel")]
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns {
            return Err(vfs::VfsError::Eagain);
        }
        // SAFETY: process ctx; preempt-off owned by syscall stub; writer wakes us via pair.reader_waiters(end).wake_all.
        #[cfg(target_os = "oxide-kernel")]
        unsafe {
            pair.reader_waiters(end).park_with_deadline(deadline_ns);
            sched::live::schedule::schedule();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(vfs::VfsError::Eagain);
    }
}

/// F171: blocking recv on an AF_UNIX SOCK_SEQPACKET/SOCK_DGRAM
/// socketpair (UnixMsgPair). Per-message semantic: returns at
/// most one pre-truncated message per call. EOF when peer closed
/// AND queue drained.
/// # C: blocks until queue non-empty or peer FIN/close
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn read_unix_msg_blocking(
    pair: &alloc::sync::Arc<crate::UnixMsgPair>,
    end: crate::UnixEnd,
    buf: &mut [u8],
    deadline_ns: u64,
) -> vfs::KResult<usize> {
    loop {
        if let Some(msg) = pair.recv(end, buf.len()) {
            let n = msg.len();
            buf[..n].copy_from_slice(&msg);
            return Ok(n);
        }
        // recv returns None only when nothing pending AND not EOF
        // (EOF returns Some(empty)). So fall through to park.
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 {
            return Err(vfs::VfsError::Eintr);
        }
        #[cfg(target_os = "oxide-kernel")]
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns {
            return Err(vfs::VfsError::Eagain);
        }
        // SAFETY: process ctx; preempt-off; sender wakes us via pair.reader_waiters(end).wake_all.
        #[cfg(target_os = "oxide-kernel")]
        unsafe {
            pair.reader_waiters(end).park_with_deadline(deadline_ns);
            sched::live::schedule::schedule();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(vfs::VfsError::Eagain);
    }
}

/// F169: monotonic-ns reader visible to io helpers without
/// crossing the kernel-vs-hosted boundary at every call site.
#[cfg(target_os = "oxide-kernel")]
fn monotonic_ns_safe() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { return hal_x86_64::X86TimerOps::monotonic_ns().0; }
    #[cfg(target_arch = "aarch64")]
    { return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
    #[allow(unreachable_code)]
    0
}

/// F169: convert a SO_RCVTIMEO / SO_SNDTIMEO ns value into an
/// absolute monotonic deadline. `0` (no timeout configured) →
/// `0` (indefinite wait). Saturating add prevents wrap.
/// # C: O(1)
pub fn compute_deadline_ns(timeo_ns: i64) -> u64 {
    if timeo_ns <= 0 { return 0; }
    let now = monotonic_ns_safe();
    if now == 0 { return 0; }
    now.saturating_add(timeo_ns as u64)
}
