// 048 shutdown — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use net::sock::{SockKind, drain_loopback};
use crate::net_trace::trace_enotsock_at;
use crate::net_common::socket_from_fd;

/// `shutdown(fd, how)` slot 48. POSIX semantics:
///   SHUT_RD   (0) — disable read side; future read()/recv* return EOF
///   SHUT_WR   (1) — disable write side; send FIN to peer
///   SHUT_RDWR (2) — both
/// AF_UNIX SHUT_WR maps to UnixPair::close_writer; TCP SHUT_WR maps
/// to tcp_close (sends FIN). SHUT_RD sets the per-socket read_shut
/// flag honored by Inode::read / read_nonblock.
/// # C: O(1)
pub fn sys_shutdown(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let fd  = args.a0;
    let how = args.a1 as u32;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"shutdown"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    const SHUT_RD:   u32 = 0;
    const SHUT_WR:   u32 = 1;
    const SHUT_RDWR: u32 = 2;
    let do_rd = matches!(how, SHUT_RD | SHUT_RDWR);
    let do_wr = matches!(how, SHUT_WR | SHUT_RDWR);
    if do_rd { sock.read_shut.store(true, Ordering::Release); }
    if do_wr {
        match &*sock.kind.lock() {
            SockKind::Unix(p, e)        => p.close_writer(*e),
            SockKind::UnixMsgPair(p, e) => p.close_writer(*e),
            SockKind::TcpConn(entry)    => {
                let _ = net::sock::stack().tcp_close(entry);
                drain_loopback();
            }
            _ => {}
        }
    }
    0
}
