// 050 listen — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_common::{errno_from_neterr, fd_file, inode_as_inet_socket, vsock_from_file};

/// `listen(fd, backlog)` slot 50. ABI shim per `docs/53§4`.
/// # C: O(1)
pub fn sys_listen(args: &SyscallArgs) -> i64 {
    let fd      = args.a0;
    let backlog = args.a1 as i32;
    let file = match fd_file(fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // D3.3: AF_VSOCK listen — register the bound port in the vsock
    // connection table so inbound OP_REQUESTs are accepted + queued.
    if let Some(vs) = vsock_from_file(file.clone()) {
        return match vs.listen_with_backlog(backlog) { Ok(()) => 0, Err(error) => errno_from_neterr(error) };
    }
    let sock = match inode_as_inet_socket(file.inode()) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"listen"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    match net::sock::listen(&sock, backlog) {
        Ok(())  => { net::bind_file(&file, &sock); 0 }
        Err(e)  => errno_from_neterr(e),
    }
}
