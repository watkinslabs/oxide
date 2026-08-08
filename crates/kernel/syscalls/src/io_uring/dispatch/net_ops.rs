// Socket operations.
//
// `send`/`recv` carry the buffer in `addr`/`len` and the message flags in
// `op_flags`; the optional destination address of a `send` is in `addr2` with
// its length in the `addr_len` half of the splice-descriptor word — NOT in
// `len`, which is the payload size.

use super::fdres::place_result;
use super::router::{call, Op};

/// # C: O(len)
#[inline(always)]
pub fn send(op: &Op) -> i64 {
    call(crate::s044_sendto::sys_sendto,
         [op.fd as u64, op.addr, op.len as u64, op.sqe.op_flags as u64,
          op.sqe.off, op.sqe.addr_len as u64])
}

/// # C: O(len)
#[inline(always)]
pub fn recv(op: &Op) -> i64 {
    call(crate::net_recv::sys_recvfrom,
         [op.fd as u64, op.addr, op.len as u64, op.sqe.op_flags as u64, 0, 0])
}

/// # C: O(len)
#[inline(always)]
pub fn sendmsg(op: &Op) -> i64 {
    call(crate::s046_sendmsg::sys_sendmsg,
         [op.fd as u64, op.sqe.addr, op.sqe.op_flags as u64, 0, 0, 0])
}

/// # C: O(len)
#[inline(always)]
pub fn recvmsg(op: &Op) -> i64 {
    call(crate::s047_recvmsg::sys_recvmsg,
         [op.fd as u64, op.sqe.addr, op.sqe.op_flags as u64, 0, 0, 0])
}

/// # C: O(1)
pub fn accept(op: &Op) -> i64 {
    let rv = crate::s043_accept::sys_accept4(&op.sqe.accept_args(op.fd));
    place_result(op.inode, op.sqe, rv)
}

/// # C: O(1)
#[inline(always)]
pub fn connect(op: &Op) -> i64 {
    call(crate::s042_connect::sys_connect, [op.fd as u64, op.sqe.addr, op.sqe.off, 0, 0, 0])
}

/// # C: O(1)
#[inline(always)]
pub fn bind(op: &Op) -> i64 {
    call(crate::s049_bind::sys_bind, [op.fd as u64, op.sqe.addr, op.sqe.off, 0, 0, 0])
}

/// The backlog is in `len`. # C: O(1)
#[inline(always)]
pub fn listen(op: &Op) -> i64 {
    call(crate::s050_listen::sys_listen, [op.fd as u64, op.sqe.len as u64, 0, 0, 0, 0])
}

/// `how` is in `len`. # C: O(1)
#[inline(always)]
pub fn shutdown(op: &Op) -> i64 {
    call(crate::s048_shutdown::sys_shutdown, [op.fd as u64, op.sqe.len as u64, 0, 0, 0, 0])
}

/// `socket(domain, type, protocol)`: domain is the SQE's `fd` field, type is
/// `off`, protocol is `len`. # C: O(1)
pub fn socket(op: &Op) -> i64 {
    let rv = call(crate::s041_socket::sys_socket,
                  [op.sqe.fd as u64, op.sqe.off, op.sqe.len as u64, 0, 0, 0]);
    place_result(op.inode, op.sqe, rv)
}
