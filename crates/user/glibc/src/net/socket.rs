// socket — BSD sockets API (docs/59§6 G13). Address/message structs (byte-
// exact glibc layout, size-asserted vs the libc crate) + freestanding syscall
// wrappers. x86_64/aarch64 both use individual socket syscalls (not socketcall).
#![allow(clippy::upper_case_acronyms)]
use core::ffi::c_void;

pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;
pub const SOCK_CLOEXEC: i32 = 0o2000000;
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOL_SOCKET: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_ERROR: i32 = 4;
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

#[repr(C)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16, // network byte order
    pub sin_addr: u32, // network byte order
    pub sin_zero: [u8; 8],
}
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: u16,
    __ss_padding: [u8; 118],
    __ss_align: u64,
}
#[repr(C)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}
#[repr(C)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: u32,
    __pad1: u32,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: usize,
    pub msg_control: *mut c_void,
    pub msg_controllen: usize,
    pub msg_flags: i32,
    __pad2: u32,
}

const _: () = assert!(core::mem::size_of::<sockaddr>() == 16);
const _: () = assert!(core::mem::size_of::<sockaddr_in>() == 16);
const _: () = assert!(core::mem::size_of::<sockaddr_in6>() == 28);
const _: () = assert!(core::mem::size_of::<sockaddr_storage>() == 128);
const _: () = assert!(core::mem::size_of::<msghdr>() == 56);
const _: () = assert!(core::mem::size_of::<iovec>() == 16);

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use crate::arch::syscall::{sys3, sys4, sys5, sys6};
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;

    // # C: int socket(int domain, int type, int protocol)
    #[no_mangle]
    pub unsafe extern "C" fn socket(domain: i32, ty: i32, proto: i32) -> i32 {
        // SAFETY: scalar args; socket(2) dereferences no memory.
        ret_isize(unsafe { sys3(nr::SOCKET, domain as usize, ty as usize, proto as usize) }) as i32
    }
    // # C: int socketpair(int domain, int type, int protocol, int sv[2])
    #[no_mangle]
    pub unsafe extern "C" fn socketpair(domain: i32, ty: i32, proto: i32, sv: *mut i32) -> i32 {
        // SAFETY: sv is a writable [i32;2] out-param per socketpair(2).
        ret_isize(unsafe { sys4(nr::SOCKETPAIR, domain as usize, ty as usize, proto as usize, sv as usize) }) as i32
    }
    // # C: int bind(int fd, const struct sockaddr *addr, socklen_t len)
    #[no_mangle]
    pub unsafe extern "C" fn bind(fd: i32, addr: *const sockaddr, len: u32) -> i32 {
        // SAFETY: addr points at `len` valid bytes of a sockaddr.
        ret_isize(unsafe { sys3(nr::BIND, fd as usize, addr as usize, len as usize) }) as i32
    }
    // # C: int listen(int fd, int backlog)
    #[no_mangle]
    pub unsafe extern "C" fn listen(fd: i32, backlog: i32) -> i32 {
        // SAFETY: scalar args.
        ret_isize(unsafe { crate::arch::syscall::sys2(nr::LISTEN, fd as usize, backlog as usize) }) as i32
    }
    // # C: int accept(int fd, struct sockaddr *addr, socklen_t *len)
    #[no_mangle]
    pub unsafe extern "C" fn accept(fd: i32, addr: *mut sockaddr, len: *mut u32) -> i32 {
        // SAFETY: addr/len are null or writable out-params per accept(2).
        ret_isize(unsafe { sys3(nr::ACCEPT, fd as usize, addr as usize, len as usize) }) as i32
    }
    // # C: int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn accept4(fd: i32, addr: *mut sockaddr, len: *mut u32, flags: i32) -> i32 {
        // SAFETY: addr/len null or writable; flags scalar.
        ret_isize(unsafe { sys4(nr::ACCEPT4, fd as usize, addr as usize, len as usize, flags as usize) }) as i32
    }
    // # C: int connect(int fd, const struct sockaddr *addr, socklen_t len)
    #[no_mangle]
    pub unsafe extern "C" fn connect(fd: i32, addr: *const sockaddr, len: u32) -> i32 {
        // SAFETY: addr points at `len` valid bytes.
        ret_isize(unsafe { sys3(nr::CONNECT, fd as usize, addr as usize, len as usize) }) as i32
    }
    // # C: int getsockname(int fd, struct sockaddr *addr, socklen_t *len)
    #[no_mangle]
    pub unsafe extern "C" fn getsockname(fd: i32, addr: *mut sockaddr, len: *mut u32) -> i32 {
        // SAFETY: addr/len are writable out-params with *len the capacity.
        ret_isize(unsafe { sys3(nr::GETSOCKNAME, fd as usize, addr as usize, len as usize) }) as i32
    }
    // # C: int getpeername(int fd, struct sockaddr *addr, socklen_t *len)
    #[no_mangle]
    pub unsafe extern "C" fn getpeername(fd: i32, addr: *mut sockaddr, len: *mut u32) -> i32 {
        // SAFETY: addr/len are writable out-params with *len the capacity.
        ret_isize(unsafe { sys3(nr::GETPEERNAME, fd as usize, addr as usize, len as usize) }) as i32
    }
    // # C: ssize_t sendto(int fd, const void *buf, size_t n, int flags, const sockaddr *to, socklen_t tolen)
    #[no_mangle]
    pub unsafe extern "C" fn sendto(fd: i32, buf: *const c_void, n: usize, flags: i32, to: *const sockaddr, tolen: u32) -> isize {
        // SAFETY: buf is readable for n bytes; to is null or a valid sockaddr.
        ret_isize(unsafe { sys6(nr::SENDTO, fd as usize, buf as usize, n, flags as usize, to as usize, tolen as usize) })
    }
    // # C: ssize_t recvfrom(int fd, void *buf, size_t n, int flags, sockaddr *from, socklen_t *fromlen)
    #[no_mangle]
    pub unsafe extern "C" fn recvfrom(fd: i32, buf: *mut c_void, n: usize, flags: i32, from: *mut sockaddr, fromlen: *mut u32) -> isize {
        // SAFETY: buf is writable for n bytes; from/fromlen null or writable.
        ret_isize(unsafe { sys6(nr::RECVFROM, fd as usize, buf as usize, n, flags as usize, from as usize, fromlen as usize) })
    }
    // # C: ssize_t send(int fd, const void *buf, size_t n, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn send(fd: i32, buf: *const c_void, n: usize, flags: i32) -> isize {
        // SAFETY: buf is readable for n bytes; send is sendto with no address.
        unsafe { sendto(fd, buf, n, flags, core::ptr::null(), 0) }
    }
    // # C: ssize_t recv(int fd, void *buf, size_t n, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn recv(fd: i32, buf: *mut c_void, n: usize, flags: i32) -> isize {
        // SAFETY: buf is writable for n bytes; recv is recvfrom with no address.
        unsafe { recvfrom(fd, buf, n, flags, core::ptr::null_mut(), core::ptr::null_mut()) }
    }
    // # C: ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn sendmsg(fd: i32, msg: *const msghdr, flags: i32) -> isize {
        // SAFETY: msg is a valid msghdr describing readable iovecs.
        ret_isize(unsafe { sys3(nr::SENDMSG, fd as usize, msg as usize, flags as usize) })
    }
    // # C: ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn recvmsg(fd: i32, msg: *mut msghdr, flags: i32) -> isize {
        // SAFETY: msg is a valid msghdr describing writable iovecs.
        ret_isize(unsafe { sys3(nr::RECVMSG, fd as usize, msg as usize, flags as usize) })
    }
    // # C: int shutdown(int fd, int how)
    #[no_mangle]
    pub unsafe extern "C" fn shutdown(fd: i32, how: i32) -> i32 {
        // SAFETY: scalar args.
        ret_isize(unsafe { crate::arch::syscall::sys2(nr::SHUTDOWN, fd as usize, how as usize) }) as i32
    }
    // # C: int setsockopt(int fd, int level, int opt, const void *val, socklen_t len)
    #[no_mangle]
    pub unsafe extern "C" fn setsockopt(fd: i32, level: i32, opt: i32, val: *const c_void, len: u32) -> i32 {
        // SAFETY: val points at `len` readable bytes.
        ret_isize(unsafe { sys5(nr::SETSOCKOPT, fd as usize, level as usize, opt as usize, val as usize, len as usize) }) as i32
    }
    // # C: int getsockopt(int fd, int level, int opt, void *val, socklen_t *len)
    #[no_mangle]
    pub unsafe extern "C" fn getsockopt(fd: i32, level: i32, opt: i32, val: *mut c_void, len: *mut u32) -> i32 {
        // SAFETY: val/len are writable out-params with *len the capacity.
        ret_isize(unsafe { sys5(nr::GETSOCKOPT, fd as usize, level as usize, opt as usize, val as usize, len as usize) }) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn struct_sizes_match_host() {
        assert_eq!(core::mem::size_of::<sockaddr>(), core::mem::size_of::<libc::sockaddr>());
        assert_eq!(core::mem::size_of::<sockaddr_in>(), core::mem::size_of::<libc::sockaddr_in>());
        assert_eq!(core::mem::size_of::<sockaddr_in6>(), core::mem::size_of::<libc::sockaddr_in6>());
        assert_eq!(core::mem::size_of::<sockaddr_storage>(), core::mem::size_of::<libc::sockaddr_storage>());
        assert_eq!(core::mem::size_of::<msghdr>(), core::mem::size_of::<libc::msghdr>());
        assert_eq!(core::mem::size_of::<iovec>(), core::mem::size_of::<libc::iovec>());
    }
}
