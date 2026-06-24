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
    use crate::malloc::heap;

    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_MSFILTER: i32 = 41;
    const MCAST_MSFILTER: i32 = 48;
    const ENOMEM: i32 = 12;
    const EINVAL: i32 = 22;

    #[repr(C)]
    struct IpMsfilter {
        multiaddr: u32,
        interface: u32,
        fmode: u32,
        numsrc: u32,
        slist: [u32; 1],
    }

    #[repr(C)]
    struct GroupFilter {
        interface: u32,
        group: sockaddr_storage,
        fmode: u32,
        numsrc: u32,
        slist: [sockaddr_storage; 1],
    }

    fn ip_msfilter_size(numsrc: u32) -> Option<usize> {
        core::mem::size_of::<IpMsfilter>()
            .checked_sub(core::mem::size_of::<u32>())?
            .checked_add(numsrc as usize * core::mem::size_of::<u32>())
    }

    fn group_filter_size(numsrc: u32) -> Option<usize> {
        core::mem::size_of::<GroupFilter>()
            .checked_sub(core::mem::size_of::<sockaddr_storage>())?
            .checked_add(numsrc as usize * core::mem::size_of::<sockaddr_storage>())
    }

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
        // SAFETY: listen(2) takes scalar fd+backlog, dereferences no memory.
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
    // # C: int sendmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn sendmmsg(fd: i32, msgvec: *mut c_void, vlen: u32, flags: i32) -> i32 {
        // SAFETY: msgvec is a vlen-element mmsghdr array the kernel reads/updates
        // (msg_len out-fields); returns the count of messages sent.
        ret_isize(unsafe { sys4(nr::SENDMMSG, fd as usize, msgvec as usize, vlen as usize, flags as usize) }) as i32
    }
    // # C: int recvmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen, int flags, struct timespec *timeout)
    #[no_mangle]
    pub unsafe extern "C" fn recvmmsg(fd: i32, msgvec: *mut c_void, vlen: u32, flags: i32, timeout: *mut c_void) -> i32 {
        // SAFETY: msgvec is a writable vlen-element mmsghdr array; timeout null
        // or a timespec; returns the count of messages received.
        ret_isize(unsafe { sys5(nr::RECVMMSG, fd as usize, msgvec as usize, vlen as usize, flags as usize, timeout as usize) }) as i32
    }
    // # C: int shutdown(int fd, int how)
    #[no_mangle]
    pub unsafe extern "C" fn shutdown(fd: i32, how: i32) -> i32 {
        // SAFETY: shutdown(2) takes scalar fd+how, dereferences no memory.
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
    // # C: int getipv4sourcefilter(int s, struct in_addr ifaddr,
    //                              struct in_addr group, uint32_t *fmode,
    //                              uint32_t *numsrc, struct in_addr *slist)
    #[no_mangle]
    pub unsafe extern "C" fn getipv4sourcefilter(fd: i32, ifaddr: u32, group: u32, fmode: *mut u32, numsrc: *mut u32, slist: *mut u32) -> i32 {
        // SAFETY: fmode/numsrc are writable; slist has capacity *numsrc. A
        // temporary ip_msfilter buffer is passed to getsockopt(IP_MSFILTER).
        unsafe {
            let n = *numsrc;
            let Some(size) = ip_msfilter_size(n) else { crate::internal::errno::set(EINVAL); return -1; };
            let p = heap::malloc(size) as *mut IpMsfilter;
            if p.is_null() { crate::internal::errno::set(ENOMEM); return -1; }
            (*p).multiaddr = group; (*p).interface = ifaddr; (*p).fmode = 0; (*p).numsrc = n;
            let mut len = size as u32;
            let r = getsockopt(fd, IPPROTO_IP, IP_MSFILTER, p as *mut c_void, &mut len);
            if r == 0 {
                *fmode = (*p).fmode; *numsrc = (*p).numsrc;
                core::ptr::copy_nonoverlapping((*p).slist.as_ptr(), slist, core::cmp::min(n, (*p).numsrc) as usize);
            }
            heap::free(p as *mut u8);
            r
        }
    }

    // # C: int setipv4sourcefilter(int s, struct in_addr ifaddr,
    //                              struct in_addr group, uint32_t fmode,
    //                              uint32_t numsrc, const struct in_addr *slist)
    #[no_mangle]
    pub unsafe extern "C" fn setipv4sourcefilter(fd: i32, ifaddr: u32, group: u32, fmode: u32, numsrc: u32, slist: *const u32) -> i32 {
        // SAFETY: slist points at numsrc IPv4 addresses. The packed
        // ip_msfilter buffer is passed to setsockopt(IP_MSFILTER).
        unsafe {
            let Some(size) = ip_msfilter_size(numsrc) else { crate::internal::errno::set(EINVAL); return -1; };
            let p = heap::malloc(size) as *mut IpMsfilter;
            if p.is_null() { crate::internal::errno::set(ENOMEM); return -1; }
            (*p).multiaddr = group; (*p).interface = ifaddr; (*p).fmode = fmode; (*p).numsrc = numsrc;
            core::ptr::copy_nonoverlapping(slist, (*p).slist.as_mut_ptr(), numsrc as usize);
            let r = setsockopt(fd, IPPROTO_IP, IP_MSFILTER, p as *const c_void, size as u32);
            heap::free(p as *mut u8);
            r
        }
    }

    unsafe fn sourcefilter_level(group: *const sockaddr) -> i32 {
        // SAFETY: group points at a sockaddr supplied to get/setsourcefilter.
        unsafe {
            match (*group).sa_family {
                AF_INET => IPPROTO_IP,
                AF_INET6 => IPPROTO_IPV6,
                _ => IPPROTO_IP,
            }
        }
    }

    // # C: int getsourcefilter(int s, uint32_t ifindex, const struct sockaddr *group,
    //                          socklen_t grouplen, uint32_t *fmode,
    //                          uint32_t *numsrc, struct sockaddr_storage *slist)
    #[no_mangle]
    pub unsafe extern "C" fn getsourcefilter(fd: i32, ifindex: u32, group: *const sockaddr, grouplen: u32, fmode: *mut u32, numsrc: *mut u32, slist: *mut sockaddr_storage) -> i32 {
        // SAFETY: group points at grouplen bytes; fmode/numsrc are writable and
        // slist has capacity *numsrc. Packed group_filter goes to getsockopt.
        unsafe {
            let n = *numsrc;
            let Some(size) = group_filter_size(n) else { crate::internal::errno::set(EINVAL); return -1; };
            let p = heap::malloc(size) as *mut GroupFilter;
            if p.is_null() { crate::internal::errno::set(ENOMEM); return -1; }
            (*p).interface = ifindex; (*p).fmode = 0; (*p).numsrc = n;
            core::ptr::write_bytes(&mut (*p).group as *mut sockaddr_storage as *mut u8, 0, core::mem::size_of::<sockaddr_storage>());
            core::ptr::copy_nonoverlapping(group as *const u8, &mut (*p).group as *mut sockaddr_storage as *mut u8, grouplen as usize);
            let mut len = size as u32;
            let r = getsockopt(fd, sourcefilter_level(group), MCAST_MSFILTER, p as *mut c_void, &mut len);
            if r == 0 {
                *fmode = (*p).fmode; *numsrc = (*p).numsrc;
                core::ptr::copy_nonoverlapping((*p).slist.as_ptr(), slist, core::cmp::min(n, (*p).numsrc) as usize);
            }
            heap::free(p as *mut u8);
            r
        }
    }

    // # C: int setsourcefilter(int s, uint32_t ifindex, const struct sockaddr *group,
    //                          socklen_t grouplen, uint32_t fmode,
    //                          uint32_t numsrc, const struct sockaddr_storage *slist)
    #[no_mangle]
    pub unsafe extern "C" fn setsourcefilter(fd: i32, ifindex: u32, group: *const sockaddr, grouplen: u32, fmode: u32, numsrc: u32, slist: *const sockaddr_storage) -> i32 {
        // SAFETY: group points at grouplen bytes; slist points at numsrc source
        // addresses. Packed group_filter goes to setsockopt(MCAST_MSFILTER).
        unsafe {
            let Some(size) = group_filter_size(numsrc) else { crate::internal::errno::set(EINVAL); return -1; };
            let p = heap::malloc(size) as *mut GroupFilter;
            if p.is_null() { crate::internal::errno::set(ENOMEM); return -1; }
            (*p).interface = ifindex; (*p).fmode = fmode; (*p).numsrc = numsrc;
            core::ptr::write_bytes(&mut (*p).group as *mut sockaddr_storage as *mut u8, 0, core::mem::size_of::<sockaddr_storage>());
            core::ptr::copy_nonoverlapping(group as *const u8, &mut (*p).group as *mut sockaddr_storage as *mut u8, grouplen as usize);
            core::ptr::copy_nonoverlapping(slist, (*p).slist.as_mut_ptr(), numsrc as usize);
            let r = setsockopt(fd, sourcefilter_level(group), MCAST_MSFILTER, p as *const c_void, size as u32);
            heap::free(p as *mut u8);
            r
        }
    }
    // # C: int sockatmark(int fd) — 1 if the next read is at the OOB mark, else 0.
    #[no_mangle]
    pub unsafe extern "C" fn sockatmark(fd: i32) -> i32 {
        let mut flag: i32 = 0;
        // SAFETY: ioctl(SIOCATMARK=0x8905) writes one int into flag, a valid out-param.
        let r = ret_isize(unsafe { sys3(nr::IOCTL, fd as usize, 0x8905, &mut flag as *mut i32 as usize) }) as i32;
        if r < 0 { r } else { flag }
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
