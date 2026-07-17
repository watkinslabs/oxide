use super::*;
use core::ffi::c_void;
    use core::cell::UnsafeCell;
    use core::ffi::c_char;
    use crate::arch::syscall::{sys1, sys3, sys4, sys5, sys6};
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;
    use crate::malloc::heap;

    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_MSFILTER: i32 = 41;
    const MCAST_MSFILTER: i32 = 48;
    const ENOMEM: i32 = 12;
    const EINVAL: i32 = 22;
    const ENOENT: i32 = 2;

    unsafe fn print_unknown_host(host: *const c_char) {
        let mut n = 0usize;
        while n < 240 && unsafe { *host.add(n) } != 0 { n += 1; }
        if n == 0 || n == 240 { return; }
        let _ = unsafe { crate::arch::syscall::sys3(crate::internal::nr::WRITE, 2,
            host as usize, n) };
        let suffix = b": Unknown host\n";
        let _ = unsafe { crate::arch::syscall::sys3(crate::internal::nr::WRITE, 2,
            suffix.as_ptr() as usize, suffix.len()) };
    }

    #[repr(transparent)]
    struct I32Cell(UnsafeCell<i32>);
    // SAFETY: rexecoptions is a historical writable C data symbol. glibc also
    // exposes it as unsynchronised process-global state.
    unsafe impl Sync for I32Cell {}

    // # C: int rexecoptions;
    #[no_mangle]
    static rexecoptions: I32Cell = I32Cell(UnsafeCell::new(0));

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
    // # C: int __socket(int domain, int type, int protocol)
    #[no_mangle]
    pub unsafe extern "C" fn __socket(domain: i32, ty: i32, proto: i32) -> i32 {
        // SAFETY: internal alias has the same scalar argument contract as socket.
        unsafe { socket(domain, ty, proto) }
    }
    // # C: int rresvport_af(int *alport, int family)
    #[no_mangle]
    pub unsafe extern "C" fn rresvport_af(alport: *mut i32, family: i32) -> i32 {
        // SAFETY: alport is a writable port out-param. A TCP socket is opened,
        // bound through bindresvport, and closed on bind failure.
        unsafe {
            let fd = socket(family, SOCK_STREAM, 0);
            if fd < 0 { return -1; }
            let mut sin = sockaddr_in { sin_family: family as u16, sin_port: 0, sin_addr: 0, sin_zero: [0; 8] };
            if !alport.is_null() && *alport > 0 { sin.sin_port = (*alport as u16).to_be(); }
            let r = bindresvport(fd, &mut sin);
            if r == 0 {
                if !alport.is_null() { *alport = u16::from_be(sin.sin_port) as i32; }
                fd
            } else {
                if !alport.is_null() { *alport = u16::from_be(sin.sin_port) as i32; }
                sys1(nr::CLOSE, fd as usize);
                -1
            }
        }
    }

    // # C: int rresvport(int *alport)
    #[no_mangle]
    pub unsafe extern "C" fn rresvport(alport: *mut i32) -> i32 {
        // SAFETY: rresvport is the IPv4 form of rresvport_af.
        unsafe { rresvport_af(alport, AF_INET as i32) }
    }
    // # C: int rcmd_af(char **ahost, unsigned short rport, const char *locuser, const char *remuser, const char *cmd, int *fd2p, sa_family_t af)
    #[no_mangle]
    pub unsafe extern "C" fn rcmd_af(_ahost: *mut *mut c_char, _rport: u16, _locuser: *const c_char, _remuser: *const c_char, _cmd: *const c_char, _fd2p: *mut i32, _af: u16) -> i32 {
        crate::internal::errno::set(EINVAL);
        -1
    }

    // # C: int rcmd(char **ahost, unsigned short rport, const char *locuser, const char *remuser, const char *cmd, int *fd2p)
    #[no_mangle]
    pub unsafe extern "C" fn rcmd(ahost: *mut *mut c_char, rport: u16, locuser: *const c_char, remuser: *const c_char, cmd: *const c_char, fd2p: *mut i32) -> i32 {
        // SAFETY: rcmd is the IPv4 form of rcmd_af.
        unsafe { rcmd_af(ahost, rport, locuser, remuser, cmd, fd2p, AF_INET) }
    }

    // # C: int rexec_af(char **ahost, int rport, const char *name, const char *pass, const char *cmd, int *fd2p, sa_family_t af)
    #[no_mangle]
    pub unsafe extern "C" fn rexec_af(_ahost: *mut *mut c_char, _rport: i32, _name: *const c_char, _pass: *const c_char, _cmd: *const c_char, _fd2p: *mut i32, _af: u16) -> i32 {
        crate::internal::errno::set(EINVAL);
        -1
    }

    // # C: int rexec(char **ahost, int rport, const char *name, const char *pass, const char *cmd, int *fd2p)
    #[no_mangle]
    pub unsafe extern "C" fn rexec(ahost: *mut *mut c_char, rport: i32, name: *const c_char, pass: *const c_char, cmd: *const c_char, fd2p: *mut i32) -> i32 {
        // SAFETY: rexec is the IPv4 form of rexec_af.
        unsafe { rexec_af(ahost, rport, name, pass, cmd, fd2p, AF_INET) }
    }

    // # C: int ruserok_af(const char *rhost, int suser, const char *ruser, const char *luser, sa_family_t af)
    #[no_mangle]
    pub unsafe extern "C" fn ruserok_af(rhost: *const c_char, _suser: i32, _ruser: *const c_char, _luser: *const c_char, _af: u16) -> i32 {
        // SAFETY: rhost is the valid NUL-terminated hostname supplied by the caller.
        unsafe { print_unknown_host(rhost); }
        -1
    }

    // # C: int ruserok(const char *rhost, int suser, const char *ruser, const char *luser)
    #[no_mangle]
    pub unsafe extern "C" fn ruserok(rhost: *const c_char, suser: i32, ruser: *const c_char, luser: *const c_char) -> i32 {
        // SAFETY: ruserok is the IPv4 form of ruserok_af.
        unsafe { ruserok_af(rhost, suser, ruser, luser, AF_INET) }
    }

    // # C: int iruserok_af(const void *raddr, int suser, const char *ruser, const char *luser, sa_family_t af)
    #[no_mangle]
    pub unsafe extern "C" fn iruserok_af(_raddr: *const c_void, _suser: i32, _ruser: *const c_char, _luser: *const c_char, _af: u16) -> i32 {
        -1
    }

    // # C: int iruserok(uint32_t raddr, int suser, const char *ruser, const char *luser)
    #[no_mangle]
    pub unsafe extern "C" fn iruserok(raddr: u32, suser: i32, ruser: *const c_char, luser: *const c_char) -> i32 {
        // SAFETY: iruserok_af only observes the provided IPv4 address bytes.
        unsafe { iruserok_af(&raddr as *const u32 as *const c_void, suser, ruser, luser, AF_INET) }
    }

    // # C: int ruserpass(const char *host, const char **aname, const char **apass)
    #[no_mangle]
    pub unsafe extern "C" fn ruserpass(_host: *const c_char, _aname: *mut *const c_char, _apass: *mut *const c_char) -> i32 {
        // SAFETY: conservative no-.netrc path. Host glibc returns success while
        // leaving outputs untouched when HOME/.netrc cannot be opened.
        crate::internal::errno::set(ENOENT);
        0
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
    // # C: int bindresvport(int sd, struct sockaddr_in *sin)
    #[no_mangle]
    pub unsafe extern "C" fn bindresvport(fd: i32, sin: *mut sockaddr_in) -> i32 {
        // SAFETY: sin is null or a writable sockaddr_in. We bind either the
        // requested port or the historical reserved range [512, 1024).
        unsafe {
            let mut local = sockaddr_in { sin_family: AF_INET, sin_port: 0, sin_addr: 0, sin_zero: [0; 8] };
            let sp = if sin.is_null() { &mut local as *mut sockaddr_in } else { sin };
            if (*sp).sin_family == 0 { (*sp).sin_family = AF_INET; }
            if (*sp).sin_port != 0 {
                return bind(fd, sp as *const sockaddr, core::mem::size_of::<sockaddr_in>() as u32);
            }
            for port in 512u16..1024u16 {
                (*sp).sin_port = port.to_be();
                let r = bind(fd, sp as *const sockaddr, core::mem::size_of::<sockaddr_in>() as u32);
                if r == 0 { return 0; }
                let e = *crate::internal::errno::__errno_location();
                if e != 98 { return -1; } // EADDRINUSE: try the next port.
            }
            crate::internal::errno::set(98);
            -1
        }
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
    // # C: int __connect(int fd, const struct sockaddr *addr, socklen_t len)
    #[no_mangle]
    pub unsafe extern "C" fn __connect(fd: i32, addr: *const sockaddr, len: u32) -> i32 {
        // SAFETY: __connect has the same sockaddr buffer contract as connect.
        unsafe { connect(fd, addr, len) }
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
    // # C: ssize_t __send(int fd, const void *buf, size_t n, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn __send(fd: i32, buf: *const c_void, n: usize, flags: i32) -> isize {
        // SAFETY: internal alias has the same readable buffer contract as send.
        unsafe { send(fd, buf, n, flags) }
    }
    // # C: ssize_t recv(int fd, void *buf, size_t n, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn recv(fd: i32, buf: *mut c_void, n: usize, flags: i32) -> isize {
        // SAFETY: buf is writable for n bytes; recv is recvfrom with no address.
        unsafe { recvfrom(fd, buf, n, flags, core::ptr::null_mut(), core::ptr::null_mut()) }
    }
    // # C: ssize_t __recv(int fd, void *buf, size_t n, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn __recv(fd: i32, buf: *mut c_void, n: usize, flags: i32) -> isize {
        // SAFETY: internal alias has the same writable buffer contract as recv.
        unsafe { recv(fd, buf, n, flags) }
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
    // # C: int __sendmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn __sendmmsg(fd: i32, msgvec: *mut c_void, vlen: u32, flags: i32) -> i32 {
        // SAFETY: internal alias has the same mmsghdr array contract as sendmmsg.
        unsafe { sendmmsg(fd, msgvec, vlen, flags) }
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
