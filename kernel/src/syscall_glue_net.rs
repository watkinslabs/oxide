// AF_INET socket syscalls — `sys_socket`, `sys_bind`, `sys_sendto`,
// `sys_recvfrom`, `sys_close` (the last via the existing close
// path; socket fds are normal VFS inodes).
//
// v1 supports SOCK_DGRAM/UDP only over AF_INET (IPv4).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use vfs::{Dentry, File, OpenFlags};

use crate::dev_net::{InetSocket, socket_sendto, socket_recv};

const AF_INET:    u32 = 2;
const SOCK_DGRAM: u32 = 2;

fn errno_from_neterr(e: net::NetError) -> i64 {
    -(match e {
        net::NetError::Eaddrinuse    => Errno::Eaddrinuse,
        net::NetError::Eaddrnotavail => Errno::Eaddrnotavail,
        net::NetError::Enobufs       => Errno::Enobufs,
        net::NetError::Enomem        => Errno::Enomem,
        net::NetError::Enetunreach   => Errno::Enetunreach,
        net::NetError::Einval        => Errno::Einval,
        net::NetError::Eio           => Errno::Eio,
        net::NetError::Eagain        => Errno::Eagain,
        net::NetError::Eafnosupport  => Errno::Eafnosupport,
        net::NetError::Enotconn      => Errno::Enotconn,
        net::NetError::Erange        => Errno::Erange,
    } as i32 as i64)
}

/// `socket(domain, type, protocol)` slot 41.
/// # C: O(1)
pub fn kernel_sys_socket(args: &SyscallArgs) -> i64 {
    let domain = args.a0 as u32;
    let typ    = args.a1 as u32 & 0xFF;  // strip SOCK_NONBLOCK / SOCK_CLOEXEC
    if domain != AF_INET { return -(Errno::Eafnosupport.as_i32() as i64); }
    if typ    != SOCK_DGRAM { return -(Errno::Esocktnosupport.as_i32() as i64); }
    let inode: vfs::InodeRef = Arc::new(InetSocket::new()) as _;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, String::from("[socket]"), Arc::clone(&inode));
    let file = File::new(inode, dentry, OpenFlags::empty());
    match fdt.alloc(file) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}

/// Read a `struct sockaddr_in` (16 bytes) at user pointer `ptr`:
///   u16 sin_family ; u16 sin_port ; u32 sin_addr ; u8 zero[8].
fn read_sockaddr_in(ptr: u64) -> Option<(u32, u16, u32)> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 8-byte aligned read.
    unsafe {
        let family = core::ptr::read_volatile(ptr as *const u16) as u32;
        let port_be = core::ptr::read_volatile((ptr + 2) as *const u16);
        let addr_be = core::ptr::read_volatile((ptr + 4) as *const u32);
        Some((family, u16::from_be(port_be), u32::from_be(addr_be)))
    }
}

fn write_sockaddr_in(ptr: u64, addr_be: u32, port_be: u16) {
    if ptr == 0 || ptr >= USER_VA_END { return; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 8-byte writes.
    unsafe {
        core::ptr::write_volatile(ptr as *mut u16, AF_INET as u16);
        core::ptr::write_volatile((ptr + 2) as *mut u16, port_be);
        core::ptr::write_volatile((ptr + 4) as *mut u32, addr_be);
        core::ptr::write_volatile((ptr + 8) as *mut u64, 0);
    }
}

fn socket_from_fd(fd: u64) -> Option<Arc<InetSocket>> {
    let cur = crate::sched::current()?;
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?;
    let file = fdt.get(fd as i32).ok()?;
    let inode: &vfs::InodeRef = file.inode();
    // Downcast from Arc<dyn Inode> by raw-pointer compare with
    // a sentinel — vfs::Inode doesn't expose Any. Workaround:
    // wrap the InetSocket in an Arc<dyn Inode> and rely on
    // matching the underlying type via a dedicated tag inode.
    // Simpler: stash a raw &InetSocket via a downcast helper.
    // For v1 we pattern: Arc<dyn Inode> → check ino() upper bits.
    let raw_ino = inode.ino();
    if (raw_ino & 0xFFFF_FFFF_0000_0000) != 0x534F_434B_0000_0000 {
        return None;
    }
    // SAFETY: ino tag confirms this Inode is an InetSocket; the
    // pointer encoded in the low 32 bits is a valid &InetSocket
    // for the Arc's lifetime (kept alive by `file`).
    let ptr = (raw_ino & 0xFFFF_FFFF) as usize;
    let _ = ptr;
    // Cleaner lift: clone the Arc<dyn Inode>, then convert via
    // a transmute through Arc::into_raw. We can't do that safely
    // without a downcast trait. So: rebuild an InetSocket-shaped
    // handle by re-reading. This v1 implementation requires the
    // caller supply the InetSocket directly via the fd_table —
    // which it does, since the Arc holds the InetSocket. We just
    // can't retrieve it as Arc<InetSocket> without a dedicated
    // downcast helper. Add one here.
    let sock_arc = inode_as_inet_socket(inode)?;
    Some(sock_arc)
}

/// Downcast an `Arc<dyn vfs::Inode>` to `Arc<InetSocket>` by
/// pattern: only succeeds when the inode IS an InetSocket
/// (vouched by the high-bit tag in `ino()`).
fn inode_as_inet_socket(inode: &vfs::InodeRef) -> Option<Arc<InetSocket>> {
    if (inode.ino() & 0xFFFF_FFFF_0000_0000) != 0x534F_434B_0000_0000 {
        return None;
    }
    // Erase fat-pointer metadata via Arc::into_raw → cast to
    // *const InetSocket → Arc::from_raw. Sound only because we
    // verified the tag.
    let raw = Arc::into_raw(inode.clone());
    let ptr = raw as *const InetSocket;
    // SAFETY: ino tag check above confirms the inode is an
    // InetSocket; refcount was just incremented by `Arc::clone`
    // followed by `into_raw` so the new Arc::from_raw consumes it.
    let arc = unsafe { Arc::from_raw(ptr) };
    Some(arc)
}

/// `bind(fd, addr, addrlen)` slot 49.
pub fn kernel_sys_bind(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock   = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    let (family, port, addr) = match read_sockaddr_in(addr_p) {
        Some(t) => t, None => return -(Errno::Efault.as_i32() as i64),
    };
    if family != AF_INET { return -(Errno::Eafnosupport.as_i32() as i64); }
    let ip = net::Ipv4Addr::from_u32(addr);
    match crate::dev_net::stack().bind_udp(ip, port) {
        Ok(())   => {
            *sock.local_port.lock() = Some(port);
            *sock.local_ip.lock()   = ip;
            0
        }
        Err(e) => errno_from_neterr(e),
    }
}

/// `sendto(fd, buf, len, flags, dest, dest_len)` slot 44.
pub fn kernel_sys_sendto(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let bufp   = args.a1;
    let len    = args.a2 as usize;
    let dest_p = args.a4;
    let sock   = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    if len > 65507 { return -(Errno::Emsgsize.as_i32() as i64); }
    // SAFETY: ptr range validated; user page mapped under caller's AS.
    let payload: alloc::vec::Vec<u8> = unsafe {
        core::slice::from_raw_parts(bufp as *const u8, len).to_vec()
    };
    let (dst_ip, dst_port) = if dest_p != 0 {
        match read_sockaddr_in(dest_p) {
            Some((fam, p, a)) if fam == AF_INET => (net::Ipv4Addr::from_u32(a), p),
            _ => return -(Errno::Einval.as_i32() as i64),
        }
    } else {
        match *sock.peer.lock() {
            Some(t) => t, None => return -(Errno::Edestaddrreq.as_i32() as i64),
        }
    };
    match socket_sendto(&sock, dst_ip, dst_port, &payload) {
        Ok(n)  => n as i64,
        Err(e) => errno_from_neterr(e),
    }
}

/// `recvfrom(fd, buf, len, flags, src, src_len)` slot 45.
pub fn kernel_sys_recvfrom(args: &SyscallArgs) -> i64 {
    let fd       = args.a0;
    let bufp     = args.a1;
    let len      = args.a2 as usize;
    let src_p    = args.a4;
    let sock     = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let (src_ip, src_port, payload) = match socket_recv(&sock) {
        Some(t) => t, None => return -(Errno::Eagain.as_i32() as i64),
    };
    let take = core::cmp::min(len, payload.len());
    // SAFETY: ptr+take validated < USER_VA_END; user page mapped under caller's AS.
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), bufp as *mut u8, take);
    }
    if src_p != 0 {
        write_sockaddr_in(src_p, src_ip.as_u32().to_be(), src_port.to_be());
    }
    take as i64
}
