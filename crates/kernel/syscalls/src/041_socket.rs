// 041 socket — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use alloc::string::String;
use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{Dentry, File, OpenFlags};
use net::sock::InetSocket;
use crate::net_common::{AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM};

/// `socket(domain, type, protocol)` slot 41. # C: O(1)
pub fn sys_socket(args: &SyscallArgs) -> i64 {
    const SOCK_CLOEXEC:  u32 = 0o2_000_000;
    const SOCK_NONBLOCK: u32 = 0o0_004_000;
    const SOCK_RAW:      u32 = 3;
    let domain = args.a0 as u32;
    let raw    = args.a1 as u32;
    let typ    = raw & 0xFF;
    let proto  = args.a2 as u32;
    let cloexec  = (raw & SOCK_CLOEXEC)  != 0;
    let nonblock = (raw & SOCK_NONBLOCK) != 0;
    const AF_UNIX_DOM: u32 = 1;
    const AF_NETLINK_DOM: u32 = ::netlink::AF_NETLINK as u32;
    const AF_PACKET_DOM: u32 = 17;
    let inode: vfs::InodeRef = if domain == AF_NETLINK_DOM {
        // Linux accepts SOCK_DGRAM and SOCK_RAW for netlink (Linux's
        // own libnl uses SOCK_RAW). Other types → EPROTOTYPE.
        if typ != SOCK_DGRAM && typ != SOCK_RAW {
            return -(Errno::Esocktnosupport.as_i32() as i64);
        }
        let sock = Arc::new(::netlink::NetlinkSocket::new(proto as u16));
        // udev/systemd-udevd: a NETLINK_KOBJECT_UEVENT socket subscribes
        // to broadcast device uevents.
        if (proto as u16) == ::netlink::proto::NETLINK_KOBJECT_UEVENT {
            ::netlink::register_uevent_listener(&sock);
        }
        sock as _
    } else {
        let inet = match (domain, typ) {
            (AF_INET,  SOCK_DGRAM)  => InetSocket::new_udp(),
            (AF_INET,  SOCK_STREAM) => InetSocket::new_tcp(),
            // F142: AF_INET+SOCK_RAW admitted as UDP shell. udhcpc /
            // libc getifaddrs use RAW sockets as ioctl handles only.
            (AF_INET,  SOCK_RAW)    => InetSocket::new_udp(),
            (AF_INET6, SOCK_DGRAM)  => InetSocket::new_udp6(),
            (AF_INET6, SOCK_STREAM) => InetSocket::new_tcp6(),
            (AF_INET6, SOCK_RAW)    => InetSocket::new_udp6(),
            (AF_UNIX_DOM, SOCK_STREAM) => InetSocket::new_unix(),
            (AF_UNIX_DOM, SOCK_DGRAM)  => InetSocket::new_unix_dgram(),
            (AF_PACKET_DOM, _) => {
                // F131: proto is htons(ETH_P_*); store host-order.
                let proto_be = (proto & 0xFFFF) as u16;
                InetSocket::new_packet(proto_be.swap_bytes(), typ as u8)
            }
            (AF_INET, _) | (AF_INET6, _) | (AF_UNIX_DOM, _) => return -(Errno::Esocktnosupport.as_i32() as i64),
            _ => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        Arc::new(inet) as _
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, String::from("[socket]"), Arc::clone(&inode));
    // F198: sockets are RW by spec — File::write needs O_RDWR.
    let mut fl = OpenFlags::O_RDWR;
    if nonblock { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc(file) {
        Ok(fd) => { if cloexec { let _ = fdt.set_cloexec(fd, true); } fd as i64 }
        Err(e) => -(e as i64),
    }
}
