// SOL_SOCKET argument import + application for slot 54. The option table,
// capability ladder, and value transforms live in `net::sock_opts::sol_socket`
// (`docs/53§4`); this file only moves bytes and stores accepted results.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::errno::Errno;
use net::sock::InetSocket;
use net::sock_opts::sol_socket::{self as sol};
use net::sock_opts::sol_socket::set::{Action, Arg, ArgClass};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Caller's network capabilities in the socket's owning namespace. # C: O(1)
pub(super) fn caps_for(sock: &InetSocket) -> sol::OptCaps {
    let Some(cur) = sched::live::current() else { return sol::OptCaps::default(); };
    let namespace = &sock.net_namespace;
    sol::OptCaps {
        net_admin: nscg::has_net_admin_for(cur, namespace),
        net_raw: nscg::has_net_raw_for(cur, namespace),
    }
}

fn read_bytes<const N: usize>(optval: u64) -> Result<[u8; N], Errno> {
    let mut bytes = [0u8; N];
    uaccess::copy_from_user(&mut bytes, optval).map_err(|_| Errno::Efault)?;
    Ok(bytes)
}

fn i32_at(bytes: &[u8], offset: usize) -> i32 {
    i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn i64_at(bytes: &[u8], offset: usize) -> i64 {
    i64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Import the caller's argument in Linux order: the leading `int` screen runs
/// for every option except `SO_BINDTODEVICE`, so a short buffer is `EINVAL`
/// and a bad pointer `EFAULT` before the option number is classified.
/// # C: O(1)
pub(crate) fn import(optname: u64, optval: u64, optlen: u32) -> Result<Arg, Errno> {
    let width = core::mem::size_of::<i32>() as u32;
    let short = if net::sock_opts::sol_socket::exact_int_argument(optname) {
        optlen != width
    } else {
        optlen < width
    };
    if short { return Err(Errno::Einval); }
    let leading = i32_at(&read_bytes::<4>(optval)?, 0);
    match net::sock_opts::sol_socket::set::arg_class(optname) {
        ArgClass::Int | ArgClass::Device | ArgClass::Filter | ArgClass::Reuseport
            | ArgClass::Devmem => Ok(Arg::Int(leading)),
        ArgClass::Linger => {
            if optlen < 8 { return Err(Errno::Einval); }
            let bytes = read_bytes::<8>(optval)?;
            Ok(Arg::Linger { on: i32_at(&bytes, 0), seconds: i32_at(&bytes, 4) })
        }
        ArgClass::Timeval => {
            if optlen < 16 { return Err(Errno::Einval); }
            let bytes = read_bytes::<16>(optval)?;
            Ok(Arg::Timeval { sec: i64_at(&bytes, 0), usec: i64_at(&bytes, 8) })
        }
        ArgClass::TxTime => {
            if optlen != 8 { return Err(Errno::Einval); }
            let bytes = read_bytes::<8>(optval)?;
            Ok(Arg::TxTime { clockid: i32_at(&bytes, 0), flags: i32_at(&bytes, 4) as u32 })
        }
        ArgClass::Timestamping => {
            if optlen != 8 { return Ok(Arg::Int(leading)); }
            let bytes = read_bytes::<8>(optval)?;
            Ok(Arg::Timestamping { flags: i32_at(&bytes, 0), bind_phc: i32_at(&bytes, 4) })
        }
        ArgClass::PacingRate => {
            if optlen < 8 { return Ok(Arg::Int(leading)); }
            Ok(Arg::PacingRate(u64::from_ne_bytes(read_bytes::<8>(optval)?)))
        }
    }
}

/// `sock_setbindtodevice`: import the caller's interface name. An over-long
/// name is truncated rather than rejected, and an empty one clears the
/// binding, so this returns the name bytes the family must resolve — empty
/// meaning "clear". # C: O(1)
pub(crate) fn import_device_name(optval: u64, optlen: u32)
    -> Result<([u8; sol::set::IFNAMSIZ], usize), Errno>
{
    let n = sol::set::device_name_len(optlen);
    let mut name = [0u8; sol::set::IFNAMSIZ];
    if n != 0 && uaccess::copy_from_user(&mut name[..n], optval).is_err() {
        return Err(Errno::Efault);
    }
    let end = name[..n].iter().position(|b| *b == 0).unwrap_or(n);
    Ok((name, end))
}

/// `sk_setsockopt` for one SOL_SOCKET write. # C: O(1)
pub(super) fn set(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen: u32) -> i64 {
    debug_assert!(sol::reads_int_argument(optname));
    let arg = match import(optname, optval, optlen) { Ok(a) => a, Err(e) => return errno(e) };
    let personality = net::sock_opts::describe(sock);
    match net::sock_opts::sol_socket::set::arg_class(optname) {
        ArgClass::Reuseport => {
            let Arg::Int(ufd) = arg else { return errno(Errno::Einval); };
            return reuseport(sock, optname, ufd, optval, optlen);
        }
        ArgClass::Devmem => return devmem_dontneed(sock, personality, optval, optlen),
        _ => {}
    }
    let env = sock.opts.base.set_env(caps_for(sock));
    let action = match net::sock_opts::sol_socket::set::admit(optname, arg, personality, env) {
        Ok(action) => action,
        Err(e) => return errno(e),
    };
    apply(sock, action)
}

/// Attach or detach the program that steers the socket's reuseport group.
/// # C: O(program bytes)
fn reuseport(sock: &Arc<InetSocket>, optname: u64, ufd: i32, optval: u64, optlen: u32) -> i64 {
    let result = (|| -> Result<(), Errno> {
        match optname {
            sol::SO_ATTACH_REUSEPORT_CBPF => {
                let header = super::main::classic_filter_header(optval, optlen)?;
                filter_mutable(sock)?;
                let program = super::main::classic_filter_program(header)?;
                net::reuseport::attach_prog(sock, program)
            }
            sol::SO_ATTACH_REUSEPORT_EBPF => {
                if optlen != core::mem::size_of::<i32>() as u32 { return Err(Errno::Einval); }
                filter_mutable(sock)?;
                let program = super::main::bpf_prog(ufd)?;
                net::reuseport::attach_prog(sock, program)
            }
            _ => net::reuseport::detach_prog(sock),
        }
    })();
    match result { Ok(()) => 0, Err(e) => errno(e) }
}

/// A locked socket filter forbids installing another program. # C: O(1)
fn filter_mutable(sock: &Arc<InetSocket>) -> Result<(), Errno> {
    sock.bpf_filter.ensure_mutable().map_err(|_| Errno::Eperm)
}

/// `SO_DEVMEM_DONTNEED`: release device-memory receive tokens. The token space
/// is populated only by a device-memory receive binding, so a socket that never
/// received into one releases nothing and reports zero. # C: O(tokens)
fn devmem_dontneed(sock: &Arc<InetSocket>, personality: sol::OptSock, optval: u64, optlen: u32)
    -> i64
{
    let tokens = match net::sock_opts::sol_socket::set::devmem_dontneed_tokens(personality, optlen) {
        Ok(tokens) => tokens, Err(e) => return errno(e),
    };
    let mut raw = alloc::vec![0u8; tokens * sol::DEVMEM_TOKEN_SIZE];
    if !raw.is_empty() && uaccess::copy_from_user(&mut raw, optval).is_err() {
        return errno(Errno::Efault);
    }
    // The return value counts fragments actually released. A token names a
    // fragment this socket received into a device-memory binding; no receive
    // path here establishes one, so every token names nothing.
    let _ = sock;
    0
}

fn apply(sock: &Arc<InetSocket>, action: Action) -> i64 {
    // The write itself lands in the one socket base every family embeds; only
    // the effects a live internet transport must be told about are here.
    if !sock.opts.base.apply(action) {
        let Action::BindToIfindex(index) = action else { return 0; };
        return bind_to_ifindex(sock, index);
    }
    match action {
        Action::Keepalive(_) => {
            if let net::sock::SockKind::TcpConn(entry) = &*sock.kind.lock() {
                net::sock_opts::apply_tcp_keepalive_opts(sock, entry);
            }
        }
        Action::RcvBuf(v) => super::main::sync_rcvbuf(sock, v),
        _ => {}
    }
    0
}

/// Publish a caller-named interface index on the socket. # C: O(log N)
pub(super) fn bind_to_ifindex(sock: &Arc<InetSocket>, index: i32) -> i64 {
    let iface = if index == 0 {
        None
    } else {
        let id = net::NetIfaceId::from_raw(index as u32);
        if net::sock::stack().ifaces.lookup_in_ns(id, sock.net_ns()).is_none() {
            return errno(Errno::Enodev);
        }
        Some(id)
    };
    match sock.set_bound_iface(iface) {
        Ok(()) => 0,
        Err(e) => crate::net_errno::errno_from_neterr(e),
    }
}
