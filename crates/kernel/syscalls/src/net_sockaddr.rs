// P5-01: sockaddr parse/format helpers — extracted from net.rs to
// stay under the 1000-line cap (docs/08§7). All helpers are
// pub(crate); net.rs and net_recv.rs consume them.

use crate::userbuf::validate_user_buf_readable;
use syscall::errno::Errno;

// The pure encoders + their ABI constants live in `sockaddr_encode`, which is
// not kernel-cfg-gated so hosted `cargo test` can prove every `*_getname`
// length and byte layout. This module owns only the user-memory marshalling.
pub(crate) use crate::sockaddr_encode::{encoded_sockaddr_for_socket, encoded_sockaddr_in,
    encoded_sockaddr_in6, encoded_sockaddr_ll, encoded_sockaddr_nl, encoded_sockaddr_un,
    encoded_sockaddr_vm, EncodedSockaddr};
use crate::sockaddr_encode::{SOCKADDR_IN_LEN, SOCKADDR_VM_LEN};

/// Linux `SIN6_LEN_RFC2133` — the minimum `sockaddr_in6` length `inet6_bind`
/// and `inet6_dgram_connect` accept (the trailing `sin6_scope_id` is optional).
const SIN6_MIN_LEN:       usize = 24;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux `move_addr_to_kernel`: validate signed socklen, storage bound, and
/// readable user range before any family-specific parse. # C: O(N pages)
pub(crate) fn move_sockaddr_to_kernel_shape(ptr: u64, addrlen: u64) -> Result<usize, i64> {
    let len = addrlen as i32;
    if len < 0 { return Err(err(Errno::Einval)); }
    let len = len as usize;
    if len > 128 { return Err(err(Errno::Einval)); }
    if len != 0 { validate_user_buf_readable(ptr, len as u64, 1)?; }
    Ok(len)
}

/// Validate a copied sockaddr has the complete protocol struct. # C: O(1)
pub(crate) fn require_sockaddr_in(addrlen: usize) -> Result<(), i64> {
    if addrlen < SOCKADDR_IN_LEN { Err(err(Errno::Einval)) } else { Ok(()) }
}

/// Validate a copied sockaddr has the complete protocol struct. # C: O(1)
pub(crate) fn require_sockaddr_in6(addrlen: usize) -> Result<(), i64> {
    if addrlen < SIN6_MIN_LEN { Err(err(Errno::Einval)) } else { Ok(()) }
}

/// Validate a copied sockaddr has the complete protocol struct. # C: O(1)
pub(crate) fn require_sockaddr_vm(addrlen: usize) -> Result<(), i64> {
    if addrlen < SOCKADDR_VM_LEN { Err(err(Errno::Einval)) } else { Ok(()) }
}


/// Copy an encoded kernel sockaddr to `addr` using Linux value-result
/// `addrlen`: read caller length, copy min(caller, kernel), then write the
/// full kernel length back to `addrlen`. # C: O(sockaddr len)
pub(crate) fn copy_sockaddr_to_user(addr: u64, addrlen: u64, sa: &EncodedSockaddr) -> i64 {
    crate::name_copyout::copy_sockaddr_value_result(|| {
            let mut raw_len = [0u8; 4];
            uaccess::copy_from_user(&mut raw_len, addrlen)?;
            Ok(i32::from_ne_bytes(raw_len))
        },
        sa.len() as u32,
        |full_len| uaccess::copy_to_user(addrlen, &full_len.to_ne_bytes()),
        |copy_len| uaccess::copy_to_user(addr, &sa.as_bytes()[..copy_len]))
    .map_or_else(err, |_| 0)
}


/// Encode sockaddr for a socket's current family without touching user memory.
/// # C: O(1)
/// `::ffff:a.b.c.d` for an IPv4 address, `::` for the unspecified one —
/// Linux `ipv6_addr_set_v4mapped`. # C: O(1)


/// Encode AF_UNIX sockaddr for a peer/local path without touching user memory.
/// # C: O(path len)
pub(crate) fn encoded_sockaddr_un_path(path: Option<&[u8]>) -> EncodedSockaddr {
    encoded_sockaddr_un(path)
}

/// Encode `struct sockaddr_vm` without touching user memory. # C: O(1)

/// Encode a genuine IPv6 peer address. # C: O(1)
pub(crate) fn encoded_sockaddr_in6_peer(ip: net::Ipv6Addr, port: u16) -> EncodedSockaddr {
    encoded_sockaddr_in6(ip.0, port.to_be(), 0)
}
