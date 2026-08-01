// SOL_SOCKET reads whose value is not one fixed-width scalar. The length
// ladders live in `net::sock_opts::sol_socket::varlen` (`docs/53§4`); this file
// resolves the live value and moves bytes.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use net::sock::InetSocket;
use net::sock_opts::sol_socket::varlen;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Import the caller's `optlen`. # C: O(1)
pub(super) fn requested(optlen_p: u64) -> Result<i32, Errno> {
    let mut raw = [0u8; core::mem::size_of::<i32>()];
    uaccess::copy_from_user(&mut raw, optlen_p).map_err(|_| Errno::Efault)?;
    let value = i32::from_ne_bytes(raw);
    if value < 0 { return Err(Errno::Einval); }
    Ok(value)
}

fn publish_len(optlen_p: u64, len: usize) -> Result<(), Errno> {
    uaccess::copy_to_user(optlen_p, &(len as u32).to_ne_bytes()).map_err(|_| Errno::Efault)
}

/// Value then length, the order every SOL_SOCKET read publishes in. # C: O(len)
fn publish(optval: u64, optlen_p: u64, bytes: &[u8]) -> i64 {
    if !bytes.is_empty() && uaccess::copy_to_user(optval, bytes).is_err() {
        return errno(Errno::Efault);
    }
    match publish_len(optlen_p, bytes.len()) { Ok(()) => 0, Err(e) => errno(e) }
}

/// `SO_MEMINFO`: nine `u32` slots, truncated to the caller's buffer. # C: O(queued frames)
pub(super) fn meminfo(sock: &Arc<InetSocket>, optval: u64, optlen_p: u64) -> i64 {
    let requested = match requested(optlen_p) { Ok(v) => v, Err(e) => return errno(e) };
    let bytes = net::sock_opts::meminfo(sock).bytes();
    publish(optval, optlen_p, &bytes[..varlen::meminfo_len(requested)])
}

/// `SO_PEERGROUPS`: the peer's supplementary group list, or the length it
/// needs. # C: O(groups)
pub(super) fn peergroups(groups: Option<Vec<u32>>, optval: u64, optlen_p: u64) -> i64 {
    let requested = match requested(optlen_p) { Ok(v) => v, Err(e) => return errno(e) };
    let count = groups.as_ref().map(Vec::len);
    match varlen::peergroups_len(count, requested) {
        Err((0, error)) => errno(error),
        Err((needed, error)) => match publish_len(optlen_p, needed) {
            Ok(()) => errno(error), Err(e) => errno(e),
        },
        Ok(_) => {
            let mut bytes = Vec::with_capacity(count.unwrap_or(0) * core::mem::size_of::<u32>());
            for gid in groups.unwrap_or_default() { bytes.extend_from_slice(&gid.to_ne_bytes()); }
            publish(optval, optlen_p, &bytes)
        }
    }
}

/// `SO_PEERNAME`: the peer address `getpeername(2)` reports, refused rather
/// than padded when the caller asks for more than it occupies. # C: O(1)
pub(super) fn peername(sock: &Arc<InetSocket>, optval: u64, optlen_p: u64) -> i64 {
    let requested = match requested(optlen_p) { Ok(v) => v, Err(e) => return errno(e) };
    let address = crate::s052_getpeername::peer_sockaddr(sock).ok();
    let len = match varlen::peername_len(address.as_ref().map(|sa| sa.len()), requested) {
        Ok(len) => len, Err(e) => return errno(e),
    };
    // The requested length can exceed nothing here: it is bounded by the
    // address the socket actually has.
    let address = address.expect("peername_len rejected the absent peer");
    publish(optval, optlen_p, &address.bytes[..len])
}

/// `SO_PEERSEC`: the peer's security label, published by whichever module
/// labels sockets. With none installed the option carries no value. # C: O(label)
pub(super) fn peersec(sock: &Arc<InetSocket>, optval: u64, optlen_p: u64) -> i64 {
    use core::sync::atomic::Ordering;
    let requested = match requested(optlen_p) { Ok(v) => v, Err(e) => return errno(e) };
    let connected = crate::s052_getpeername::peer_sockaddr(sock).is_ok();
    let context = security::network::PeerContext {
        namespace: sock.net_ns(),
        family: sock.family.load(Ordering::Acquire),
        connected,
    };
    let Some(label) = security::network::peer_security(context) else {
        return errno(Errno::Enoprotoopt);
    };
    // A buffer too small still learns the label's length.
    if (requested as usize) < label.len() {
        return match publish_len(optlen_p, label.len()) {
            Ok(()) => errno(Errno::Erange), Err(e) => errno(e),
        };
    }
    publish(optval, optlen_p, &label)
}

/// `SO_GET_FILTER`: dump the retained classic blocks of the attached program.
/// The published length counts BLOCKS, not bytes. # C: O(program bytes)
pub(super) fn get_filter(target: &socket::FilterFile, optval: u64, optlen_p: u64) -> i64 {
    let requested = match requested(optlen_p) { Ok(v) => v, Err(e) => return errno(e) };
    let insns = target.classic_insns();
    let read = match varlen::get_filter(insns.as_ref().map(Vec::len), target.is_attached(),
        requested)
    {
        Ok(read) => read, Err(e) => return errno(e),
    };
    if read.copy_bytes != 0 {
        let insns = insns.expect("a byte count implies retained classic blocks");
        if uaccess::copy_to_user(optval, &insns[..read.copy_bytes]).is_err() {
            return errno(Errno::Efault);
        }
    }
    match publish_len(optlen_p, read.published_len) { Ok(()) => 0, Err(e) => errno(e) }
}
