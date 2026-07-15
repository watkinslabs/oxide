// AF_PACKET receive-side ABI copyout.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

/// Copy a Linux `sockaddr_ll` using value-result `addrlen` semantics. # C: O(1)
pub fn copy_sockaddr_ll_to_user(src_p: u64, src_len: u64, meta: net::sock::PacketAddr) -> i64 {
    let mut address = [0u8; 20];
    address[0..2].copy_from_slice(&17u16.to_ne_bytes());
    address[2..4].copy_from_slice(&meta.protocol.to_be_bytes());
    address[4..8].copy_from_slice(&(meta.ifindex as i32).to_ne_bytes());
    address[8..10].copy_from_slice(&meta.hatype.to_ne_bytes());
    address[10] = meta.pkttype; address[11] = meta.halen;
    address[12..20].copy_from_slice(&meta.addr);
    let mut raw_len = [0u8; 4];
    if uaccess::copy_from_user(&mut raw_len, src_len).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let user_len = i32::from_ne_bytes(raw_len);
    if user_len < 0 { return -(Errno::Einval.as_i32() as i64); }
    if uaccess::copy_to_user(src_len, &(address.len() as u32).to_ne_bytes()).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let take = core::cmp::min(user_len as usize, address.len());
    if uaccess::copy_to_user(src_p, &address[..take]).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}
