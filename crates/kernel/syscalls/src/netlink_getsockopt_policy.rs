use syscall::errno::Errno;

/// Decode the caller's NETLINK `getsockopt` output capacity. # C: O(1)
pub fn requested_len(raw_len: [u8; core::mem::size_of::<i32>()]) -> Result<usize, Errno> {
    let requested = i32::from_ne_bytes(raw_len);
    if requested < 0 { return Err(Errno::Einval); }
    Ok(requested as usize)
}
