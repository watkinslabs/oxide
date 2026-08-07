// RTM_NEWNSID / RTM_GETNSID request grammar.

use syscall::errno::Errno;

/// `struct rtgenmsg` is the one-byte family selector before attributes.
const RTGENMSG_LEN: usize = 1;
/// `NETNSA_*` attribute numbers.
pub const NETNSA_NSID: u16 = 1;
pub const NETNSA_PID: u16 = 2;
pub const NETNSA_FD: u16 = 3;
pub const NETNSA_TARGET_NSID: u16 = 4;
pub const NETNSA_CURRENT_NSID: u16 = 5;

/// Decoded `RTM_NEWNSID`: an explicit caller-local ID and a peer nsfs fd.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct New { pub nsid: i32, pub fd: i32 }
/// Decoded `RTM_GETNSID`: a peer nsfs fd.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Get { pub fd: i32 }

fn attrs(body: &[u8]) -> Result<alloc::vec::Vec<(u16, &[u8])>, Errno> {
    if body.len() < RTGENMSG_LEN || body[0] != 0 { return Err(Errno::Einval); }
    let mut off = RTGENMSG_LEN;
    let mut out = alloc::vec::Vec::new();
    while off < body.len() {
        if body.len() - off < 4 { return Err(Errno::Einval); }
        let len = u16::from_ne_bytes([body[off], body[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([body[off + 2], body[off + 3]]) & 0x3fff;
        if len < 4 || len > body.len() - off { return Err(Errno::Einval); }
        let next = (len + 3) & !3;
        if next > body.len() - off { return Err(Errno::Einval); }
        out.push((ty, &body[off + 4..off + len]));
        off += next;
    }
    Ok(out)
}

fn i32_attr(value: &[u8]) -> Result<i32, Errno> {
    value.try_into().map(i32::from_ne_bytes).map_err(|_| Errno::Einval)
}

/// Parse `RTM_NEWNSID`; PID references remain unsupported until a task-pid
/// namespace resolver exists, so they are refused rather than misresolved.
/// # C: O(N attrs)
pub fn new(body: &[u8]) -> Result<New, Errno> {
    let mut nsid = None;
    let mut fd = None;
    for (ty, value) in attrs(body)? {
        match ty {
            NETNSA_NSID if nsid.is_none() => nsid = Some(i32_attr(value)?),
            NETNSA_FD if fd.is_none() => fd = Some(i32_attr(value)?),
            NETNSA_NSID | NETNSA_FD | NETNSA_PID | NETNSA_TARGET_NSID | NETNSA_CURRENT_NSID =>
                return Err(Errno::Einval),
            _ => return Err(Errno::Einval),
        }
    }
    Ok(New { nsid: nsid.ok_or(Errno::Einval)?, fd: fd.ok_or(Errno::Einval)? })
}

/// Parse `RTM_GETNSID`'s peer nsfs-fd form. # C: O(N attrs)
pub fn get(body: &[u8]) -> Result<Get, Errno> {
    let mut fd = None;
    for (ty, value) in attrs(body)? {
        match ty {
            NETNSA_FD if fd.is_none() => fd = Some(i32_attr(value)?),
            NETNSA_FD | NETNSA_PID | NETNSA_NSID | NETNSA_TARGET_NSID | NETNSA_CURRENT_NSID =>
                return Err(Errno::Einval),
            _ => return Err(Errno::Einval),
        }
    }
    Ok(Get { fd: fd.ok_or(Errno::Einval)? })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(attrs: &[(u16, i32)]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec![0];
        for (ty, value) in attrs {
            out.extend_from_slice(&8u16.to_ne_bytes()); out.extend_from_slice(&ty.to_ne_bytes());
            out.extend_from_slice(&value.to_ne_bytes());
        }
        out
    }

    #[test]
    fn new_requires_one_nsid_and_one_fd() {
        assert_eq!(new(&request(&[(NETNSA_NSID, 7), (NETNSA_FD, 3)])), Ok(New { nsid: 7, fd: 3 }));
        assert_eq!(new(&request(&[(NETNSA_FD, 3)])), Err(Errno::Einval));
        assert_eq!(new(&request(&[(NETNSA_NSID, 7)])), Err(Errno::Einval));
    }

    #[test]
    fn get_refuses_duplicates_and_non_fd_peer_references() {
        assert_eq!(get(&request(&[(NETNSA_FD, 3)])), Ok(Get { fd: 3 }));
        assert_eq!(get(&request(&[(NETNSA_FD, 3), (NETNSA_FD, 4)])), Err(Errno::Einval));
        assert_eq!(get(&request(&[(NETNSA_PID, 44)])), Err(Errno::Einval));
    }
}
