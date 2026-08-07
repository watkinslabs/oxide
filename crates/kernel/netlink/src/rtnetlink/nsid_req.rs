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

/// Peer namespace reference accepted by `RTM_NEWNSID` and `RTM_GETNSID`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PeerRef { Fd(i32), Pid(u32), Nsid(i32) }
/// Decoded `RTM_NEWNSID`: explicit caller-local ID plus its peer reference.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct New { pub nsid: i32, pub peer: PeerRef }
/// Decoded `RTM_GETNSID`, including its optional caller-local target namespace.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Get { pub peer: PeerRef, pub target_nsid: Option<i32> }
/// Decoded `RTM_GETNSID` dump selector.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Dump { pub target_nsid: Option<i32> }

/// Request-parser failure, retaining the offending attribute's wire position
/// for the `NLMSGERR_ATTR_OFFS` extended-ack contract.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ParseError { pub errno: Errno, pub offset: Option<u32> }

impl ParseError {
    const fn plain(errno: Errno) -> Self { Self { errno, offset: None } }
    const fn attr(errno: Errno, offset: usize) -> Self {
        Self { errno, offset: Some((crate::Nlmsghdr::SIZE + offset) as u32) }
    }
}

fn attrs(body: &[u8]) -> Result<alloc::vec::Vec<(u16, &[u8], usize)>, ParseError> {
    if body.len() < RTGENMSG_LEN || body[0] != 0 { return Err(ParseError::plain(Errno::Einval)); }
    let mut off = RTGENMSG_LEN;
    let mut out = alloc::vec::Vec::new();
    while off < body.len() {
        if body.len() - off < 4 { return Err(ParseError::attr(Errno::Einval, off)); }
        let len = u16::from_ne_bytes([body[off], body[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([body[off + 2], body[off + 3]]) & 0x3fff;
        if len < 4 || len > body.len() - off { return Err(ParseError::attr(Errno::Einval, off)); }
        let next = (len + 3) & !3;
        if next > body.len() - off { return Err(ParseError::attr(Errno::Einval, off)); }
        out.push((ty, &body[off + 4..off + len], off));
        off += next;
    }
    Ok(out)
}

fn i32_attr(value: &[u8], offset: usize) -> Result<i32, ParseError> {
    value.try_into().map(i32::from_ne_bytes).map_err(|_| ParseError::attr(Errno::Einval, offset))
}

/// Parse `RTM_NEWNSID`; PID references remain unsupported until a task-pid
/// namespace resolver exists, so they are refused rather than misresolved.
/// # C: O(N attrs)
pub fn new(body: &[u8]) -> Result<New, ParseError> {
    let mut nsid = None;
    let mut peer = None;
    for (ty, value, offset) in attrs(body)? {
        match ty {
            NETNSA_NSID if nsid.is_none() => nsid = Some(i32_attr(value, offset)?),
            NETNSA_FD if peer.is_none() => peer = Some(PeerRef::Fd(i32_attr(value, offset)?)),
            NETNSA_PID if peer.is_none() => peer = Some(PeerRef::Pid(i32_attr(value, offset)? as u32)),
            NETNSA_NSID | NETNSA_FD | NETNSA_PID | NETNSA_TARGET_NSID | NETNSA_CURRENT_NSID =>
                return Err(ParseError::attr(Errno::Einval, offset)),
            _ => return Err(ParseError::attr(Errno::Einval, offset)),
        }
    }
    Ok(New { nsid: nsid.ok_or(ParseError::plain(Errno::Einval))?, peer: peer.ok_or(ParseError::plain(Errno::Einval))? })
}

/// Parse `RTM_GETNSID`'s peer nsfs-fd form. # C: O(N attrs)
pub fn get(body: &[u8]) -> Result<Get, ParseError> {
    let mut peer = None;
    let mut target_nsid = None;
    for (ty, value, offset) in attrs(body)? {
        match ty {
            NETNSA_FD if peer.is_none() => peer = Some(PeerRef::Fd(i32_attr(value, offset)?)),
            NETNSA_PID if peer.is_none() => peer = Some(PeerRef::Pid(i32_attr(value, offset)? as u32)),
            NETNSA_NSID if peer.is_none() => peer = Some(PeerRef::Nsid(i32_attr(value, offset)?)),
            NETNSA_TARGET_NSID if target_nsid.is_none() => target_nsid = Some(i32_attr(value, offset)?),
            NETNSA_FD | NETNSA_PID | NETNSA_NSID | NETNSA_TARGET_NSID | NETNSA_CURRENT_NSID =>
                return Err(ParseError::attr(Errno::Einval, offset)),
            _ => return Err(ParseError::attr(Errno::Einval, offset)),
        }
    }
    Ok(Get { peer: peer.ok_or(ParseError::plain(Errno::Einval))?, target_nsid })
}

/// Parse `RTM_GETNSID|NLM_F_DUMP`; only a target namespace is meaningful.
/// # C: O(N attrs)
pub fn dump(body: &[u8]) -> Result<Dump, ParseError> {
    let mut target_nsid = None;
    for (ty, value, offset) in attrs(body)? {
        match ty {
            NETNSA_TARGET_NSID if target_nsid.is_none() => target_nsid = Some(i32_attr(value, offset)?),
            _ => return Err(ParseError::attr(Errno::Einval, offset)),
        }
    }
    Ok(Dump { target_nsid })
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
        assert_eq!(new(&request(&[(NETNSA_NSID, 7), (NETNSA_FD, 3)])), Ok(New { nsid: 7, peer: PeerRef::Fd(3) }));
        assert_eq!(new(&request(&[(NETNSA_NSID, 7), (NETNSA_PID, 3)])), Ok(New { nsid: 7, peer: PeerRef::Pid(3) }));
        assert_eq!(new(&request(&[(NETNSA_FD, 3)])).unwrap_err().errno, Errno::Einval);
        assert_eq!(new(&request(&[(NETNSA_NSID, 7)])).unwrap_err().errno, Errno::Einval);
    }

    #[test]
    fn get_refuses_duplicates_and_non_fd_peer_references() {
        assert_eq!(get(&request(&[(NETNSA_FD, 3)])), Ok(Get { peer: PeerRef::Fd(3), target_nsid: None }));
        assert_eq!(get(&request(&[(NETNSA_NSID, 6), (NETNSA_TARGET_NSID, 9)])),
            Ok(Get { peer: PeerRef::Nsid(6), target_nsid: Some(9) }));
        assert_eq!(get(&request(&[(NETNSA_FD, 3), (NETNSA_FD, 4)])).unwrap_err().offset, Some(25));
        assert_eq!(get(&request(&[(NETNSA_FD, 3), (NETNSA_PID, 44)])).unwrap_err().offset, Some(25));
    }

    #[test]
    fn dump_accepts_only_one_target_namespace() {
        assert_eq!(dump(&request(&[])), Ok(Dump { target_nsid: None }));
        assert_eq!(dump(&request(&[(NETNSA_TARGET_NSID, 9)])), Ok(Dump { target_nsid: Some(9) }));
        assert_eq!(dump(&request(&[(NETNSA_NSID, 9)])).unwrap_err().offset, Some(17));
    }
}
