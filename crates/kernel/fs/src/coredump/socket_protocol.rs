// Pure request/ack validation for coredump sockets.

use super::socket_uapi::{self, Mark};

/// Owner selected by a valid acknowledgement.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Owner {
    Kernel,
    Userspace,
    Reject,
}

/// Validated collector decision.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Choice {
    pub owner: Owner,
    pub wait: bool,
}

/// Whether a direct socket waits for its collector after delivery. # C: O(1)
pub fn direct_wait(core_pipe_limit: i64) -> bool { core_pipe_limit != 0 }

/// Result of checking the advertised acknowledgement size. # C: O(1)
pub fn size_mark(size: u32) -> Option<Mark> {
    if size < socket_uapi::WIRE_SIZE_V0_U32 { Some(Mark::MinSize) }
    else if size > socket_uapi::WIRE_SIZE_V0_U32 { Some(Mark::MaxSize) }
    else { None }
}

/// Validate a complete version-zero acknowledgement. # C: O(1)
pub fn validate_ack(bytes: &[u8; socket_uapi::WIRE_SIZE_V0]) -> Result<Choice, Option<Mark>> {
    let size = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
    if size != socket_uapi::WIRE_SIZE_V0_U32 { return Err(None); }
    let spare = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
    let mask = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
    if mask & !socket_uapi::MODE_SUPPORTED != 0 { return Err(Some(Mark::Unsupported)); }
    let primary = mask & socket_uapi::MODE_PRIMARY;
    if primary.count_ones() != 1 { return Err(Some(Mark::Conflicting)); }
    if spare != 0 { return Err(Some(Mark::Unsupported)); }
    let owner = if primary == socket_uapi::MODE_KERNEL { Owner::Kernel }
        else if primary == socket_uapi::MODE_USERSPACE { Owner::Userspace }
        else { Owner::Reject };
    Ok(Choice { owner, wait: mask & socket_uapi::MODE_WAIT != 0 })
}

/// Run the version-zero request/ack exchange over exact-read and write-all
/// operations. Validation failures send their required marker when one exists.
/// # C: O(1) plus transport waits
pub fn negotiate<R, W>(mut read_exact: R, mut write_all: W) -> Option<Choice>
where R: FnMut(&mut [u8]) -> bool, W: FnMut(&[u8]) -> bool {
    if !write_all(&socket_uapi::request_bytes()) { return None }
    let mut ack = [0u8; socket_uapi::WIRE_SIZE_V0];
    let size_bytes = core::mem::size_of::<u32>();
    if !read_exact(&mut ack[..size_bytes]) { return None }
    let size = u32::from_ne_bytes(ack[..size_bytes].try_into().ok()?);
    if let Some(mark) = size_mark(size) {
        let _ = write_all(&socket_uapi::mark_bytes(mark));
        return None;
    }
    if !read_exact(&mut ack[size_bytes..]) { return None }
    match validate_ack(&ack) {
        Ok(choice) => if write_all(&socket_uapi::mark_bytes(Mark::RequestAck)) {
            Some(choice)
        } else { None },
        Err(Some(mark)) => { let _ = write_all(&socket_uapi::mark_bytes(mark)); None }
        Err(None) => None,
    }
}
