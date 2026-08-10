// Where a buffer-selecting receive puts the bytes.
//
// An entry that carries `IOSQE_BUFFER_SELECT` does not name its own
// destination: the ring draws one from the caller's group and the transfer
// must land THERE. For a plain `RECV` that is the whole story — the drawn
// buffer is the payload destination and there is nothing else in the entry.
//
// A `RECVMSG` still has a message header, and the two halves come from
// different places: the ADDRESS and ANCILLARY capacities are the caller's,
// read out of the `msghdr` the entry points at, while the PAYLOAD lands in
// the drawn buffer. Under multishot there is no header to write back into
// either — a submission posting completions long after the caller moved on
// cannot publish into a header it may have reused — so the drawn buffer
// carries its own frame instead:
//
//   | 16 bytes | namelen  | controllen | the rest |
//   | header   | address  | ancillary  | payload  |
//
// The header is `struct io_uring_recvmsg_out`: the address length BEFORE
// truncation, the ancillary length actually used, the payload length, and the
// message flags. A caller walks its group's buffers and reads each frame; it
// never sees a `msghdr` written back at all.
//
// Ungated: the frame is arithmetic over lengths the entry published, and the
// file that runs the transfer is kernel-gated (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use crate::io_uring_abi::ops::IORING_OP_RECVMSG;

/// `sizeof(struct io_uring_recvmsg_out)`.
pub const RECVMSG_OUT_BYTES: u32 = 16;

/// Byte offsets inside `struct io_uring_recvmsg_out`.
pub mod out {
    /// Length of the source address BEFORE truncation.
    pub const NAMELEN: u32 = 0;
    /// Ancillary bytes this delivery actually used.
    pub const CONTROLLEN: u32 = 4;
    /// Length of the payload this delivery carried.
    pub const PAYLOADLEN: u32 = 8;
    /// The message flags the delivery settled.
    pub const FLAGS: u32 = 12;
}

/// One multishot `RECVMSG` frame, as offsets into the drawn buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Frame {
    /// Bytes the frame spends before the payload: header, address, ancillary.
    pub hdr_len: u32,
    /// Where the source address is written, and how much room it has.
    pub name_off: u32,
    pub namelen: u32,
    /// Where the ancillary stream is written, and how much room it has.
    pub control_off: u32,
    pub controllen: u32,
    /// Where the payload starts, and how much of the buffer is left for it.
    pub payload_off: u32,
    pub payload_len: u32,
}

/// Lay a multishot `RECVMSG` frame out inside a drawn buffer of `buf_len`
/// bytes, given the address and ancillary capacities the caller published in
/// its `msghdr`.
///
/// A buffer too small to hold the frame's fixed part is `EFAULT` — there is
/// nowhere to write the header that tells the caller what happened, so
/// delivering into it would hand back bytes with no way to read them.
/// # C: O(1)
pub fn frame(buf_len: u32, namelen: u32, controllen: u32) -> Result<Frame, Errno> {
    let hdr_len = RECVMSG_OUT_BYTES.checked_add(namelen).ok_or(Errno::Eoverflow)?
        .checked_add(controllen).ok_or(Errno::Eoverflow)?;
    if buf_len < hdr_len { return Err(Errno::Efault); }
    Ok(Frame {
        hdr_len,
        name_off: RECVMSG_OUT_BYTES,
        namelen,
        control_off: hdr_len - controllen,
        controllen,
        payload_off: hdr_len,
        payload_len: buf_len - hdr_len,
    })
}

impl Frame {
    /// What one delivery of `payload` bytes into this frame reports.
    ///
    /// The frame's fixed part is spent whether or not the delivery filled it,
    /// so the result counts the whole frame plus the payload — that is the
    /// number a caller adds to a buffer's base to find the next frame.
    /// # C: O(1)
    pub fn result(&self, payload: u64) -> i64 {
        let carried = core::cmp::min(payload, self.payload_len as u64);
        self.hdr_len as i64 + carried as i64
    }
}

/// `struct io_uring_recvmsg_out`'s payload-length word, which reports the
/// delivery's TRUE length even when the frame could only carry part of it —
/// the same truncation report a message-carrying receive makes with its own
/// header. # C: O(1)
pub fn payloadlen(payload: u64) -> u32 { core::cmp::min(payload, u32::MAX as u64) as u32 }

/// The payload cap a message-carrying receive takes from its header when the
/// destination is a drawn buffer.
///
/// The header's segment vector no longer says WHERE the payload goes — the
/// group said that — but its single segment still says how much of the drawn
/// buffer this delivery may use, and zero means all of it. More than one
/// segment is malformed rather than merely surplus: a run of segments
/// describes a scatter the drawn buffer is not, and silently reading the first
/// would deliver a different amount than the caller wrote down. # C: O(1)
pub fn cap_from_iovlen(iovlen: usize, first_len: Option<u64>) -> Result<u64, Errno> {
    match iovlen {
        0 => Ok(0),
        1 => Ok(first_len.unwrap_or(0)),
        _ => Err(Errno::Einval),
    }
}

/// Whether the ENTRY's own length caps the buffer the group hands out.
///
/// It does for every opcode but the message-carrying receive, which takes that
/// cap from its header instead — so the entry's length field is not a second,
/// quieter answer to the same question. # C: O(1)
pub fn entry_caps_drawn_buffer(op: u8) -> bool { op != IORING_OP_RECVMSG }

/// Where one buffer-selecting receive delivers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Selected {
    /// The payload destination: address and room.
    pub payload: (u64, u32),
    /// The frame this delivery carries its own header in, when it has no
    /// `msghdr` to write one back into.
    pub frame: Option<Frame>,
}

/// Place one buffer-selecting receive's payload.
///
/// The answer is the DRAWN buffer in every case. The entry's own address is
/// not a candidate: on a plain `RECV` it is the buffer the group replaced, and
/// on a `RECVMSG` it is the message header — delivering there would write the
/// payload over the header while the ring reported, in the completion, that
/// the bytes had gone into a buffer it had just retired from the group. The
/// caller would read that buffer and find whatever was in it before.
/// # C: O(1)
pub fn selected(multishot: bool, buf_addr: u64, buf_len: u32, cap: u64, namelen: u32,
    controllen: u32) -> Result<Selected, Errno>
{
    let buf_len = if cap == 0 || cap >= buf_len as u64 { buf_len } else { cap as u32 };
    if !multishot { return Ok(Selected { payload: (buf_addr, buf_len), frame: None }); }
    let f = frame(buf_len, namelen, controllen)?;
    Ok(Selected {
        payload: (buf_addr + f.payload_off as u64, f.payload_len),
        frame: Some(f),
    })
}

#[cfg(test)]
#[path = "dest_tests.rs"]
mod tests;
