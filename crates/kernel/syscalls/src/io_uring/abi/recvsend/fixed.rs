// `IORING_RECVSEND_FIXED_BUF` — a send or receive that moves its bytes
// through a REGISTERED buffer instead of through an address.
//
// The entry names the buffer by index in `buf_index` and names a window
// inside it with `addr`/`len`. What makes this different from an ordinary
// transfer is not speed: the frames were pinned when the buffer was
// registered, so the transfer reaches the same physical memory whatever the
// process did to its mappings since. A registration that has been dropped
// takes its pin with it, so no transfer can outlive one.
//
// Ungated: the window arithmetic and every refusal are decisions, and the
// files that move the bytes are kernel-gated (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use crate::io_uring_abi::bundle::IORING_RECVSEND_BUNDLE;
use crate::io_uring_abi::ops::{IORING_OP_RECV, IORING_OP_SEND, IOSQE_BUFFER_SELECT};

use super::{FIXED_BUF, MULTISHOT, SEND_VECTORIZED};

/// The refusals a fixed-buffer entry earns before any byte moves.
///
/// One pinned window is one answer to "where do the bytes go", and each of
/// these pairings supplies a second: a message-carrying opcode describes its
/// own scatter list, a provided-buffer group hands out an address of its own,
/// a bundle spans a RUN of such addresses, multishot needs a fresh buffer per
/// delivery, and the vectorized send reads `addr` as a segment vector rather
/// than as the window. # C: O(1)
pub fn admit(op: u8, sqe_flags: u8, ioprio: u16) -> Result<(), Errno> {
    if ioprio & FIXED_BUF == 0 { return Ok(()); }
    if !matches!(op, IORING_OP_SEND | IORING_OP_RECV) { return Err(Errno::Einval); }
    if sqe_flags & IOSQE_BUFFER_SELECT != 0 { return Err(Errno::Einval); }
    let refused = IORING_RECVSEND_BUNDLE
        | if op == IORING_OP_SEND { SEND_VECTORIZED } else { MULTISHOT };
    if ioprio & refused != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// The part of a registered buffer one transfer occupies: how far into the
/// registration it starts, and how many bytes it moves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Window {
    pub off: u64,
    pub len: u64,
}

/// Place `addr`/`len` inside the registration `[base, base+buf_len)`.
///
/// The entry addresses the window the same way it would address ordinary
/// memory — by the address the buffer was registered at — so a caller that
/// keeps its own pointers needs no second coordinate system. An address
/// outside the registration, or a length running past its end, is `EFAULT`:
/// the transfer would have to touch memory this ring never pinned. An empty
/// registration is `EFAULT` for the same reason — the slot names no frames.
/// # C: O(1)
pub fn window(base: u64, buf_len: u64, addr: u64, len: u32) -> Result<Window, Errno> {
    if buf_len == 0 { return Err(Errno::Efault); }
    let off = addr.checked_sub(base).ok_or(Errno::Efault)?;
    let end = off.checked_add(len as u64).ok_or(Errno::Efault)?;
    if end > buf_len { return Err(Errno::Efault); }
    Ok(Window { off, len: len as u64 })
}

#[cfg(test)]
#[path = "fixed_tests.rs"]
mod tests;
