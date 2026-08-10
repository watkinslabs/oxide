// Sending one message gathered from several pieces.
//
// Three entries describe a send whose payload is not one contiguous range of
// the caller's memory, and all three end here so the socket layer sees ONE
// message rather than one message per piece — a datagram split across
// several calls is several datagrams, which is not what any of them asked
// for:
//
//   * a bundle, whose pieces are a run of the caller's provided buffers;
//   * a vectorized send, whose pieces are the segment vector at `addr`;
//   * a registered-buffer send, whose single piece is a window inside frames
//     this ring pinned — reached through the kernel's own mapping of them, so
//     the bytes leave the memory the caller registered whatever it has since
//     done to its page tables.
//
// The gather itself is one pass over the pieces into one payload, in order.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::io_uring::pin::PinnedRange;
use crate::io_uring_abi::bundle::Seg;
use crate::io_uring_abi::recvsend::fixed::Window;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sizeof(struct sockaddr_storage)` — an oversized address length is clamped
/// to it rather than refused, and the family's own parser reads no further.
const SOCKADDR_STORAGE_LEN: usize = 128;

/// `sizeof(struct iovec)` and the offset of its length word, native width.
const IOVEC_BYTES: usize = 16;
const IOVEC_LEN_AT: usize = 8;

/// Most segments one send may name, matching the vectored-I/O bound.
const UIO_MAXIOV: usize = 1024;

/// Where a gathered send reads its payload from.
pub enum Source<'a> {
    /// Ranges of the caller's address space.
    User(&'a [Seg]),
    /// A window inside a buffer this ring pinned.
    Pinned(&'a PinnedRange, Window),
}

/// The destination address an entry may name beside its payload.
#[derive(Clone, Copy)]
pub struct Dest {
    pub name: u64,
    pub namelen: u64,
}

impl Source<'_> {
    /// Total payload length. # C: O(segments)
    fn total(&self) -> usize {
        match self {
            Source::User(segs) => {
                let mut n = 0usize;
                for s in *segs { n = core::cmp::min(uaccess::MAX_RW_COUNT, n.saturating_add(s.len as usize)); }
                n
            }
            Source::Pinned(_, w) => core::cmp::min(uaccess::MAX_RW_COUNT, w.len as usize),
        }
    }
}

/// Import a segment vector of `nr` entries at `addr`.
///
/// The vector is read once, before any byte moves, so a send either names a
/// well-formed set of pieces or moves nothing at all. # C: O(nr + faults)
pub fn import_vec(addr: u64, nr: u32) -> Result<Vec<Seg>, i64> {
    let nr = nr as usize;
    if nr > UIO_MAXIOV { return Err(err(Errno::Einval)); }
    let bytes = nr.checked_mul(IOVEC_BYTES).ok_or_else(|| err(Errno::Einval))?;
    let mut raw = Vec::new();
    if raw.try_reserve_exact(bytes).is_err() { return Err(err(Errno::Enomem)); }
    raw.resize(bytes, 0);
    if bytes != 0 { uaccess::copy_from_user(&mut raw, addr).map_err(|e| err(e))?; }
    let mut out = Vec::new();
    if out.try_reserve_exact(nr).is_err() { return Err(err(Errno::Enomem)); }
    for e in raw.chunks_exact(IOVEC_BYTES) {
        let base = u64::from_ne_bytes(e[..8].try_into().expect("an eight-byte word"));
        let raw_len = u64::from_ne_bytes(e[IOVEC_LEN_AT..].try_into().expect("an eight-byte word"));
        let len = core::cmp::min(raw_len, uaccess::MAX_RW_COUNT as u64) as u32;
        if len != 0 && !uaccess::access_ok(base, len as usize) { return Err(err(Errno::Efault)); }
        out.push(Seg { addr: base, len });
    }
    Ok(out)
}

/// Send one message gathered from `src`. # C: O(bytes)
pub fn send_message(fd: i32, src: Source, dest: Dest, msg_flags: u32) -> i64 {
    let Some(cur) = sched::live::current() else { return err(Errno::Ebadf) };
    let ctx = socket::SendContext::new(cur);
    let total = src.total();
    let mut io = GatherSend { task: cur, fd, src, total, dest };
    match socket::send_io(&ctx, msg_flags, &mut io) {
        Ok(o) => o.bytes as i64,
        Err(e) => -(e.errno() as i64),
    }
}

/// The pieces, presented to the socket layer as one message. Payload bytes are
/// gathered exactly once, in order.
struct GatherSend<'a> {
    task: &'a sched::Task,
    fd: i32,
    src: Source<'a>,
    total: usize,
    dest: Dest,
}

impl GatherSend<'_> {
    /// # C: O(address bytes)
    fn name(&self) -> Result<Option<Vec<u8>>, socket::Error> {
        if self.dest.name == 0 { return Ok(None); }
        if (self.dest.namelen as i32) < 0 { return Err(socket::Error::Einval); }
        let len = core::cmp::min(self.dest.namelen as usize, SOCKADDR_STORAGE_LEN);
        if len == 0 { return Ok(None); }
        let mut v = Vec::new();
        v.try_reserve_exact(len).map_err(|_| socket::Error::Enomem)?;
        v.resize(len, 0);
        uaccess::copy_from_user(&mut v, self.dest.name).map_err(|_| socket::Error::Efault)?;
        Ok(Some(v))
    }

    /// Gather the payload, and say whether a piece of it could not be read.
    ///
    /// A fault after some bytes have been gathered is a SHORT message rather
    /// than a failure: those bytes are real and the socket layer decides what
    /// a short send reports. A fault with nothing gathered is `EFAULT`.
    /// # C: O(bytes)
    fn gather(&self) -> Result<(Vec<u8>, bool), socket::Error> {
        let mut out = Vec::new();
        out.try_reserve_exact(self.total).map_err(|_| socket::Error::Enomem)?;
        out.resize(self.total, 0);
        let done = match &self.src {
            Source::User(segs) => self.gather_user(segs, &mut out),
            // The window names frames this ring holds a reference on for the
            // whole transfer, so the read cannot fault: it moves the window
            // whole, or the window was never inside the registration.
            Source::Pinned(buf, w) => {
                buf.read_at(w.off, &mut out).map_err(|_| socket::Error::Efault)?;
                self.total
            }
        };
        if done < self.total {
            out.truncate(done);
            if done == 0 { return Err(socket::Error::Efault); }
            return Ok((out, true));
        }
        Ok((out, false))
    }

    /// # C: O(bytes)
    fn gather_user(&self, segs: &[Seg], out: &mut [u8]) -> usize {
        let mut done = 0usize;
        for s in segs {
            let take = core::cmp::min(s.len as usize, self.total - done);
            if take == 0 { continue; }
            // SAFETY: done + take never exceeds self.total, the initialised length of out.
            let left = unsafe { uaccess::raw_copy_from_user(out[done..].as_mut_ptr(), s.addr, take) };
            done += take - left;
            if left != 0 { break; }
        }
        done
    }
}

impl socket::MessageIo for GatherSend<'_> {
    fn file(&mut self) -> socket::KResult<Arc<vfs::File>> {
        // SAFETY: running task on this CPU; preempt-off; fd-table view is stable for lookup.
        let table = unsafe { self.task.fd_table_ref() }.ok_or(socket::Error::Ebadf)?;
        table.get(self.fd).map_err(|_| socket::Error::Ebadf)
    }

    fn import_envelope(&mut self) -> socket::KResult<Option<socket::Message>> {
        Ok(Some(socket::Message { requested_len: self.total, name: self.name()?,
                                  ..socket::Message::default() }))
    }

    fn import_payload(&mut self, message: &mut socket::Message) -> socket::KResult<()> {
        let (payload, faulted) = self.gather()?;
        message.payload = payload;
        message.payload_faulted = faulted;
        Ok(())
    }

    fn import(&mut self, mode: socket::ImportMode) -> socket::KResult<socket::Message> {
        let name = self.name()?;
        if mode == socket::ImportMode::RawOobEnvelope {
            return Ok(socket::Message { requested_len: self.total, name,
                                        ..socket::Message::default() });
        }
        let (payload, payload_faulted) = self.gather()?;
        Ok(socket::Message { payload, payload_faulted, requested_len: self.total, name,
                             ..socket::Message::default() })
    }
}
