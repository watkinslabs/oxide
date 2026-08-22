//! Per-program diagnostic streams.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use syscall::errno::Errno;
use sync::{Spinlock, TaskList as TaskListClass};

pub(crate) const STDOUT: u32 = 1;
pub(crate) const STDERR: u32 = 2;
const MAX_CAPACITY: usize = 100_000;

struct Element {
    bytes: Vec<u8>,
    consumed: usize,
}

#[derive(Default)]
struct Stream {
    queued: usize,
    fifo: VecDeque<Element>,
}

pub struct ProgStreams {
    stdout: Spinlock<Stream, TaskListClass>,
    stderr: Spinlock<Stream, TaskListClass>,
}

impl ProgStreams {
    /// Create the two empty streams attached to a new program. # C: O(1)
    pub const fn new() -> Self {
        Self {
            stdout: Spinlock::new(Stream { queued: 0, fifo: VecDeque::new() }),
            stderr: Spinlock::new(Stream { queued: 0, fifo: VecDeque::new() }),
        }
    }

    fn get(&self, id: u32) -> Result<&Spinlock<Stream, TaskListClass>, Errno> {
        match id { STDOUT => Ok(&self.stdout), STDERR => Ok(&self.stderr), _ => Err(Errno::Enoent) }
    }

    /// Append one runtime diagnostic as one FIFO element. Capacity includes
    /// partially consumed elements and, like the ABI owner, never reaches the
    /// 100,000-byte ceiling. # C: O(bytes)
    pub fn push(&self, id: u32, bytes: &[u8]) -> Result<(), Errno> {
        let stream = self.get(id)?;
        let mut copy = Vec::new();
        copy.try_reserve_exact(bytes.len()).map_err(|_| Errno::Enomem)?;
        copy.extend_from_slice(bytes);
        let mut stream = stream.lock();
        let next = stream.queued.checked_add(copy.len()).ok_or(Errno::Enospc)?;
        if stream.queued >= MAX_CAPACITY || next >= MAX_CAPACITY { return Err(Errno::Enospc); }
        stream.fifo.try_reserve(1).map_err(|_| Errno::Enomem)?;
        stream.queued = next;
        stream.fifo.push_back(Element { bytes: copy, consumed: 0 });
        Ok(())
    }

    /// Drain at most `len` bytes to userspace. A fault restores the current
    /// element's cursor; earlier complete elements stay consumed. # C: O(len)
    pub fn drain_user(&self, id: u32, user: u64, len: usize) -> Result<usize, Errno> {
        let mut stream = self.get(id)?.lock();
        let mut copied = 0usize;
        while copied < len {
            let Some(front) = stream.fifo.front_mut() else { break };
            let before = front.consumed;
            let take = (front.bytes.len() - before).min(len - copied);
            let bytes = &front.bytes[before..before + take];
            let Some(destination) = user.checked_add(copied as u64) else { return Err(Errno::Efault) };
            if super::super::user::write_bytes(destination, bytes).is_err() {
                front.consumed = before;
                return Err(Errno::Efault);
            }
            front.consumed += take;
            copied += take;
            if front.consumed == front.bytes.len() {
                let done = stream.fifo.pop_front().unwrap();
                stream.queued -= done.bytes.len();
            }
        }
        Ok(copied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_partial_reads_and_stream_isolation() {
        let streams = ProgStreams::new();
        streams.push(STDOUT, b"abc").unwrap();
        streams.push(STDOUT, b"def").unwrap();
        streams.push(STDERR, b"err").unwrap();
        let mut out = [0u8; 8];
        assert_eq!(streams.drain_user(STDOUT, out.as_mut_ptr() as u64, 4), Ok(4));
        assert_eq!(&out[..4], b"abcd");
        assert_eq!(streams.drain_user(STDOUT, out.as_mut_ptr() as u64, 4), Ok(2));
        assert_eq!(&out[..2], b"ef");
        assert_eq!(streams.drain_user(STDERR, out.as_mut_ptr() as u64, 3), Ok(3));
        assert_eq!(&out[..3], b"err");
    }

    #[test]
    fn strict_capacity_and_unknown_stream_match_the_abi() {
        let streams = ProgStreams::new();
        assert_eq!(streams.push(0, b"x"), Err(Errno::Enoent));
        let bytes = alloc::vec![0u8; MAX_CAPACITY - 1];
        streams.push(STDOUT, &bytes).unwrap();
        assert_eq!(streams.push(STDOUT, b"x"), Err(Errno::Enospc));
    }

    #[test]
    fn user_fault_does_not_advance_the_front_element() {
        let streams = ProgStreams::new();
        streams.push(STDOUT, b"kept").unwrap();
        assert_eq!(streams.drain_user(STDOUT, 0, 4), Err(Errno::Efault));
        let mut out = [0u8; 4];
        assert_eq!(streams.drain_user(STDOUT, out.as_mut_ptr() as u64, 4), Ok(4));
        assert_eq!(&out, b"kept");
    }
}
