//! Sink-only `ttynull` file operations.
//!
//! Linux's null TTY consumes every write and advertises a 64 KiB write room.
//! It has no receive producer. Oxide exposes the same useful console contract:
//! output succeeds without reaching either the serial UART or the video VT.

use vfs::{File, FileOps, KResult, VfsError};

pub(crate) struct NullFileOps;

impl FileOps for NullFileOps {
    fn read_file(&self, _file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { Ok(0) } else { Err(VfsError::Eagain) }
    }

    fn read_nonblock_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_file(file, off, buf)
    }

    fn write_file(&self, _file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        Ok(buf.len())
    }

    fn write_nonblock_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_file(file, off, buf)
    }

    fn can_poll(&self, _file: &File) -> bool { true }
    fn poll_open_file(&self, _file: &File) -> u32 { tty::ldisc::pollmask::POLLOUT }
}

pub(crate) fn read(buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() { Ok(0) } else { Err(VfsError::Eagain) }
}

pub(crate) fn write(buf: &[u8]) -> usize { buf.len() }
pub(crate) const fn poll() -> u32 { tty::ldisc::pollmask::POLLOUT }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_write_is_consumed_without_becoming_readable() {
        assert_eq!(write(b"discarded console bytes"), 23);
        assert_eq!(poll(), tty::ldisc::pollmask::POLLOUT);
        assert_eq!(read(&mut [0u8; 1]), Err(VfsError::Eagain));
        assert_eq!(read(&mut []), Ok(0));
    }
}
