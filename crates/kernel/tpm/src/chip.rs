// The character-device transaction model.
//
// The device is a request/response pipe with exactly one command in flight
// per open file, and the rules that keep it that way are all state, not
// locking:
//
//   - a write while an unread response is parked is refused, so a second
//     command cannot silently discard the first one's answer;
//   - a response is consumed once — each read hands back only the bytes not
//     yet returned, and zeroes what it hands back so the buffer does not
//     retain a measurement after the reader has it;
//   - a response nobody reads is dropped after a bounded wait rather than
//     wedging the file forever.
//
// None of this touches the filesystem; a device node is wired up by the
// layer that owns device nodes and calls into this state machine.

use alloc::vec;
use alloc::vec::Vec;

use crate::limits::TPM_BUFSIZE;
use crate::uapi::HDR_OFF_LEN;

/// Bytes of a command that must be present before its length field can be
/// read: the tag and the length itself.
const MIN_WRITE_LEN: usize = 6;

/// Why a device-file operation was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DevError {
    /// The command is larger than the device buffer.
    TooBig,
    /// A response is still parked, or a command is still queued.
    Busy,
    /// The command is shorter than its own length field says.
    Inval,
    /// The transport failed.
    Io,
}

/// What a poll on the device file would report.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Readiness {
    /// A response is waiting to be read.
    Readable,
    /// The device will accept a command.
    Writable,
}

/// One open file on the device.
pub struct DevFile {
    buf: Vec<u8>,
    /// Bytes of response not yet handed to the reader.
    response_length: usize,
    /// Whether the reader has taken at least part of the current response.
    response_read: bool,
    /// Offset of the next unread response byte.
    off: usize,
    /// Whether a command has been queued but not yet transmitted.
    command_enqueued: bool,
}

impl Default for DevFile { fn default() -> Self { Self::new() } }

impl DevFile {
    /// A freshly opened file: no command in flight, nothing to read.
    /// # C: O(TPM_BUFSIZE)
    pub fn new() -> Self {
        DevFile { buf: vec![0u8; TPM_BUFSIZE], response_length: 0, response_read: true, off: 0, command_enqueued: false }
    }

    /// Accept a command, leaving it staged for the transport.
    ///
    /// Returns the number of bytes accepted, which is the whole command: a
    /// partial command is an error rather than a short write, because the
    /// device has no way to resume one. # C: O(len)
    pub fn write(&mut self, cmd: &[u8]) -> Result<usize, DevError> {
        if cmd.len() > TPM_BUFSIZE { return Err(DevError::TooBig); }
        if (!self.response_read && self.response_length != 0) || self.command_enqueued { return Err(DevError::Busy); }
        if cmd.len() < MIN_WRITE_LEN { return Err(DevError::Inval); }
        let declared = u32::from_be_bytes([
            cmd[HDR_OFF_LEN], cmd[HDR_OFF_LEN + 1], cmd[HDR_OFF_LEN + 2], cmd[HDR_OFF_LEN + 3],
        ]) as usize;
        if cmd.len() < declared { return Err(DevError::Inval); }
        self.buf[..cmd.len()].copy_from_slice(cmd);
        self.response_length = 0;
        self.response_read = false;
        self.off = 0;
        Ok(cmd.len())
    }

    /// The staged command, for the transport to send. # C: O(1)
    pub fn staged(&self, len: usize) -> &[u8] { &self.buf[..len] }

    /// Queue the staged command for asynchronous transmission. A file with a
    /// queued command refuses further writes. # C: O(1)
    pub fn enqueue(&mut self) { self.command_enqueued = true; }

    /// Record the response the transport produced. # C: O(len)
    pub fn complete(&mut self, rsp: &[u8]) -> Result<(), DevError> {
        self.command_enqueued = false;
        if rsp.len() > TPM_BUFSIZE { return Err(DevError::TooBig); }
        self.buf[..rsp.len()].copy_from_slice(rsp);
        self.response_length = rsp.len();
        self.response_read = false;
        self.off = 0;
        Ok(())
    }

    /// Record that the transport failed; nothing becomes readable. # C: O(1)
    pub fn fail(&mut self) {
        self.command_enqueued = false;
        self.response_length = 0;
        self.response_read = true;
        self.off = 0;
    }

    /// Hand the reader up to `out.len()` bytes of the parked response,
    /// returning how many. Bytes handed over are cleared from the buffer and
    /// are never returned twice. # C: O(n)
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        if self.response_length == 0 { return 0; }
        self.response_read = true;
        let n = core::cmp::min(out.len(), self.response_length);
        if n == 0 { self.response_length = 0; self.off = 0; return 0; }
        out[..n].copy_from_slice(&self.buf[self.off..self.off + n]);
        self.buf[self.off..self.off + n].fill(0);
        self.response_length -= n;
        self.off += n;
        if self.response_length == 0 { self.off = 0; }
        n
    }

    /// Bytes of response still unread. # C: O(1)
    pub fn response_length(&self) -> usize { self.response_length }

    /// What a poll would report. # C: O(1)
    pub fn readiness(&self) -> Readiness {
        if self.response_length != 0 { Readiness::Readable } else { Readiness::Writable }
    }

    /// Drop a response no reader collected, freeing the file for the next
    /// command. The buffer is zeroed: an abandoned response is still a
    /// measurement. # C: O(TPM_BUFSIZE)
    pub fn expire(&mut self) {
        self.response_read = true;
        self.response_length = 0;
        self.off = 0;
        self.buf.fill(0);
    }

    /// Close the file. # C: O(TPM_BUFSIZE)
    pub fn release(&mut self) {
        self.command_enqueued = false;
        self.expire();
    }
}
