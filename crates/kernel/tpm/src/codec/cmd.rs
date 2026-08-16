// Command buffer builder. The header's length field tracks the buffer on
// every append, so a command that is never finished still describes itself
// correctly, and a command that overflows the transport buffer is refused at
// `finish` rather than truncated on the wire.

use alloc::vec::Vec;

use super::error::CodecError;
use crate::limits::TPM_BUFSIZE;
use crate::uapi::{
    HDR_OFF_LEN, HEADER_SIZE, TPM2_RS_PW, TPM2_ST_NO_SESSIONS, TPM2_ST_SESSIONS,
    TPM_TAG_RQU_COMMAND,
};

/// Bytes a password authorisation area occupies: handle, empty nonce, no
/// attributes, empty authorisation value.
const PW_AUTH_BODY_LEN: u32 = 9;

/// A command under construction.
pub struct CmdBuf {
    data: Vec<u8>,
    tag: u16,
    handles: u8,
    limit: usize,
    overflow: bool,
}

impl CmdBuf {
    /// Start a command with `tag` and command code `cc`. # C: O(1)
    pub fn new(tag: u16, cc: u32) -> Self { Self::with_limit(tag, cc, TPM_BUFSIZE) }

    /// Start a command bounded by a transport buffer of `limit` bytes.
    /// # C: O(1)
    pub fn with_limit(tag: u16, cc: u32, limit: usize) -> Self {
        let mut b = CmdBuf { data: Vec::with_capacity(HEADER_SIZE), tag, handles: 0, limit, overflow: false };
        b.data.extend_from_slice(&tag.to_be_bytes());
        b.data.extend_from_slice(&(HEADER_SIZE as u32).to_be_bytes());
        b.data.extend_from_slice(&cc.to_be_bytes());
        b
    }

    /// Structure tag this command carries. # C: O(1)
    pub fn tag(&self) -> u16 { self.tag }

    /// Number of handles appended so far. # C: O(1)
    pub fn handles(&self) -> u8 { self.handles }

    /// Bytes appended so far, header included. # C: O(1)
    pub fn len(&self) -> usize { self.data.len() }

    /// Whether nothing beyond the header has been appended. # C: O(1)
    pub fn is_empty(&self) -> bool { self.data.len() == HEADER_SIZE }

    /// Whether an append has exceeded the transport buffer. # C: O(1)
    pub fn overflowed(&self) -> bool { self.overflow }

    fn sync_len(&mut self) {
        let n = (self.data.len() as u32).to_be_bytes();
        self.data[HDR_OFF_LEN..HDR_OFF_LEN + 4].copy_from_slice(&n);
    }

    /// Append raw bytes. # C: O(n)
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        if self.overflow { return self; }
        if self.data.len() + b.len() > self.limit { self.overflow = true; return self; }
        self.data.extend_from_slice(b);
        self.sync_len();
        self
    }

    /// Append a byte. # C: O(1)
    pub fn u8(&mut self, v: u8) -> &mut Self { self.bytes(&[v]) }

    /// Append a 16-bit big-endian word. # C: O(1)
    pub fn u16(&mut self, v: u16) -> &mut Self { self.bytes(&v.to_be_bytes()) }

    /// Append a 32-bit big-endian word. # C: O(1)
    pub fn u32(&mut self, v: u32) -> &mut Self { self.bytes(&v.to_be_bytes()) }

    /// Append a 16-bit-counted byte string. # C: O(n)
    pub fn sized_u16(&mut self, b: &[u8]) -> &mut Self {
        self.u16(b.len() as u16);
        self.bytes(b)
    }

    /// Append a command handle. Handles precede the authorisation area, so
    /// the count is tracked to locate where parameters begin. # C: O(1)
    pub fn handle(&mut self, h: u32) -> &mut Self {
        self.u32(h);
        self.handles = self.handles.saturating_add(1);
        self
    }

    /// Append a password authorisation area holding an empty authorisation
    /// value. Valid only in a command tagged as carrying sessions. # C: O(1)
    pub fn password_auth(&mut self) -> &mut Self {
        self.u32(PW_AUTH_BODY_LEN);
        self.u32(TPM2_RS_PW);
        self.u16(0);
        self.u8(0);
        self.u16(0);
        self
    }

    /// Finish the command. Fails if an append overflowed the transport
    /// buffer or if the tag is not one this kernel emits. # C: O(1)
    pub fn finish(self) -> Result<Vec<u8>, CodecError> {
        if self.overflow { return Err(CodecError::Overflow { limit: self.limit }); }
        match self.tag {
            TPM2_ST_NO_SESSIONS | TPM2_ST_SESSIONS | TPM_TAG_RQU_COMMAND => Ok(self.data),
            t => Err(CodecError::BadTag(t)),
        }
    }
}
