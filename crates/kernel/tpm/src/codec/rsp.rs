// Response header validation. Three checks stand between a device and the
// rest of the kernel, and each has a way of failing open:
//
//   - a buffer shorter than the header would otherwise be read as one;
//   - a length field larger than the buffer would let a body parser walk off
//     the end, and one smaller would leave trailing bytes attributed to the
//     response;
//   - a non-zero response code that is not checked reads exactly like
//     success, so `ok` is the only way to reach the body.

use super::error::CodecError;
use super::reader::Reader;
use crate::rc::Rc;
use crate::uapi::{HDR_OFF_CODE, HDR_OFF_LEN, HDR_OFF_TAG, HEADER_SIZE, TPM2_ST_NO_SESSIONS, TPM2_ST_SESSIONS};

/// A validated response buffer.
pub struct Response<'a> {
    buf: &'a [u8],
    tag: u16,
    rc: Rc,
}

impl<'a> Response<'a> {
    /// Validate a response buffer's framing. Does NOT accept or reject the
    /// response code — see `ok`. # C: O(1)
    pub fn parse(buf: &'a [u8]) -> Result<Self, CodecError> {
        if buf.len() < HEADER_SIZE { return Err(CodecError::ShortHeader { got: buf.len() }); }
        let tag = u16::from_be_bytes([buf[HDR_OFF_TAG], buf[HDR_OFF_TAG + 1]]);
        let declared = u32::from_be_bytes([
            buf[HDR_OFF_LEN], buf[HDR_OFF_LEN + 1], buf[HDR_OFF_LEN + 2], buf[HDR_OFF_LEN + 3],
        ]);
        if (declared as usize) < HEADER_SIZE { return Err(CodecError::LengthUnderHeader { declared }); }
        if declared as usize != buf.len() { return Err(CodecError::LengthMismatch { declared, actual: buf.len() }); }
        if tag != TPM2_ST_NO_SESSIONS && tag != TPM2_ST_SESSIONS { return Err(CodecError::BadTag(tag)); }
        let rc = Rc::new(u32::from_be_bytes([
            buf[HDR_OFF_CODE], buf[HDR_OFF_CODE + 1], buf[HDR_OFF_CODE + 2], buf[HDR_OFF_CODE + 3],
        ]));
        Ok(Response { buf, tag, rc })
    }

    /// Structure tag. # C: O(1)
    pub fn tag(&self) -> u16 { self.tag }

    /// Total length, header included. # C: O(1)
    pub fn len(&self) -> usize { self.buf.len() }

    /// Whether the response carries nothing beyond its header. # C: O(1)
    pub fn is_empty(&self) -> bool { self.buf.len() == HEADER_SIZE }

    /// Decoded response code. # C: O(1)
    pub fn rc(&self) -> Rc { self.rc }

    /// Reject any non-success code. A warning is not a success: the command
    /// did not run. # C: O(1)
    pub fn ok(&self) -> Result<(), CodecError> {
        if self.rc.is_success() { Ok(()) } else { Err(CodecError::Device(self.rc)) }
    }

    /// Everything after the header, parameter-size field included.
    /// # C: O(1)
    pub fn raw_body(&self) -> &'a [u8] { &self.buf[HEADER_SIZE..] }

    /// Response handles, of which the command's attributes say how many.
    /// Handles precede the parameter-size field. # C: O(1)
    pub fn handles(&self, n: usize) -> Result<&'a [u8], CodecError> {
        let body = self.raw_body();
        if body.len() < 4 * n { return Err(CodecError::Truncated { need: 4 * n, have: body.len() }); }
        Ok(&body[..4 * n])
    }

    /// The response parameters, past `n_handles` response handles. In a
    /// response carrying sessions the parameters are prefixed by a 32-bit
    /// size, which is consumed here so callers see the same layout in both
    /// tagging modes. # C: O(1)
    pub fn parameters_after(&self, n_handles: usize) -> Result<&'a [u8], CodecError> {
        let body = self.raw_body();
        if body.len() < 4 * n_handles { return Err(CodecError::Truncated { need: 4 * n_handles, have: body.len() }); }
        let body = &body[4 * n_handles..];
        if self.tag != TPM2_ST_SESSIONS { return Ok(body); }
        if body.len() < 4 { return Err(CodecError::Truncated { need: 4, have: body.len() }); }
        let n = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
        if body.len() - 4 < n { return Err(CodecError::Truncated { need: n, have: body.len() - 4 }); }
        Ok(&body[4..4 + n])
    }

    /// The response parameters of a command that returns no handle.
    /// # C: O(1)
    pub fn parameters(&self) -> Result<&'a [u8], CodecError> { self.parameters_after(0) }

    /// Cursor over the parameters, after `ok` has accepted the code.
    /// # C: O(1)
    pub fn reader(&self) -> Result<Reader<'a>, CodecError> { self.reader_after(0) }

    /// Cursor over the parameters of a command returning `n_handles` handles.
    /// # C: O(1)
    pub fn reader_after(&self, n_handles: usize) -> Result<Reader<'a>, CodecError> {
        self.ok()?;
        Ok(Reader::new(self.parameters_after(n_handles)?))
    }
}
