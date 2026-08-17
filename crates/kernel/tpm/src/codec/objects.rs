// Object, sealing and non-volatile-index commands. These take their
// structured operands as already-marshalled sized buffers: the public area,
// sensitive area and private blob are opaque to this layer, which owns the
// framing — header, handles, authorisation area, TPM2B lengths — and nothing
// else. A caller that hands over a blob of the wrong shape gets a device
// error, not a silently reframed command.

use alloc::vec::Vec;

use super::cmd::CmdBuf;
use super::error::CodecError;
use super::rsp::Response;
use crate::uapi::{
    TPM2_CC_CREATE, TPM2_CC_CREATE_PRIMARY, TPM2_CC_GET_TEST_RESULT,
    TPM2_CC_HIERARCHY_CHANGE_AUTH, TPM2_CC_LOAD, TPM2_CC_NV_READ, TPM2_CC_NV_READ_PUBLIC,
    TPM2_CC_NV_WRITE, TPM2_CC_READ_PUBLIC, TPM2_CC_UNSEAL, TPM2_ST_NO_SESSIONS, TPM2_ST_SESSIONS,
};

/// Create a primary object under `hierarchy`.
///
/// `sensitive`, `public` and `outside_info` are marshalled TPM2B bodies
/// without their length prefixes; `pcr_selection` is a marshalled
/// selection list. # C: O(total operand length)
pub fn create_primary(hierarchy: u32, sensitive: &[u8], public: &[u8], outside_info: &[u8],
                      pcr_selection: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_SESSIONS, TPM2_CC_CREATE_PRIMARY);
    b.handle(hierarchy);
    b.password_auth();
    b.sized_u16(sensitive);
    b.sized_u16(public);
    b.sized_u16(outside_info);
    b.bytes(pcr_selection);
    b.finish()
}

/// Create an object under a loaded parent. # C: O(total operand length)
pub fn create(parent: u32, sensitive: &[u8], public: &[u8], outside_info: &[u8],
              pcr_selection: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_SESSIONS, TPM2_CC_CREATE);
    b.handle(parent);
    b.password_auth();
    b.sized_u16(sensitive);
    b.sized_u16(public);
    b.sized_u16(outside_info);
    b.bytes(pcr_selection);
    b.finish()
}

/// Load a previously created object into the device. # C: O(blob length)
pub fn load(parent: u32, private: &[u8], public: &[u8]) -> Result<Vec<u8>, CodecError> {
    if private.is_empty() || public.is_empty() { return Err(CodecError::BadArgument("empty object blob")); }
    let mut b = CmdBuf::new(TPM2_ST_SESSIONS, TPM2_CC_LOAD);
    b.handle(parent);
    b.password_auth();
    b.sized_u16(private);
    b.sized_u16(public);
    b.finish()
}

/// Read the public area of a loaded object. # C: O(1)
pub fn read_public(handle: u32) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_READ_PUBLIC);
    b.handle(handle);
    b.finish()
}

/// Release the data sealed in a loaded object. # C: O(1)
pub fn unseal(handle: u32) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_SESSIONS, TPM2_CC_UNSEAL);
    b.handle(handle);
    b.password_auth();
    b.finish()
}

/// Parse the sensitive data an unseal returned. # C: O(1)
pub fn parse_unseal<'a>(rsp: &Response<'a>) -> Result<&'a [u8], CodecError> {
    let mut r = rsp.reader()?;
    r.sized_u16()
}

/// Read `size` bytes at `offset` from a non-volatile index. # C: O(1)
pub fn nv_read(auth_handle: u32, nv_index: u32, size: u16, offset: u16) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_SESSIONS, TPM2_CC_NV_READ);
    b.handle(auth_handle);
    b.handle(nv_index);
    b.password_auth();
    b.u16(size);
    b.u16(offset);
    b.finish()
}

/// Parse the data a non-volatile read returned. # C: O(1)
pub fn parse_nv_read<'a>(rsp: &Response<'a>) -> Result<&'a [u8], CodecError> {
    let mut r = rsp.reader()?;
    r.sized_u16()
}

/// Write `data` at `offset` into a non-volatile index. # C: O(len)
pub fn nv_write(auth_handle: u32, nv_index: u32, data: &[u8], offset: u16) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_SESSIONS, TPM2_CC_NV_WRITE);
    b.handle(auth_handle);
    b.handle(nv_index);
    b.password_auth();
    b.sized_u16(data);
    b.u16(offset);
    b.finish()
}

/// Read the public area of a non-volatile index. # C: O(1)
pub fn nv_read_public(nv_index: u32) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_NV_READ_PUBLIC);
    b.handle(nv_index);
    b.finish()
}

/// Replace a hierarchy's authorisation value. # C: O(len)
pub fn hierarchy_change_auth(hierarchy: u32, new_auth: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_SESSIONS, TPM2_CC_HIERARCHY_CHANGE_AUTH);
    b.handle(hierarchy);
    b.password_auth();
    b.sized_u16(new_auth);
    b.finish()
}

/// Read the result of the last self test. # C: O(1)
pub fn get_test_result() -> Result<Vec<u8>, CodecError> {
    CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_GET_TEST_RESULT).finish()
}

/// A self-test result: vendor-defined data and the response code the tests
/// produced.
pub struct TestResult<'a> {
    pub data: &'a [u8],
    pub test_result: u32,
}

/// Parse a self-test result. # C: O(1)
pub fn parse_get_test_result<'a>(rsp: &Response<'a>) -> Result<TestResult<'a>, CodecError> {
    let mut r = rsp.reader()?;
    let data = r.sized_u16()?;
    let test_result = r.u32()?;
    Ok(TestResult { data, test_result })
}
