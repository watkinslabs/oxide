// The commands this kernel builds and the parsers for their responses. Each
// pair is written together so the encoding and the decoding of one command
// cannot drift apart.

use alloc::vec::Vec;

use super::cmd::CmdBuf;
use super::error::CodecError;
use super::reader::Reader;
use super::rsp::Response;
use crate::alg::Alg;
use crate::limits::{MAX_RNG_DATA, PCR_SELECT_MIN, PLATFORM_PCR};
use crate::uapi::{
    TPM2_CC_CONTEXT_LOAD, TPM2_CC_CONTEXT_SAVE, TPM2_CC_FLUSH_CONTEXT, TPM2_CC_GET_CAPABILITY,
    TPM2_CC_GET_RANDOM, TPM2_CC_PCR_EXTEND, TPM2_CC_PCR_READ, TPM2_CC_SELF_TEST,
    TPM2_CC_SHUTDOWN, TPM2_CC_STARTUP, TPM2_CC_STIR_RANDOM, TPM2_ST_NO_SESSIONS,
    TPM2_ST_SESSIONS,
};

/// Selection bitmap naming a single register. Bit `idx & 7` of byte
/// `idx >> 3`. # C: O(1)
pub fn pcr_select(idx: usize) -> Result<[u8; PCR_SELECT_MIN], CodecError> {
    if idx >= PLATFORM_PCR { return Err(CodecError::BadArgument("pcr index")); }
    let mut sel = [0u8; PCR_SELECT_MIN];
    sel[idx >> 3] = 1 << (idx & 7);
    Ok(sel)
}

/// Read one register from one bank. # C: O(1)
pub fn pcr_read(alg: Alg, idx: usize) -> Result<Vec<u8>, CodecError> {
    let sel = pcr_select(idx)?;
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_PCR_READ);
    b.u32(1).u16(alg.id()).u8(PCR_SELECT_MIN as u8).bytes(&sel);
    b.finish()
}

/// A PCR read result: the update counter and the digest of the first
/// selection the device returned.
pub struct PcrReadOut<'a> {
    pub update_counter: u32,
    pub alg_id: u16,
    pub digest: &'a [u8],
}

/// Parse a PCR read response. # C: O(selections)
pub fn parse_pcr_read<'a>(rsp: &Response<'a>) -> Result<PcrReadOut<'a>, CodecError> {
    let mut r = rsp.reader()?;
    let update_counter = r.u32()?;
    let selects = r.u32()?;
    if selects == 0 { return Err(CodecError::ShortBody { need: 1, have: 0 }); }
    let mut alg_id = 0u16;
    for i in 0..selects {
        let a = r.u16()?;
        let n = r.u8()? as usize;
        r.bytes(n)?;
        if i == 0 { alg_id = a; }
    }
    let digests = r.u32()?;
    if digests == 0 { return Err(CodecError::ShortBody { need: 1, have: 0 }); }
    let digest = r.sized_u16()?;
    Ok(PcrReadOut { update_counter, alg_id, digest })
}

/// Extend one register in every bank named by `digests`, authorised by an
/// empty password. Each entry is (algorithm identifier, digest). # C: O(banks)
pub fn pcr_extend(idx: usize, digests: &[(u16, &[u8])]) -> Result<Vec<u8>, CodecError> {
    if idx >= PLATFORM_PCR { return Err(CodecError::BadArgument("pcr index")); }
    if digests.is_empty() { return Err(CodecError::BadArgument("no digests")); }
    for (id, d) in digests.iter() {
        match Alg::digest_size_of(*id) {
            Some(n) if n == d.len() => {}
            Some(_) => return Err(CodecError::BadArgument("digest length")),
            None => return Err(CodecError::BadArgument("unknown algorithm")),
        }
    }
    let mut b = CmdBuf::new(TPM2_ST_SESSIONS, TPM2_CC_PCR_EXTEND);
    b.handle(idx as u32);
    b.password_auth();
    b.u32(digests.len() as u32);
    for (id, d) in digests.iter() { b.u16(*id).bytes(d); }
    b.finish()
}

/// Request `n` random bytes. # C: O(1)
pub fn get_random(n: u16) -> Result<Vec<u8>, CodecError> {
    if n == 0 || n as usize > MAX_RNG_DATA { return Err(CodecError::BadArgument("random byte count")); }
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_GET_RANDOM);
    b.u16(n);
    b.finish()
}

/// Parse a random-bytes response. The device may return fewer bytes than
/// asked for; it may never return more than it declares. # C: O(1)
pub fn parse_get_random<'a>(rsp: &Response<'a>) -> Result<&'a [u8], CodecError> {
    let mut r = rsp.reader()?;
    r.sized_u16()
}

/// Add caller entropy to the device's pool. # C: O(n)
pub fn stir_random(seed: &[u8]) -> Result<Vec<u8>, CodecError> {
    if seed.is_empty() { return Err(CodecError::BadArgument("empty seed")); }
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_STIR_RANDOM);
    b.sized_u16(seed);
    b.finish()
}

/// Query `count` values of `property` within `capability`. # C: O(1)
pub fn get_capability(capability: u32, property: u32, count: u32) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_GET_CAPABILITY);
    b.u32(capability).u32(property).u32(count);
    b.finish()
}

/// A capability response: whether more data remains, which capability the
/// payload belongs to, and a cursor positioned at the payload.
pub struct CapabilityOut<'a> {
    pub more_data: bool,
    pub capability: u32,
    pub reader: Reader<'a>,
}

/// Parse a capability response up to the start of its payload. # C: O(1)
pub fn parse_get_capability<'a>(rsp: &Response<'a>) -> Result<CapabilityOut<'a>, CodecError> {
    let mut r = rsp.reader()?;
    let more_data = r.u8()? != 0;
    let capability = r.u32()?;
    Ok(CapabilityOut { more_data, capability, reader: r })
}

/// Run the device's self tests. `full` re-runs tests already passed.
/// # C: O(1)
pub fn self_test(full: bool) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_SELF_TEST);
    b.u8(u8::from(full));
    b.finish()
}

/// Start the device. # C: O(1)
pub fn startup(startup_type: u16) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_STARTUP);
    b.u16(startup_type);
    b.finish()
}

/// Stop the device. # C: O(1)
pub fn shutdown(shutdown_type: u16) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_SHUTDOWN);
    b.u16(shutdown_type);
    b.finish()
}

/// Release a loaded object or session. # C: O(1)
pub fn flush_context(handle: u32) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_FLUSH_CONTEXT);
    b.u32(handle);
    b.finish()
}

/// Save a loaded object or session out of the device. # C: O(1)
pub fn context_save(handle: u32) -> Result<Vec<u8>, CodecError> {
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_CONTEXT_SAVE);
    b.u32(handle);
    b.finish()
}

/// Load a previously saved context blob back into the device. # C: O(n)
pub fn context_load(blob: &[u8]) -> Result<Vec<u8>, CodecError> {
    if blob.is_empty() { return Err(CodecError::BadArgument("empty context")); }
    let mut b = CmdBuf::new(TPM2_ST_NO_SESSIONS, TPM2_CC_CONTEXT_LOAD);
    b.bytes(blob);
    b.finish()
}

/// Parse the response handle a command returns. Response handles sit ahead
/// of the parameter area, not inside it. # C: O(1)
pub fn parse_handle(rsp: &Response<'_>) -> Result<u32, CodecError> {
    rsp.ok()?;
    let h = rsp.handles(1)?;
    Ok(u32::from_be_bytes([h[0], h[1], h[2], h[3]]))
}
