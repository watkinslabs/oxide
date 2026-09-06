use alloc::vec::Vec;
use syscall::nt_compositor::{Header, Record, HEADER_LEN};
use super::TransportError;

/// Exact reads distinguish EOF at any byte from a complete record. # C: O(bytes)
pub(super) fn read_record(mut read: impl FnMut(&mut [u8]) -> Result<usize, TransportError>) -> Result<Record, TransportError> {
    let mut header = [0; HEADER_LEN]; read_exact(&mut header, &mut read)?;
    let header = Header::decode(&header).map_err(|_| TransportError::Invalid)?;
    if !header.opcode.from_backend() { return Err(TransportError::Invalid); }
    let mut payload = Vec::new(); payload.try_reserve_exact(header.length as usize).map_err(|_| TransportError::NoMemory)?;
    payload.resize(header.length as usize, 0); read_exact(&mut payload, &mut read)?;
    let record = Record { header, payload }; record.validate().map_err(|_| TransportError::Invalid)?; Ok(record)
}

fn read_exact(mut out: &mut [u8], read: &mut impl FnMut(&mut [u8]) -> Result<usize, TransportError>) -> Result<(), TransportError> {
    while !out.is_empty() {
        let n = read(out)?;
        if n == 0 { return Err(TransportError::Disconnected); }
        if n > out.len() { return Err(TransportError::Invalid); }
        out = &mut out[n..];
    } Ok(())
}

/// Transport success requires all bytes, including the final pixel. # C: O(bytes)
pub(super) fn write_record(mut bytes: &[u8], mut write: impl FnMut(&[u8]) -> Result<usize, TransportError>) -> Result<(), TransportError> {
    while !bytes.is_empty() {
        let n = write(bytes)?;
        if n == 0 { return Err(TransportError::Disconnected); }
        if n > bytes.len() { return Err(TransportError::Invalid); }
        bytes = &bytes[n..];
    } Ok(())
}
