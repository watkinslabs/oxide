//! Host-testable decoding for one AMD64 Windows `CONTEXT` restore image.

const CONTEXT_BYTES: usize = 0x4d0;
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_CONTROL: u32 = 0x0000_0001;
const CONTEXT_INTEGER: u32 = 0x0000_0002;
const CONTEXT_SEGMENTS: u32 = 0x0000_0004;
const CONTEXT_FLOATING_POINT: u32 = 0x0000_0008;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x0000_0010;
const CONTEXT_XSTATE: u32 = 0x0000_0040;
const CONTEXT_HIGH_FLAGS: u32 = 0xd800_0000;
const CONTEXT_SUPPORTED: u32 = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER
    | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_HIGH_FLAGS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RestoreImage {
    pub flags: u32,
    pub rflags: u32,
    pub registers: [u64; 17],
    pub floating: Option<[u8; 512]>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Error { Invalid, Unsupported }

impl RestoreImage {
    pub const RAX: usize = 0;
    pub const RCX: usize = 1;
    pub const RDX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSP: usize = 4;
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
    pub const R8: usize = 8;
    pub const R9: usize = 9;
    pub const R10: usize = 10;
    pub const R11: usize = 11;
    pub const R12: usize = 12;
    pub const R13: usize = 13;
    pub const R14: usize = 14;
    pub const R15: usize = 15;
    pub const RIP: usize = 16;

    pub fn has_integer(&self) -> bool { self.flags & CONTEXT_INTEGER != 0 }
}

pub(crate) fn decode(bytes: &[u8]) -> Result<RestoreImage, Error> {
    if bytes.len() != CONTEXT_BYTES { return Err(Error::Invalid); }
    let flags = read_u32(bytes, 0x30)?;
    if flags & CONTEXT_AMD64 != CONTEXT_AMD64 || flags & CONTEXT_CONTROL == 0 { return Err(Error::Invalid); }
    if flags & (CONTEXT_XSTATE | CONTEXT_DEBUG_REGISTERS) != 0 { return Err(Error::Unsupported); }
    if flags & !CONTEXT_SUPPORTED != 0 { return Err(Error::Invalid); }
    let offsets = [0x78, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8,
        0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, 0xf8];
    let mut registers = [0u64; 17];
    for (slot, offset) in registers.iter_mut().zip(offsets) { *slot = read_u64(bytes, offset)?; }
    let floating = if flags & CONTEXT_FLOATING_POINT != 0 {
        let mut image = [0u8; 512];
        image.copy_from_slice(bytes.get(0x100..0x300).ok_or(Error::Invalid)?);
        Some(image)
    } else { None };
    Ok(RestoreImage { flags, rflags: read_u32(bytes, 0x44)?, registers, floating })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(bytes.get(offset..offset + 4).ok_or(Error::Invalid)?.try_into().map_err(|_| Error::Invalid)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(bytes.get(offset..offset + 8).ok_or(Error::Invalid)?.try_into().map_err(|_| Error::Invalid)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> [u8; CONTEXT_BYTES] {
        let mut bytes = [0u8; CONTEXT_BYTES];
        bytes[0x30..0x34].copy_from_slice(&(CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT).to_le_bytes());
        bytes[0x44..0x48].copy_from_slice(&0x202u32.to_le_bytes());
        bytes[0x78..0x80].copy_from_slice(&7u64.to_le_bytes());
        bytes[0x98..0xa0].copy_from_slice(&0x7000u64.to_le_bytes());
        bytes[0xf8..0x100].copy_from_slice(&0x4000u64.to_le_bytes());
        bytes[0x118..0x11c].copy_from_slice(&0x1f80u32.to_le_bytes());
        bytes
    }

    #[test]
    fn decodes_control_integer_and_fxsave_transactionally() {
        let image = decode(&full()).unwrap();
        assert_eq!(image.registers[RestoreImage::RAX], 7);
        assert_eq!(image.registers[RestoreImage::RSP], 0x7000);
        assert_eq!(image.registers[RestoreImage::RIP], 0x4000);
        assert_eq!(&image.floating.unwrap()[24..28], &0x1f80u32.to_le_bytes());
    }

    #[test]
    fn rejects_records_without_control_or_amd64_identity() {
        let mut bytes = full();
        bytes[0x30..0x34].copy_from_slice(&CONTEXT_INTEGER.to_le_bytes());
        assert_eq!(decode(&bytes), Err(Error::Invalid));
        bytes[0x30..0x34].copy_from_slice(&(CONTEXT_AMD64 | CONTEXT_INTEGER).to_le_bytes());
        assert_eq!(decode(&bytes), Err(Error::Invalid));
    }

    #[test]
    fn rejects_unowned_debug_and_xstate_components() {
        for unsupported in [CONTEXT_DEBUG_REGISTERS, CONTEXT_XSTATE] {
            let mut bytes = full();
            let flags = CONTEXT_AMD64 | CONTEXT_CONTROL | unsupported;
            bytes[0x30..0x34].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(decode(&bytes), Err(Error::Unsupported));
        }
    }
}
