// x86_64 ELF relocation engine. v1 supports the relocation types
// real-world .ko files actually emit:
//   - R_X86_64_64       (1):  S + A          (8 bytes)
//   - R_X86_64_PC32     (2):  S + A - P      (4 bytes, sign-extended)
//   - R_X86_64_PLT32    (4):  same as PC32 (no separate PLT in v1)
//   - R_X86_64_32       (10): S + A          (4 bytes, zero-extended)
//   - R_X86_64_32S      (11): S + A          (4 bytes, sign-extended,
//                                             must fit in i32)
//
// Other types (GOT*, TLS*, COPY) surface as RelocError::Unsupported
// and the caller (Module::load) refuses to load such modules.
//
// Inputs:
//   `dest`:        the byte slice covering the section being
//                  relocated (after section placement).
//   `dest_lba`:    the section's virtual base address.
//   `r`:           the parsed Rela record (offset is relative to
//                  the section base; addend is signed).
//   `sym_value`:   the absolute virtual address of the symbol the
//                  relocation references.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RelocError {
    OutOfRange,
    Unsupported,
    DestTooSmall,
}

pub const R_X86_64_NONE:    u32 = 0;
pub const R_X86_64_64:      u32 = 1;
pub const R_X86_64_PC32:    u32 = 2;
pub const R_X86_64_GOT32:   u32 = 3;
pub const R_X86_64_PLT32:   u32 = 4;
pub const R_X86_64_GOTPCREL:u32 = 9;
pub const R_X86_64_32:      u32 = 10;
pub const R_X86_64_32S:     u32 = 11;
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;

/// Apply one relocation. `dest_base` is the virtual address of
/// `dest[0]`; `r_offset` is the offset within `dest` to patch.
/// `sym_value` is the resolved absolute VA of the referenced symbol.
/// # C: O(1)
pub fn apply(
    r_type: u32,
    r_offset: u64, addend: i64,
    sym_value: u64,
    dest: &mut [u8], dest_base: u64,
) -> Result<(), RelocError> {
    let off = r_offset as usize;
    let p   = dest_base.wrapping_add(r_offset);
    match r_type {
        R_X86_64_NONE => Ok(()),
        R_X86_64_64 => {
            if off + 8 > dest.len() { return Err(RelocError::DestTooSmall); }
            let v = sym_value.wrapping_add(addend as u64);
            dest[off..off+8].copy_from_slice(&v.to_le_bytes());
            Ok(())
        }
        R_X86_64_PC32 | R_X86_64_PLT32 => {
            if off + 4 > dest.len() { return Err(RelocError::DestTooSmall); }
            let v = sym_value.wrapping_add(addend as u64).wrapping_sub(p);
            let v = v as i64;
            if v < i32::MIN as i64 || v > i32::MAX as i64 {
                return Err(RelocError::OutOfRange);
            }
            dest[off..off+4].copy_from_slice(&(v as i32).to_le_bytes());
            Ok(())
        }
        R_X86_64_32 => {
            if off + 4 > dest.len() { return Err(RelocError::DestTooSmall); }
            let v = sym_value.wrapping_add(addend as u64);
            if v > u32::MAX as u64 { return Err(RelocError::OutOfRange); }
            dest[off..off+4].copy_from_slice(&(v as u32).to_le_bytes());
            Ok(())
        }
        R_X86_64_32S => {
            if off + 4 > dest.len() { return Err(RelocError::DestTooSmall); }
            let v = sym_value.wrapping_add(addend as u64) as i64;
            if v < i32::MIN as i64 || v > i32::MAX as i64 {
                return Err(RelocError::OutOfRange);
            }
            dest[off..off+4].copy_from_slice(&(v as i32).to_le_bytes());
            Ok(())
        }
        _ => Err(RelocError::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_64_simple() {
        let mut buf = [0u8; 16];
        apply(R_X86_64_64, 0, 0x10, 0x1000, &mut buf, 0).unwrap();
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 0x1010);
    }

    #[test]
    fn r_pc32_displacement() {
        // dest_base=0x2000, r_offset=4, sym=0x3000, A=-4 → S + A - P = 0x3000-4-0x2004 = 0xff8
        let mut buf = [0u8; 8];
        apply(R_X86_64_PC32, 4, -4, 0x3000, &mut buf, 0x2000).unwrap();
        let v = i32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(v, 0xff8);
    }

    #[test]
    fn r_32s_oor() {
        let mut buf = [0u8; 8];
        let r = apply(R_X86_64_32S, 0, 0, 0x8000_0000, &mut buf, 0);
        assert_eq!(r.err().unwrap(), RelocError::OutOfRange);
    }

    #[test]
    fn unsupported_type() {
        let mut buf = [0u8; 8];
        assert_eq!(apply(R_X86_64_GOTPCREL, 0, 0, 0, &mut buf, 0).err().unwrap(),
                   RelocError::Unsupported);
    }
}
