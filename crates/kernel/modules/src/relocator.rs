// ELF relocation engine. v1 supports the relocation types real-world .ko files
// actually emit on x86_64 and aarch64:
//   - R_X86_64_64       (1):  S + A          (8 bytes)
//   - R_X86_64_PC32     (2):  S + A - P      (4 bytes, sign-extended)
//   - R_X86_64_PLT32    (4):  same as PC32 (no separate PLT in v1)
//   - R_X86_64_32       (10): S + A          (4 bytes, zero-extended)
//   - R_X86_64_32S      (11): S + A          (4 bytes, sign-extended,
//                                             must fit in i32)
//   - R_AARCH64_ABS64/PREL32/CALL26/JUMP26/ADR_PREL_PG_HI21/ADD_ABS_LO12_NC
//     and LD/ST *_ABS_LO12_NC forms used by kernel modules.
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
pub const R_X86_64_COPY:    u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;   // S
pub const R_X86_64_JUMP_SLOT: u32 = 7;  // S
pub const R_X86_64_RELATIVE: u32 = 8;   // B + A   (B = base/load_bias)
pub const R_X86_64_GOTPCREL:u32 = 9;
pub const R_X86_64_32:      u32 = 10;
pub const R_X86_64_32S:     u32 = 11;
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;

pub const R_AARCH64_NONE:      u32 = 0;
pub const R_AARCH64_ABS64:     u32 = 257;
pub const R_AARCH64_ABS32:     u32 = 258;
pub const R_AARCH64_ABS16:     u32 = 259;
pub const R_AARCH64_PREL64:    u32 = 260;
pub const R_AARCH64_PREL32:    u32 = 261;
pub const R_AARCH64_PREL16:    u32 = 262;
pub const R_AARCH64_MOVW_UABS_G0: u32 = 263;
pub const R_AARCH64_MOVW_UABS_G0_NC: u32 = 264;
pub const R_AARCH64_MOVW_UABS_G1: u32 = 265;
pub const R_AARCH64_MOVW_UABS_G1_NC: u32 = 266;
pub const R_AARCH64_MOVW_UABS_G2: u32 = 267;
pub const R_AARCH64_MOVW_UABS_G2_NC: u32 = 268;
pub const R_AARCH64_MOVW_UABS_G3: u32 = 269;
pub const R_AARCH64_LD_PREL_LO19: u32 = 273;
pub const R_AARCH64_ADR_PREL_LO21: u32 = 274;
pub const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
pub const R_AARCH64_ADR_PREL_PG_HI21_NC: u32 = 276;
pub const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
pub const R_AARCH64_LDST8_ABS_LO12_NC: u32 = 278;
pub const R_AARCH64_TSTBR14:   u32 = 279;
pub const R_AARCH64_CONDBR19:  u32 = 280;
pub const R_AARCH64_JUMP26:    u32 = 282;
pub const R_AARCH64_CALL26:    u32 = 283;
pub const R_AARCH64_LDST16_ABS_LO12_NC: u32 = 284;
pub const R_AARCH64_LDST32_ABS_LO12_NC: u32 = 285;
pub const R_AARCH64_LDST64_ABS_LO12_NC: u32 = 286;
pub const R_AARCH64_MOVW_PREL_G0: u32 = 287;
pub const R_AARCH64_MOVW_PREL_G0_NC: u32 = 288;
pub const R_AARCH64_MOVW_PREL_G1: u32 = 289;
pub const R_AARCH64_MOVW_PREL_G1_NC: u32 = 290;
pub const R_AARCH64_MOVW_PREL_G2: u32 = 291;
pub const R_AARCH64_MOVW_PREL_G2_NC: u32 = 292;
pub const R_AARCH64_MOVW_PREL_G3: u32 = 293;
pub const R_AARCH64_LDST128_ABS_LO12_NC: u32 = 299;

/// Apply one dynamic relocation (.so / PIE binary). `load_bias`
/// is the address the .so was loaded at (B in ABI terminology).
/// For static-link relocator users (e.g. modules loader), call
/// `apply()` instead which doesn't take load_bias.
/// # C: O(1)
pub fn apply_dynamic(
    r_type: u32,
    r_offset: u64, addend: i64,
    sym_value: u64,
    load_bias: u64,
    dest: &mut [u8], dest_base: u64,
) -> Result<(), RelocError> {
    let off = r_offset as usize;
    match r_type {
        R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
            if off + 8 > dest.len() { return Err(RelocError::DestTooSmall); }
            // Both copy the symbol's resolved VA into the slot.
            // (R_X86_64_JUMP_SLOT is technically lazy-resolvable
            // through the PLT; v1 always eagerly resolves.)
            dest[off..off+8].copy_from_slice(&sym_value.to_le_bytes());
            Ok(())
        }
        R_X86_64_RELATIVE => {
            if off + 8 > dest.len() { return Err(RelocError::DestTooSmall); }
            // B + A — no symbol involved.
            let v = load_bias.wrapping_add(addend as u64);
            dest[off..off+8].copy_from_slice(&v.to_le_bytes());
            Ok(())
        }
        _ => apply(r_type, r_offset, addend, sym_value, dest, dest_base),
    }
}

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

/// Apply one relocation using the ELF `e_machine` value. # C: O(1)
pub fn apply_for_machine(
    machine: u16,
    r_type: u32,
    r_offset: u64, addend: i64,
    sym_value: u64,
    dest: &mut [u8], dest_base: u64,
) -> Result<(), RelocError> {
    match machine {
        elf::EM_X86_64  => apply(r_type, r_offset, addend, sym_value, dest, dest_base),
        elf::EM_AARCH64 => apply_aarch64(r_type, r_offset, addend, sym_value, dest, dest_base),
        _ => Err(RelocError::Unsupported),
    }
}

fn apply_aarch64(
    r_type: u32,
    r_offset: u64, addend: i64,
    sym_value: u64,
    dest: &mut [u8], dest_base: u64,
) -> Result<(), RelocError> {
    let off = r_offset as usize;
    let p = dest_base.wrapping_add(r_offset);
    let s = sym_value.wrapping_add(addend as u64);
    match r_type {
        R_AARCH64_NONE => Ok(()),
        R_AARCH64_ABS64 => write_u64(dest, off, s),
        R_AARCH64_ABS32 => {
            if s > u32::MAX as u64 { return Err(RelocError::OutOfRange); }
            write_u32(dest, off, s as u32)
        }
        R_AARCH64_ABS16 => {
            if s > u16::MAX as u64 { return Err(RelocError::OutOfRange); }
            write_u16(dest, off, s as u16)
        }
        R_AARCH64_PREL64 => write_u64(dest, off, s.wrapping_sub(p)),
        R_AARCH64_PREL32 => {
            let v = s.wrapping_sub(p) as i64;
            if !fits_signed(v, 32) { return Err(RelocError::OutOfRange); }
            write_u32(dest, off, (v as i32) as u32)
        }
        R_AARCH64_PREL16 => {
            let v = s.wrapping_sub(p) as i64;
            if !fits_signed(v, 16) { return Err(RelocError::OutOfRange); }
            write_u16(dest, off, v as u16)
        }
        R_AARCH64_MOVW_UABS_G0 => movw_abs(dest, off, s, 0, true),
        R_AARCH64_MOVW_UABS_G0_NC => movw_abs(dest, off, s, 0, false),
        R_AARCH64_MOVW_UABS_G1 => movw_abs(dest, off, s, 1, true),
        R_AARCH64_MOVW_UABS_G1_NC => movw_abs(dest, off, s, 1, false),
        R_AARCH64_MOVW_UABS_G2 => movw_abs(dest, off, s, 2, true),
        R_AARCH64_MOVW_UABS_G2_NC => movw_abs(dest, off, s, 2, false),
        R_AARCH64_MOVW_UABS_G3 => movw_abs(dest, off, s, 3, false),
        R_AARCH64_MOVW_PREL_G0 => movw_prel(dest, off, s, p, 0, true),
        R_AARCH64_MOVW_PREL_G0_NC => movw_prel(dest, off, s, p, 0, false),
        R_AARCH64_MOVW_PREL_G1 => movw_prel(dest, off, s, p, 1, true),
        R_AARCH64_MOVW_PREL_G1_NC => movw_prel(dest, off, s, p, 1, false),
        R_AARCH64_MOVW_PREL_G2 => movw_prel(dest, off, s, p, 2, true),
        R_AARCH64_MOVW_PREL_G2_NC => movw_prel(dest, off, s, p, 2, false),
        R_AARCH64_MOVW_PREL_G3 => movw_prel(dest, off, s, p, 3, false),
        R_AARCH64_JUMP26 | R_AARCH64_CALL26 => branch26(dest, off, s, p),
        R_AARCH64_CONDBR19 | R_AARCH64_LD_PREL_LO19 => branch19(dest, off, s, p),
        R_AARCH64_TSTBR14 => branch14(dest, off, s, p),
        R_AARCH64_ADR_PREL_LO21 => adr21(dest, off, s.wrapping_sub(p) as i64),
        R_AARCH64_ADR_PREL_PG_HI21 | R_AARCH64_ADR_PREL_PG_HI21_NC => {
            let sp = s & !0xfff;
            let pp = p & !0xfff;
            adr21(dest, off, sp.wrapping_sub(pp) as i64 >> 12)
        }
        R_AARCH64_ADD_ABS_LO12_NC => imm12(dest, off, s, 0),
        R_AARCH64_LDST8_ABS_LO12_NC   => imm12(dest, off, s, 0),
        R_AARCH64_LDST16_ABS_LO12_NC  => imm12(dest, off, s, 1),
        R_AARCH64_LDST32_ABS_LO12_NC  => imm12(dest, off, s, 2),
        R_AARCH64_LDST64_ABS_LO12_NC  => imm12(dest, off, s, 3),
        R_AARCH64_LDST128_ABS_LO12_NC => imm12(dest, off, s, 4),
        _ => Err(RelocError::Unsupported),
    }
}

fn write_u64(dest: &mut [u8], off: usize, v: u64) -> Result<(), RelocError> {
    if off + 8 > dest.len() { return Err(RelocError::DestTooSmall); }
    dest[off..off + 8].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn write_u32(dest: &mut [u8], off: usize, v: u32) -> Result<(), RelocError> {
    if off + 4 > dest.len() { return Err(RelocError::DestTooSmall); }
    dest[off..off + 4].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn write_u16(dest: &mut [u8], off: usize, v: u16) -> Result<(), RelocError> {
    if off + 2 > dest.len() { return Err(RelocError::DestTooSmall); }
    dest[off..off + 2].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn read_insn(dest: &[u8], off: usize) -> Result<u32, RelocError> {
    if off + 4 > dest.len() { return Err(RelocError::DestTooSmall); }
    Ok(u32::from_le_bytes(dest[off..off + 4].try_into().unwrap()))
}

fn write_insn(dest: &mut [u8], off: usize, insn: u32) -> Result<(), RelocError> {
    write_u32(dest, off, insn)
}

fn branch26(dest: &mut [u8], off: usize, s: u64, p: u64) -> Result<(), RelocError> {
    let delta = s.wrapping_sub(p) as i64;
    let imm = delta >> 2;
    if (delta & 3) != 0 || !fits_signed(imm, 26) { return Err(RelocError::OutOfRange); }
    let insn = read_insn(dest, off)?;
    write_insn(dest, off, (insn & !0x03ff_ffff) | (imm as u32 & 0x03ff_ffff))
}

fn branch19(dest: &mut [u8], off: usize, s: u64, p: u64) -> Result<(), RelocError> {
    let delta = s.wrapping_sub(p) as i64;
    let imm = delta >> 2;
    if (delta & 3) != 0 || !fits_signed(imm, 19) { return Err(RelocError::OutOfRange); }
    let insn = read_insn(dest, off)?;
    write_insn(dest, off, (insn & !(0x7ffff << 5)) | ((imm as u32 & 0x7ffff) << 5))
}

fn branch14(dest: &mut [u8], off: usize, s: u64, p: u64) -> Result<(), RelocError> {
    let delta = s.wrapping_sub(p) as i64;
    let imm = delta >> 2;
    if (delta & 3) != 0 || !fits_signed(imm, 14) { return Err(RelocError::OutOfRange); }
    let insn = read_insn(dest, off)?;
    write_insn(dest, off, (insn & !(0x3fff << 5)) | ((imm as u32 & 0x3fff) << 5))
}

fn adr21(dest: &mut [u8], off: usize, v: i64) -> Result<(), RelocError> {
    if !fits_signed(v, 21) { return Err(RelocError::OutOfRange); }
    let imm = v as u32 & 0x1f_ffff;
    let insn = read_insn(dest, off)?;
    let patched = (insn & !((0x3 << 29) | (0x7ffff << 5)))
        | ((imm & 0x3) << 29)
        | (((imm >> 2) & 0x7ffff) << 5);
    write_insn(dest, off, patched)
}

fn imm12(dest: &mut [u8], off: usize, s: u64, shift: u32) -> Result<(), RelocError> {
    let lo = s & 0xfff;
    let imm = (lo >> shift) as u32;
    let insn = read_insn(dest, off)?;
    write_insn(dest, off, (insn & !(0xfff << 10)) | (imm << 10))
}

fn movw_abs(dest: &mut [u8], off: usize, s: u64, chunk: u32, check: bool) -> Result<(), RelocError> {
    if check && chunk < 3 && s >= (1u64 << ((chunk + 1) * 16)) {
        return Err(RelocError::OutOfRange);
    }
    movw(dest, off, ((s >> (chunk * 16)) & 0xffff) as u32)
}

fn movw_prel(dest: &mut [u8], off: usize, s: u64, p: u64, chunk: u32, check: bool) -> Result<(), RelocError> {
    let v = s.wrapping_sub(p) as i64;
    if check && chunk < 3 && !fits_signed(v, (chunk + 1) * 16) {
        return Err(RelocError::OutOfRange);
    }
    movw(dest, off, ((v as u64 >> (chunk * 16)) & 0xffff) as u32)
}

fn movw(dest: &mut [u8], off: usize, imm: u32) -> Result<(), RelocError> {
    let insn = read_insn(dest, off)?;
    write_insn(dest, off, (insn & !(0xffff << 5)) | (imm << 5))
}

fn fits_signed(v: i64, bits: u32) -> bool {
    let min = -(1i64 << (bits - 1));
    let max = (1i64 << (bits - 1)) - 1;
    v >= min && v <= max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_64_simple() {
        let _modules = crate::test_serial::claim();
        let mut buf = [0u8; 16];
        apply(R_X86_64_64, 0, 0x10, 0x1000, &mut buf, 0).unwrap();
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 0x1010);
    }

    #[test]
    fn r_pc32_displacement() {
        let _modules = crate::test_serial::claim();
        // dest_base=0x2000, r_offset=4, sym=0x3000, A=-4 → S + A - P = 0x3000-4-0x2004 = 0xff8
        let mut buf = [0u8; 8];
        apply(R_X86_64_PC32, 4, -4, 0x3000, &mut buf, 0x2000).unwrap();
        let v = i32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(v, 0xff8);
    }

    #[test]
    fn r_32s_oor() {
        let _modules = crate::test_serial::claim();
        let mut buf = [0u8; 8];
        let r = apply(R_X86_64_32S, 0, 0, 0x8000_0000, &mut buf, 0);
        assert_eq!(r.err().unwrap(), RelocError::OutOfRange);
    }

    #[test]
    fn unsupported_type() {
        let _modules = crate::test_serial::claim();
        let mut buf = [0u8; 8];
        assert_eq!(apply(R_X86_64_GOTPCREL, 0, 0, 0, &mut buf, 0).err().unwrap(),
                   RelocError::Unsupported);
    }

    #[test]
    fn r_glob_dat_writes_sym_value() {
        let _modules = crate::test_serial::claim();
        let mut buf = [0u8; 8];
        apply_dynamic(R_X86_64_GLOB_DAT, 0, 0, 0xDEAD_BEEF_CAFE_F00D, 0, &mut buf, 0).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 0xDEAD_BEEF_CAFE_F00D);
    }

    #[test]
    fn r_jump_slot_writes_sym_value() {
        let _modules = crate::test_serial::claim();
        let mut buf = [0u8; 8];
        apply_dynamic(R_X86_64_JUMP_SLOT, 0, 0, 0x1234_5678, 0, &mut buf, 0).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 0x1234_5678);
    }

    #[test]
    fn r_relative_uses_load_bias_plus_addend() {
        let _modules = crate::test_serial::claim();
        let mut buf = [0u8; 8];
        apply_dynamic(R_X86_64_RELATIVE, 0, 0x100, 0, 0x4000_0000, &mut buf, 0).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 0x4000_0100);
    }

    #[test]
    fn aarch64_abs64() {
        let _modules = crate::test_serial::claim();
        let mut buf = [0u8; 8];
        apply_for_machine(elf::EM_AARCH64, R_AARCH64_ABS64, 0, 7, 0x1000, &mut buf, 0).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 0x1007);
    }

    #[test]
    fn aarch64_call26() {
        let _modules = crate::test_serial::claim();
        let mut buf = 0x9400_0000u32.to_le_bytes();
        apply_for_machine(elf::EM_AARCH64, R_AARCH64_CALL26, 0, 0, 0x1080, &mut buf, 0x1000).unwrap();
        assert_eq!(u32::from_le_bytes(buf) & 0x03ff_ffff, 0x20);
    }

    #[test]
    fn aarch64_movw_uabs() {
        let _modules = crate::test_serial::claim();
        let mut buf = 0xd280_0000u32.to_le_bytes();
        apply_for_machine(elf::EM_AARCH64, R_AARCH64_MOVW_UABS_G1_NC, 0, 0, 0x1234_5678, &mut buf, 0).unwrap();
        assert_eq!((u32::from_le_bytes(buf) >> 5) & 0xffff, 0x1234);
    }

    #[test]
    fn aarch64_adrp_add_pair() {
        let _modules = crate::test_serial::claim();
        let mut adrp = 0x9000_0000u32.to_le_bytes();
        let mut add = 0x9100_0000u32.to_le_bytes();
        apply_for_machine(elf::EM_AARCH64, R_AARCH64_ADR_PREL_PG_HI21, 0, 0, 0x401234, &mut adrp, 0x400000).unwrap();
        apply_for_machine(elf::EM_AARCH64, R_AARCH64_ADD_ABS_LO12_NC, 0, 0, 0x401234, &mut add, 0).unwrap();
        assert_ne!(u32::from_le_bytes(adrp), 0x9000_0000);
        assert_eq!((u32::from_le_bytes(add) >> 10) & 0xfff, 0x234);
    }

    #[test]
    fn aarch64_branch_range_checks() {
        let _modules = crate::test_serial::claim();
        let mut buf = 0x1400_0000u32.to_le_bytes();
        let r = apply_for_machine(elf::EM_AARCH64, R_AARCH64_JUMP26, 0, 0, 0x2000_0000, &mut buf, 0);
        assert_eq!(r.err().unwrap(), RelocError::OutOfRange);
    }
}
