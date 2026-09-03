//! Bounded DWARF call-frame record parsing for builtin ELF modules.
//!
//! Wine's `unwind_builtin_dll` locates an FDE in `.eh_frame` and interprets
//! its CIE/FDE instructions.  This module owns the file-format boundary only:
//! it never follows a target address or reads process memory.  The runtime
//! owner can therefore use it for a fault-aware lookup before applying CFA
//! rules to a register context.

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DwarfError {
    Truncated,
    Overflow,
    UnsupportedEncoding,
    InvalidRecord,
}

pub type Result<T> = core::result::Result<T, DwarfError>;

pub const DW_EH_PE_ABSPTR: u8 = 0x00;
pub const DW_EH_PE_ULEB128: u8 = 0x01;
pub const DW_EH_PE_UDATA2: u8 = 0x02;
pub const DW_EH_PE_UDATA4: u8 = 0x03;
pub const DW_EH_PE_UDATA8: u8 = 0x04;
pub const DW_EH_PE_SLEB128: u8 = 0x09;
pub const DW_EH_PE_SDATA2: u8 = 0x0a;
pub const DW_EH_PE_SDATA4: u8 = 0x0b;
pub const DW_EH_PE_SDATA8: u8 = 0x0c;
pub const DW_EH_PE_PCREL: u8 = 0x10;
pub const DW_EH_PE_DATAREL: u8 = 0x30;
pub const DW_EH_PE_OMIT: u8 = 0xff;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EhBases {
    pub text: u64,
    pub data: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallFrameRecord {
    pub offset: usize,
    pub end: usize,
    pub cie_offset: Option<usize>,
    pub code_start: Option<u64>,
    pub code_length: Option<u64>,
    pub body: Vec<u8>,
}

/// The validated instruction stream and alignment factors for one FDE.
/// CIE initialization instructions precede the FDE instructions because the
/// DWARF state machine starts with the CIE state for every frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameProgram {
    pub code_align: u64,
    pub data_align: i64,
    pub instructions: Vec<u8>,
}

/// Decode one bounded ULEB128 value.
pub fn uleb128(input: &[u8]) -> Result<(u64, usize)> {
    let mut value = 0u64;
    for (index, &byte) in input.iter().enumerate() {
        if index >= 10 { return Err(DwarfError::Overflow); }
        let shift = index * 7;
        let bits = (byte & 0x7f) as u64;
        if shift == 63 && bits > 1 { return Err(DwarfError::Overflow); }
        value |= bits.checked_shl(shift as u32).ok_or(DwarfError::Overflow)?;
        if byte & 0x80 == 0 { return Ok((value, index + 1)); }
        if index == 9 { return Err(DwarfError::Overflow); }
    }
    Err(DwarfError::Truncated)
}

/// Decode one bounded SLEB128 value.
pub fn sleb128(input: &[u8]) -> Result<(i64, usize)> {
    let (unsigned, used) = uleb128(input)?;
    let last = input[used - 1];
    if used == 10 && unsigned > 0x7fff_ffff_ffff_ffff && last & 0x40 == 0 {
        return Err(DwarfError::Overflow);
    }
    let shift = (used * 7).min(64);
    let value = if shift < 64 && last & 0x40 != 0 {
        (unsigned | (!0u64 << shift)) as i64
    } else { unsigned as i64 };
    Ok((value, used))
}

/// Decode a DW_EH_PE pointer without dereferencing indirect encodings.
pub fn encoded_pointer(input: &[u8], encoding: u8, address: u64, bases: EhBases)
    -> Result<(u64, usize)>
{
    if encoding == DW_EH_PE_OMIT { return Err(DwarfError::UnsupportedEncoding); }
    if encoding & 0x80 != 0 { return Err(DwarfError::UnsupportedEncoding); }
    let (value, used) = match encoding & 0x0f {
        DW_EH_PE_ABSPTR => (read_u64(input)? as i128, 8),
        DW_EH_PE_ULEB128 => { let (v, n) = uleb128(input)?; (v as i128, n) }
        DW_EH_PE_UDATA2 => (read_u16(input)? as i128, 2),
        DW_EH_PE_UDATA4 => (read_u32(input)? as i128, 4),
        DW_EH_PE_UDATA8 => (read_u64(input)? as i128, 8),
        DW_EH_PE_SLEB128 => { let (v, n) = sleb128(input)?; (v as i128, n) }
        DW_EH_PE_SDATA2 => (read_u16(input)? as i16 as i128, 2),
        DW_EH_PE_SDATA4 => (read_u32(input)? as i32 as i128, 4),
        DW_EH_PE_SDATA8 => (read_u64(input)? as i64 as i128, 8),
        _ => return Err(DwarfError::UnsupportedEncoding),
    };
    let base = match encoding & 0x70 {
        0x00 => 0,
        DW_EH_PE_PCREL => address,
        DW_EH_PE_DATAREL => bases.data,
        _ => return Err(DwarfError::UnsupportedEncoding),
    };
    let result = (base as i128).checked_add(value).ok_or(DwarfError::Overflow)?;
    if !(0..=u64::MAX as i128).contains(&result) { return Err(DwarfError::Overflow); }
    Ok((result as u64, used))
}

/// Walk `.eh_frame` records and return their bounded locations.
pub fn records(section: &[u8]) -> Result<Vec<CallFrameRecord>> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < section.len() {
        let length = read_u32(&section[offset..])? as usize;
        if length == 0 { break; }
        let end = offset.checked_add(4).and_then(|v| v.checked_add(length))
            .ok_or(DwarfError::Overflow)?;
        if end > section.len() || length < 4 { return Err(DwarfError::InvalidRecord); }
        let id = read_u32(&section[offset + 4..])?;
        let cie_offset = if id == 0 {
            None
        } else {
            let cie = (offset + 4).checked_sub(id as usize)
                .ok_or(DwarfError::InvalidRecord)?;
            Some(cie)
        };
        result.push(CallFrameRecord {
            offset, end, cie_offset, code_start: None, code_length: None,
            body: section[offset + 8..end].to_vec(),
        });
        offset = end;
    }
    Ok(result)
}

/// Find and decode the FDE covering `ip`. The returned record's code range is
/// absolute in the same address space as `ip`; CFA instruction execution is
/// intentionally left to the register-context owner.
pub fn find_fde<'a>(section: &'a [u8], section_address: u64, ip: u64, bases: EhBases)
    -> Result<Option<CallFrameRecord>>
{
    let entries = records(section)?;
    for entry in &entries {
        let Some(cie_offset) = entry.cie_offset else { continue; };
        let Some(cie) = entries.iter().find(|candidate| candidate.offset == cie_offset) else {
            return Err(DwarfError::InvalidRecord);
        };
        let encoding = cie_fde_encoding(cie)?;
        let start_offset = entry.offset.checked_add(8).ok_or(DwarfError::Overflow)?;
        let start_at = section_address.checked_add(start_offset as u64)
            .ok_or(DwarfError::Overflow)?;
        let (start, start_used) = encoded_pointer(&entry.body, encoding, start_at, bases)?;
        let range_encoding = encoding & 0x0f;
        let range_at = start_at.checked_add(start_used as u64).ok_or(DwarfError::Overflow)?;
        let (length, _) = encoded_pointer(&entry.body[start_used..], range_encoding, range_at, bases)?;
        let end = start.checked_add(length).ok_or(DwarfError::Overflow)?;
        if ip >= start && ip < end {
            let mut result = entry.clone(); result.code_start = Some(start); result.code_length = Some(length);
            return Ok(Some(result));
        }
    }
    Ok(None)
}

/// Build the bounded CIE+FDE program for a record returned by `find_fde`.
/// Pointer fields are decoded and skipped using the same encoding rules as
/// lookup; augmentation payloads are never exposed as instructions.
pub fn frame_program(section: &[u8], fde: &CallFrameRecord) -> Result<FrameProgram> {
    let cie_offset = fde.cie_offset.ok_or(DwarfError::InvalidRecord)?;
    let entries = records(section)?;
    let cie = entries.iter().find(|entry| entry.offset == cie_offset)
        .ok_or(DwarfError::InvalidRecord)?;
    let (code_align, data_align, cie_instructions, encoding, augmentation_z) = parse_cie(cie)?;
    let fde_body = fde.body.as_slice();
    let start_at = (fde.offset as u64).checked_add(8).ok_or(DwarfError::Overflow)?;
    let (_, used) = encoded_pointer(fde_body, encoding, start_at, EhBases { text: 0, data: 0 })?;
    let range_encoding = encoding & 0x0f;
    let range_at = start_at.checked_add(used as u64).ok_or(DwarfError::Overflow)?;
    let (_, range_used) = encoded_pointer(&fde_body[used..], range_encoding, range_at,
        EhBases { text: 0, data: 0 })?;
    let mut cursor = used.checked_add(range_used).ok_or(DwarfError::Overflow)?;
    if augmentation_z {
        let (length, count) = uleb128(&fde_body[cursor..])?;
        cursor = cursor.checked_add(count).and_then(|v| v.checked_add(length as usize))
            .ok_or(DwarfError::Overflow)?;
        if cursor > fde_body.len() { return Err(DwarfError::Truncated); }
    }
    let mut instructions = cie_instructions;
    instructions.extend_from_slice(fde_body.get(cursor..).ok_or(DwarfError::Truncated)?);
    Ok(FrameProgram { code_align, data_align, instructions })
}

fn cie_fde_encoding(cie: &CallFrameRecord) -> Result<u8> {
    Ok(parse_cie(cie)?.3)
}

fn parse_cie(cie: &CallFrameRecord) -> Result<(u64, i64, Vec<u8>, u8, bool)> {
    let body = cie.body.as_slice();
    let version = *body.first().ok_or(DwarfError::Truncated)?;
    let nul = body.get(1..).ok_or(DwarfError::Truncated)?.iter().position(|&b| b == 0)
        .map(|n| n + 1).ok_or(DwarfError::InvalidRecord)?;
    let augmentation = &body[1..nul];
    let mut cursor = nul + 1;
    let (code_align, used) = uleb128(&body[cursor..])?; cursor += used;
    let (data_align, used) = sleb128(&body[cursor..])?; cursor += used;
    if version == 1 { cursor = cursor.checked_add(1).ok_or(DwarfError::Overflow)?; }
    else { let (_, used) = uleb128(&body[cursor..])?; cursor += used; }
    let mut encoding = DW_EH_PE_ABSPTR;
    let mut augmentation_end = None;
    for &kind in augmentation {
        match kind {
            b'z' => { let (length, used) = uleb128(&body[cursor..])?; cursor += used;
                augmentation_end = Some(cursor.checked_add(length as usize).ok_or(DwarfError::Overflow)?); }
            b'L' => cursor = cursor.checked_add(1).ok_or(DwarfError::Overflow)?,
            b'P' => { let kind = *body.get(cursor).ok_or(DwarfError::Truncated)?; cursor += 1;
                let (_, used) = encoded_pointer(&body[cursor..], kind, 0, EhBases { text: 0, data: 0 })?; cursor += used; }
            b'R' => { encoding = *body.get(cursor).ok_or(DwarfError::Truncated)?; cursor += 1; }
            b'S' => {}
            _ => return Err(DwarfError::InvalidRecord),
        }
    }
    if let Some(end) = augmentation_end {
        if cursor > end || end > body.len() { return Err(DwarfError::InvalidRecord); }
        cursor = end;
    }
    Ok((code_align, data_align, body.get(cursor..).ok_or(DwarfError::Truncated)?.to_vec(),
        encoding, augmentation.iter().any(|&kind| kind == b'z')))
}

fn read_u16(input: &[u8]) -> Result<u16> {
    let bytes = input.get(..2).ok_or(DwarfError::Truncated)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}
fn read_u32(input: &[u8]) -> Result<u32> {
    let bytes = input.get(..4).ok_or(DwarfError::Truncated)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
fn read_u64(input: &[u8]) -> Result<u64> {
    let bytes = input.get(..8).ok_or(DwarfError::Truncated)?;
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| DwarfError::Truncated)?))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::*;

    #[test]
    fn decodes_signed_and_unsigned_leb_values() {
        assert_eq!(uleb128(&[0xe5, 0x8e, 0x26]), Ok((624485, 3)));
        assert_eq!(sleb128(&[0x9b, 0xf1, 0x59]), Ok((-624485, 3)));
    }

    #[test]
    fn rejects_unterminated_or_overlong_leb() {
        assert_eq!(uleb128(&[0x80]), Err(DwarfError::Truncated));
        assert_eq!(uleb128(&[0x80; 10]), Err(DwarfError::Overflow));
    }

    #[test]
    fn decodes_pcrel_pointer_without_dereference() {
        assert_eq!(encoded_pointer(&[0xfc, 0xff, 0xff, 0xff], DW_EH_PE_PCREL | DW_EH_PE_SDATA4,
            0x1000, EhBases { text: 0, data: 0 }), Ok((0xffc, 4)));
    }

    #[test]
    fn walks_cie_and_fde_records() {
        let section = [4, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4];
        let parsed = records(&section).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].cie_offset, Some(8));
        assert_eq!(parsed[1].body, vec![1, 2, 3, 4]);
    }

    #[test]
    fn finds_fde_covering_instruction_pointer() {
        let mut section = vec![13, 0, 0, 0, 0, 0, 0, 0, 3, b'z', b'R', 0, 1, 0x78, 16, 1, 3];
        section.extend_from_slice(&[13, 0, 0, 0, 21, 0, 0, 0, 0x00, 0x10, 0, 0, 0x20, 0, 0, 0, 0]);
        let entries = records(&section).unwrap();
        assert_eq!(entries[0].body, vec![3, b'z', b'R', 0, 1, 0x78, 16, 1, 3]);
        assert_eq!(entries[1].body.len(), 9);
        assert_eq!(cie_fde_encoding(&entries[0]), Ok(3));
        let fde = find_fde(&section, 0, 0x1010, EhBases { text: 0, data: 0 }).unwrap().unwrap();
        assert_eq!(fde.code_start, Some(0x1000)); assert_eq!(fde.code_length, Some(0x20));
        let program = frame_program(&section, &fde).unwrap();
        assert_eq!(program.code_align, 1); assert_eq!(program.data_align, -8);
        assert!(program.instructions.is_empty());
        section[25] = 0xff;
        assert_eq!(find_fde(&section, 0, 0x1010, EhBases { text: 0, data: 0 }).unwrap(), None);
    }
}
