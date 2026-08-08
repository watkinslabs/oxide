// BTF v1 raw-blob decoding and cross-record validation.

use alloc::vec::Vec;
use core::ops::Range;
use syscall::errno::Errno;

use super::format::*;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct BtfIndex {
    _types: Vec<BtfType>,
    _strings: Range<usize>,
    _layouts: Vec<Layout>,
    _layout: Option<Range<usize>>,
}

impl BtfIndex {
    #[cfg(test)]
    /// # C: O(1)
    pub(super) fn type_count(&self) -> usize { self._types.len() }
    #[cfg(test)]
    /// # C: O(1)
    pub(super) fn string_range(&self) -> Range<usize> { self._strings.clone() }
    #[cfg(test)]
    /// # C: O(1)
    pub(super) fn layout_range(&self) -> Option<Range<usize>> { self._layout.clone() }
    #[cfg(test)]
    /// # C: O(1)
    pub(super) fn layouts(&self) -> &[Layout] { &self._layouts }
    /// Name of the `BTF_KIND_FUNC` record at `id`, read out of `raw`'s
    /// string section. `None` when `id` names no type or names a kind
    /// other than a function, which is how an attach target that is not a
    /// function is refused without a second type table.
    /// # C: O(name length)
    pub(super) fn func_name<'a>(&self, raw: &'a [u8], id: u32) -> Option<&'a [u8]> {
        let t = id.checked_sub(1).and_then(|i| self._types.get(i as usize))?;
        if t.kind != Kind::Func { return None; }
        let strings = raw.get(self._strings.clone())?;
        let off = t.name_off as usize;
        let end = strings.get(off..)?.iter().position(|b| *b == EMPTY_STRING)?;
        Some(&strings[off..off + end])
    }

    #[cfg(test)]
    /// # C: O(1)
    pub(super) fn type_by_id(&self, id: u32) -> Option<&BtfType> {
        id.checked_sub(1).and_then(|i| self._types.get(i as usize))
    }
    #[cfg(test)]
    /// # C: O(1)
    pub(crate) fn empty_for_test() -> Self {
        Self {
            _types: Vec::new(),
            _strings: 0..0,
            _layouts: Vec::new(),
            _layout: None,
        }
    }
}

struct Reader<'a> { bytes: &'a [u8], pos: usize }

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, pos: 0 } }
    fn u32(&mut self) -> Result<u32, Errno> {
        let end = self.pos.checked_add(WORD_LEN).ok_or(Errno::Einval)?;
        let b: [u8; WORD_LEN] = self.bytes.get(self.pos..end)
            .ok_or(Errno::Einval)?.try_into().map_err(|_| Errno::Einval)?;
        self.pos = end;
        Ok(u32::from_ne_bytes(b))
    }
    fn i32(&mut self) -> Result<i32, Errno> { Ok(self.u32()? as i32) }
    fn done(&self) -> bool { self.pos == self.bytes.len() }
    fn remaining(&self) -> usize { self.bytes.len() - self.pos }
}

fn word(raw: &[u8], off: usize) -> Result<u32, Errno> {
    let end = off.checked_add(WORD_LEN).ok_or(Errno::Einval)?;
    let b: [u8; WORD_LEN] = raw.get(off..end)
        .ok_or(Errno::Einval)?.try_into().map_err(|_| Errno::Einval)?;
    Ok(u32::from_ne_bytes(b))
}

fn half(raw: &[u8], off: usize) -> Result<u16, Errno> {
    let end = off.checked_add(2).ok_or(Errno::Einval)?;
    let b: [u8; 2] = raw.get(off..end)
        .ok_or(Errno::Einval)?.try_into().map_err(|_| Errno::Einval)?;
    Ok(u16::from_ne_bytes(b))
}

fn section(base: usize, off: u32, len: u32, raw_len: usize) -> Result<Range<usize>, Errno> {
    let start = base.checked_add(off as usize).ok_or(Errno::Einval)?;
    let end = start.checked_add(len as usize).ok_or(Errno::Einval)?;
    if end > raw_len { return Err(Errno::Einval); }
    Ok(start..end)
}

fn reserve<T>(v: &mut Vec<T>, count: usize) -> Result<(), Errno> {
    v.try_reserve_exact(count).map_err(|_| Errno::Enomem)
}

fn read_many<T>(
    r: &mut Reader<'_>, count: usize, width: usize,
    mut one: impl FnMut(&mut Reader<'_>) -> Result<T, Errno>,
) -> Result<Vec<T>, Errno> {
    if count.checked_mul(width).is_none_or(|needed| needed > r.remaining()) {
        return Err(Errno::Einval);
    }
    let mut out = Vec::new();
    reserve(&mut out, count)?;
    for _ in 0..count { out.push(one(r)?); }
    Ok(out)
}

fn decode_type(r: &mut Reader<'_>) -> Result<BtfType, Errno> {
    let name_off = r.u32()?;
    let info = r.u32()?;
    let size_or_type = r.u32()?;
    let vlen = (info & INFO_VLEN_MASK) as usize;
    let kind = Kind::from_raw((info >> INFO_KIND_SHIFT) & INFO_KIND_MASK)
        .ok_or(Errno::Einval)?;
    let kind_flag = info & INFO_KIND_FLAG != 0;
    if kind_flag && !matches!(kind, Kind::Struct | Kind::Union | Kind::Enum | Kind::Fwd
        | Kind::DeclTag | Kind::TypeTag | Kind::Enum64) {
        return Err(Errno::Einval);
    }
    let data = match kind {
        Kind::Unknown => return Err(Errno::Einval),
        Kind::Int => {
            if vlen != 0 || kind_flag || size_or_type == 0 {
                return Err(Errno::Einval);
            }
            let raw = r.u32()?;
            if raw & INT_UNUSED_MASK != 0 { return Err(Errno::Einval); }
            let encoding = ((raw >> INT_ENCODING_SHIFT) & INT_ENCODING_MASK) as u8;
            let bit_offset = ((raw >> INT_OFFSET_SHIFT) & INT_OFFSET_MASK) as u8;
            let bits = (raw & INT_BITS_MASK) as u8;
            if encoding & !INT_ENCODING_ALLOWED != 0
                || bit_offset as u32 + bits as u32 > size_or_type.saturating_mul(BITS_PER_BYTE) {
                return Err(Errno::Einval);
            }
            if encoding != 0 && !encoding.is_power_of_two() { return Err(Errno::Eopnotsupp); }
            TypeData::Int { encoding, bit_offset, bits }
        }
        Kind::Ptr => { exact_empty(vlen, kind_flag)?; TypeData::None }
        Kind::Array => {
            exact_empty(vlen, kind_flag)?;
            if size_or_type != 0 { return Err(Errno::Einval); }
            TypeData::Array { elem_type: r.u32()?, index_type: r.u32()?, nelems: r.u32()? }
        }
        Kind::Struct | Kind::Union => TypeData::Members(read_many(r, vlen, MEMBER_DATA_LEN, |r| {
            let name_off = r.u32()?;
            let type_id = r.u32()?;
            let off = r.u32()?;
            Ok(Member {
                name_off, type_id,
                bit_offset: if kind_flag { off & MEMBER_OFFSET_MASK } else { off },
                bitfield_bits: if kind_flag { (off >> MEMBER_BITFIELD_SHIFT) as u8 } else { 0 },
            })
        })?),
        Kind::Enum => {
            if size_or_type == 0 || size_or_type > MAX_ENUM_SIZE
                || !size_or_type.is_power_of_two() {
                return Err(Errno::Einval);
            }
            TypeData::Enum(read_many(r, vlen, ENUM_DATA_LEN, |r| {
                Ok(EnumValue { name_off: r.u32()?, value: r.i32()? })
            })?)
        }
        Kind::Fwd => {
            if vlen != 0 || size_or_type != 0 { return Err(Errno::Einval); }
            TypeData::None
        }
        Kind::Typedef | Kind::Volatile | Kind::Const | Kind::Restrict => {
            exact_empty(vlen, kind_flag)?;
            TypeData::None
        }
        Kind::TypeTag => {
            if vlen != 0 { return Err(Errno::Einval); }
            TypeData::None
        }
        Kind::Func => {
            if kind_flag || vlen > LINKAGE_EXTERN as usize { return Err(Errno::Einval); }
            TypeData::None
        }
        Kind::FuncProto => {
            if kind_flag { return Err(Errno::Einval); }
            TypeData::Params(read_many(r, vlen, PARAM_DATA_LEN, |r| {
                Ok(Param { name_off: r.u32()?, type_id: r.u32()? })
            })?)
        }
        Kind::Var => {
            exact_empty(vlen, kind_flag)?;
            let linkage = r.u32()?;
            if linkage > LINKAGE_EXTERN { return Err(Errno::Einval); }
            TypeData::Var { linkage }
        }
        Kind::Datasec => {
            if kind_flag { return Err(Errno::Einval); }
            TypeData::Datasec(read_many(r, vlen, SECINFO_DATA_LEN, |r| {
                Ok(SecInfo { type_id: r.u32()?, offset: r.u32()?, size: r.u32()? })
            })?)
        }
        Kind::Float => {
            if !matches!(size_or_type, FLOAT16_SIZE | FLOAT32_SIZE | FLOAT64_SIZE
                | FLOAT96_SIZE | FLOAT128_SIZE) {
                return Err(Errno::Einval);
            }
            exact_empty(vlen, kind_flag)?;
            TypeData::None
        }
        Kind::DeclTag => {
            if vlen != 0 { return Err(Errno::Einval); }
            TypeData::DeclTag { component_idx: r.i32()? }
        }
        Kind::Enum64 => {
            if size_or_type == 0 || size_or_type > MAX_ENUM_SIZE
                || !size_or_type.is_power_of_two() {
                return Err(Errno::Einval);
            }
            TypeData::Enum64(read_many(r, vlen, ENUM64_DATA_LEN, |r| {
                let name_off = r.u32()?;
                let lo = r.u32()? as u64;
                let hi = r.u32()? as u64;
                Ok(Enum64Value { name_off, value: lo | hi << u32::BITS })
            })?)
        }
    };
    Ok(BtfType { name_off, kind, kind_flag, size_or_type, data })
}

fn exact_empty(vlen: usize, kind_flag: bool) -> Result<(), Errno> {
    if vlen != 0 || kind_flag { Err(Errno::Einval) } else { Ok(()) }
}

fn validate_sections(raw_len: usize, header_len: usize, ranges: &[Range<usize>])
    -> Result<(), Errno>
{
    let mut ordered = Vec::new();
    reserve(&mut ordered, ranges.len())?;
    ordered.extend_from_slice(ranges);
    ordered.sort_unstable_by_key(|r| (r.start, r.end));
    let mut next = header_len;
    for r in ordered {
        if r.start != next { return Err(Errno::Einval); }
        next = r.end;
    }
    if next == raw_len { Ok(()) } else { Err(Errno::Einval) }
}

fn decode_layouts(raw: &[u8], range: &Range<usize>) -> Result<Vec<Layout>, Errno> {
    if range.len() < LAYOUT_DATA_LEN || range.len() % LAYOUT_DATA_LEN != 0 {
        return Err(Errno::Einval);
    }
    let mut layouts = Vec::new();
    reserve(&mut layouts, range.len() / LAYOUT_DATA_LEN)?;
    for b in raw[range.clone()].chunks_exact(LAYOUT_DATA_LEN) {
        layouts.push(Layout {
            info_size: b[0],
            elem_size: b[1],
            flags: u16::from_ne_bytes([b[2], b[3]]),
        });
    }
    Ok(layouts)
}

/// Decode and validate one native-endian BTF v1 blob. # C: O(bytes + types²)
pub(super) fn parse(raw: &[u8]) -> Result<BtfIndex, Errno> {
    if raw.len() < LEGACY_HEADER_LEN || raw.len() > MAX_RAW_SIZE
        || half(raw, HEADER_MAGIC_OFF)? != MAGIC {
        return Err(Errno::Einval);
    }
    if raw[HEADER_VERSION_OFF] != VERSION || raw[HEADER_FLAGS_OFF] != FLAGS_NONE {
        return Err(Errno::Eopnotsupp);
    }
    let header_len = word(raw, HEADER_LEN_OFF)? as usize;
    if header_len < LEGACY_HEADER_LEN || header_len > raw.len() {
        return Err(Errno::Einval);
    }
    if header_len > HEADER_LEN && raw[HEADER_LEN..header_len].iter().any(|b| *b != 0) {
        return Err(Errno::E2big);
    }
    let type_off = word(raw, HEADER_TYPE_OFF_OFF)?;
    let type_len = word(raw, HEADER_TYPE_LEN_OFF)?;
    let str_off = word(raw, HEADER_STR_OFF_OFF)?;
    let str_len = word(raw, HEADER_STR_LEN_OFF)?;
    if type_off as usize % WORD_LEN != 0 || type_len as usize % WORD_LEN != 0
        || type_len == 0 || str_len == 0 {
        return Err(Errno::Einval);
    }
    let tr = section(header_len, type_off, type_len, raw.len())?;
    let sr = section(header_len, str_off, str_len, raw.len())?;
    let layout = if header_len >= HEADER_LEN {
        let off = word(raw, HEADER_LAYOUT_OFF_OFF)?;
        let len = word(raw, HEADER_LAYOUT_LEN_OFF)?;
        if len == 0 { None }
        else {
            if off as usize % WORD_LEN != 0 { return Err(Errno::Einval); }
            Some(section(header_len, off, len, raw.len())?)
        }
    } else { None };
    let mut sections = Vec::new();
    reserve(&mut sections, if layout.is_some() { 3 } else { 2 })?;
    sections.push(tr.clone());
    sections.push(sr.clone());
    if let Some(lr) = &layout { sections.push(lr.clone()); }
    validate_sections(raw.len(), header_len, &sections)?;
    if header_len < HEADER_LEN && sr.end != raw.len()
        || raw[sr.start] != EMPTY_STRING || raw[sr.end - 1] != EMPTY_STRING {
        return Err(Errno::Einval);
    }
    let layouts = match &layout {
        Some(range) => decode_layouts(raw, range)?,
        None => Vec::new(),
    };
    let mut r = Reader::new(&raw[tr]);
    let mut types = Vec::new();
    while !r.done() {
        if types.len() == MAX_TYPE_ID { return Err(Errno::Einval); }
        reserve(&mut types, 1)?;
        types.push(decode_type(&mut r)?);
    }
    super::validate::validate_all(&types, &raw[sr.clone()])?;
    Ok(BtfIndex {
        _types: types,
        _strings: sr,
        _layouts: layouts,
        _layout: layout,
    })
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
