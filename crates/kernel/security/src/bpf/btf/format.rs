// Raw BTF v1 layout constants and decoded records.

use alloc::vec::Vec;

pub(super) const MAGIC: u16 = 0xeb9f;
pub(super) const VERSION: u8 = 1;
pub(super) const FLAGS_NONE: u8 = 0;

pub(super) const LEGACY_HEADER_LEN: usize = 24;
pub(super) const HEADER_LEN: usize = 32;
pub(super) const HEADER_MAGIC_OFF: usize = 0;
pub(super) const HEADER_VERSION_OFF: usize = 2;
pub(super) const HEADER_FLAGS_OFF: usize = 3;
pub(super) const HEADER_LEN_OFF: usize = 4;
pub(super) const HEADER_TYPE_OFF_OFF: usize = 8;
pub(super) const HEADER_TYPE_LEN_OFF: usize = 12;
pub(super) const HEADER_STR_OFF_OFF: usize = 16;
pub(super) const HEADER_STR_LEN_OFF: usize = 20;
pub(super) const HEADER_LAYOUT_OFF_OFF: usize = 24;
pub(super) const HEADER_LAYOUT_LEN_OFF: usize = 28;

pub(super) const WORD_LEN: usize = 4;
#[cfg(test)]
pub(super) const INT_DATA_LEN: usize = 4;
pub(super) const MEMBER_DATA_LEN: usize = 12;
pub(super) const ENUM_DATA_LEN: usize = 8;
pub(super) const PARAM_DATA_LEN: usize = 8;
pub(super) const SECINFO_DATA_LEN: usize = 12;
pub(super) const ENUM64_DATA_LEN: usize = 12;
pub(super) const LAYOUT_DATA_LEN: usize = 4;

pub(super) const INFO_VLEN_MASK: u32 = 0x00ff_ffff;
pub(super) const INFO_KIND_SHIFT: u32 = 24;
pub(super) const INFO_KIND_MASK: u32 = 0x7f;
pub(super) const INFO_KIND_FLAG: u32 = 1 << 31;
pub(super) const MEMBER_OFFSET_MASK: u32 = 0x00ff_ffff;
pub(super) const MEMBER_BITFIELD_SHIFT: u32 = 24;

pub(super) const INT_ENCODING_SHIFT: u32 = 24;
pub(super) const INT_ENCODING_MASK: u32 = 0x0f;
pub(super) const INT_OFFSET_SHIFT: u32 = 16;
pub(super) const INT_OFFSET_MASK: u32 = 0xff;
pub(super) const INT_BITS_MASK: u32 = 0xff;
pub(super) const INT_UNUSED_MASK: u32 = 0xf000_0000 | 0x0000_ff00;
pub(super) const INT_ENCODING_ALLOWED: u8 = 0x07;

pub(super) const MAX_TYPE_ID: usize = 0x000f_ffff;
pub(super) const MAX_NAME_OFFSET: usize = 0x00ff_ffff;
pub(super) const MAX_RAW_SIZE: usize = 16 * 1024 * 1024;
pub(super) const MAX_RESOLVE_DEPTH: usize = 32;
pub(super) const MAX_NAME_LEN: usize = 128;
pub(super) const TYPE_ID_VOID: u32 = 0;
pub(super) const EMPTY_NAME_OFFSET: u32 = 0;
pub(super) const EMPTY_STRING: u8 = 0;
pub(super) const BITS_PER_BYTE: u32 = 8;
pub(super) const MAX_ENUM_SIZE: u32 = 8;
pub(super) const FLOAT16_SIZE: u32 = 2;
pub(super) const FLOAT32_SIZE: u32 = 4;
pub(super) const FLOAT64_SIZE: u32 = 8;
pub(super) const FLOAT96_SIZE: u32 = 12;
pub(super) const FLOAT128_SIZE: u32 = 16;

#[cfg(test)]
pub(super) const LINKAGE_STATIC: u32 = 0;
#[cfg(test)]
pub(super) const LINKAGE_GLOBAL: u32 = 1;
pub(super) const LINKAGE_EXTERN: u32 = 2;
pub(super) const DECL_TAG_TYPE_COMPONENT: i32 = -1;
pub(super) const VISIT_OPEN: u8 = 1;
pub(super) const VISIT_DONE: u8 = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum Kind {
    Unknown = 0, Int = 1, Ptr = 2, Array = 3, Struct = 4, Union = 5,
    Enum = 6, Fwd = 7, Typedef = 8, Volatile = 9, Const = 10,
    Restrict = 11, Func = 12, FuncProto = 13, Var = 14, Datasec = 15,
    Float = 16, DeclTag = 17, TypeTag = 18, Enum64 = 19,
}

impl Kind {
    /// # C: O(1)
    pub(super) fn from_raw(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Unknown, 1 => Self::Int, 2 => Self::Ptr, 3 => Self::Array,
            4 => Self::Struct, 5 => Self::Union, 6 => Self::Enum, 7 => Self::Fwd,
            8 => Self::Typedef, 9 => Self::Volatile, 10 => Self::Const,
            11 => Self::Restrict, 12 => Self::Func, 13 => Self::FuncProto,
            14 => Self::Var, 15 => Self::Datasec, 16 => Self::Float,
            17 => Self::DeclTag, 18 => Self::TypeTag, 19 => Self::Enum64,
            _ => return None,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Member {
    pub name_off: u32,
    pub type_id: u32,
    pub bit_offset: u32,
    pub bitfield_bits: u8,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct EnumValue {
    pub name_off: u32,
    pub value: i32,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Enum64Value {
    pub name_off: u32,
    pub value: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Param {
    pub name_off: u32,
    pub type_id: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct SecInfo {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct Layout {
    pub info_size: u8,
    pub elem_size: u8,
    pub flags: u16,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum TypeData {
    None,
    Int { encoding: u8, bit_offset: u8, bits: u8 },
    Array { elem_type: u32, index_type: u32, nelems: u32 },
    Members(Vec<Member>),
    Enum(Vec<EnumValue>),
    Params(Vec<Param>),
    Var { linkage: u32 },
    Datasec(Vec<SecInfo>),
    DeclTag { component_idx: i32 },
    Enum64(Vec<Enum64Value>),
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct BtfType {
    pub name_off: u32,
    pub kind: Kind,
    pub kind_flag: bool,
    pub size_or_type: u32,
    pub data: TypeData,
}
