// `desc_struct` packing for one LDT entry, plus the two "this entry is
// empty" predicates the write ladder consults.
//
// The 8 bytes are consumed directly by the CPU through LDTR. Field order and
// bit positions follow the architectural segment-descriptor layout:
//
//   bits  0..15  limit[15:0]
//   bits 16..31  base[15:0]
//   bits 32..39  base[23:16]
//   bits 40..43  type
//   bit  44      S    (1 = code/data, 0 = system)
//   bits 45..46  DPL
//   bit  47      P    (present)
//   bits 48..51  limit[19:16]
//   bit  52      AVL
//   bit  53      L    (64-bit code segment)
//   bit  54      D/B
//   bit  55      G    (granularity)
//   bits 56..63  base[31:24]

use super::UserDesc;

/// Bytes in one packed descriptor.
pub const DESC_BYTES: usize = 8;

/// Bit offsets of every packed field. Named because a bare `40` in a shift
/// is exactly the silent-privilege-bug bait this module exists to prevent.
const OFF_LIMIT_LO: u32 = 0;
const OFF_BASE_LO: u32 = 16;
const OFF_BASE_MID: u32 = 32;
const OFF_TYPE: u32 = 40;
const OFF_S: u32 = 44;
const OFF_DPL: u32 = 45;
const OFF_P: u32 = 47;
const OFF_LIMIT_HI: u32 = 48;
const OFF_AVL: u32 = 52;
const OFF_L: u32 = 53;
const OFF_D: u32 = 54;
const OFF_G: u32 = 55;
const OFF_BASE_HI: u32 = 56;

/// `type` bit meanings for a code/data (`S == 1`) descriptor.
const TYPE_ACCESSED: u64 = 1 << 0;
const TYPE_WRITE_READ_SHIFT: u32 = 1;
const TYPE_CONTENTS_SHIFT: u32 = 2;

/// Descriptor privilege level every user LDT entry is pinned to. An LDT
/// entry is reachable only from the process that installed it, and installing
/// a ring-0 descriptor there would be a direct privilege escalation, so this
/// is a constant and never derived from the caller's request.
const USER_DPL: u64 = 3;

/// A `user_desc` that means "clear this entry" under the ORIGINAL write
/// semantics, mirroring the reference's `LDT_empty`: a not-present,
/// read/exec-only, 16-bit, byte-granular, zero-base, zero-limit, unusable
/// data segment. `lm` is deliberately ignored — a 32-bit caller leaves it
/// uninitialised.
/// # C: O(1)
pub fn ldt_empty(info: &UserDesc) -> bool {
    info.base_addr == 0
        && info.limit == 0
        && info.contents == super::CONTENTS_DATA
        && info.read_exec_only
        && !info.seg_32bit
        && !info.limit_in_pages
        && info.seg_not_present
        && !info.useable
}

/// An all-zero `user_desc`. Programs expect this to mean "no segment at
/// all"; it is the shape `ldt_empty` deliberately does NOT match (it has
/// `read_exec_only == 0` and `seg_not_present == 0`), which is why the
/// reference carries both predicates.
/// # C: O(1)
pub fn ldt_zero(info: &UserDesc) -> bool {
    info.base_addr == 0
        && info.limit == 0
        && info.contents == super::CONTENTS_DATA
        && !info.read_exec_only
        && !info.seg_32bit
        && !info.limit_in_pages
        && !info.seg_not_present
        && !info.useable
}

/// Pack one `user_desc` into its 8-byte descriptor.
///
/// `oldmode` forces `AVL` to zero: the original sub-function had no
/// `useable` bit, so accepting one there would let a caller set a bit the
/// contract it invoked never described.
///
/// The `L` bit is hardwired to zero. It selects a 64-bit code segment, and a
/// user-installable one would change how the CPU classifies the caller's
/// mode; `sysret` would then reload a different code segment than the one
/// that entered the kernel.
/// # C: O(1)
pub fn fill_ldt(info: &UserDesc, oldmode: bool) -> u64 {
    let mut d: u64 = 0;
    d |= ((info.limit & 0xFFFF) as u64) << OFF_LIMIT_LO;
    d |= ((info.base_addr & 0x0000_FFFF) as u64) << OFF_BASE_LO;
    d |= (((info.base_addr & 0x00FF_0000) >> 16) as u64) << OFF_BASE_MID;

    // type = accessed | (writable/readable) | contents. The accessed bit is
    // pre-set so the table never needs to be writable to the CPU.
    let mut ty: u64 = TYPE_ACCESSED;
    ty |= ((!info.read_exec_only) as u64) << TYPE_WRITE_READ_SHIFT;
    ty |= (info.contents as u64) << TYPE_CONTENTS_SHIFT;
    d |= (ty & 0xF) << OFF_TYPE;

    d |= 1u64 << OFF_S;
    d |= USER_DPL << OFF_DPL;
    d |= ((!info.seg_not_present) as u64) << OFF_P;
    d |= (((info.limit & 0x000F_0000) >> 16) as u64) << OFF_LIMIT_HI;
    d |= ((info.useable && !oldmode) as u64) << OFF_AVL;
    d |= 0u64 << OFF_L;
    d |= (info.seg_32bit as u64) << OFF_D;
    d |= (info.limit_in_pages as u64) << OFF_G;
    d |= (((info.base_addr & 0xFF00_0000) >> 24) as u64) << OFF_BASE_HI;
    d
}
