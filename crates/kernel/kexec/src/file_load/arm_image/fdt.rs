// A flattened device tree, decoded into a tree and re-flattened.
//
// WHY A DECODE/RE-FLATTEN AND NOT AN IN-PLACE EDIT. The reference edits the
// blob in place because C has no other option: `fdt_open_into` copies the tree
// into a larger buffer with slack, every `fdt_setprop` memmoves the struct
// block, and `fdt_pack` squeezes the slack back out at the end. The OBSERVABLE
// result is a tree with a known set of properties added, changed and removed —
// which is what is mirrored here. Decoding once and emitting once reaches the
// same tree without a manual free-space calculation, and makes every edit a
// value change a test can assert on rather than a byte offset.
//
// What is preserved verbatim: the memory reservation block, `boot_cpuid_phys`,
// every node, every property and every property value, in tree order. What is
// NOT preserved: the string-table layout and any `FDT_NOP` padding, neither of
// which any consumer can observe — the format defines lookup by name.
//
// Module manifest:
// - `build`: the re-flatten — header, reservation block, struct block, strings.
// - `edit`:  path lookup and the property/reservation edits a handover makes.
//
// Ungated. A tree handed to the new kernel with `linux,initrd-start` written
// at the wrong width, or a string table whose offsets are one entry out, boots
// a kernel that finds no root filesystem and says nothing about why.

extern crate alloc;
use alloc::vec::Vec;

use crate::validate::{Error, KResult};

pub mod build;
pub mod edit;

/// `0xd00dfeed`, big-endian at offset 0 of every blob.
pub const FDT_MAGIC: u32 = 0xd00d_feed;
/// The version this emits.
pub const FDT_VERSION: u32 = 17;
/// The oldest reader that can consume what this emits.
pub const FDT_LAST_COMP_VERSION: u32 = 16;
/// Bytes of header, which is also the version-17 `off_mem_rsvmap` floor.
pub const FDT_HEADER_SIZE: usize = 40;
/// Reservation entries and the reservation block are 8-byte aligned.
pub const FDT_RSV_ALIGN: usize = 8;
/// Struct-block tokens and property headers are 4-byte aligned.
pub const FDT_TOKEN_ALIGN: usize = 4;

/// Struct-block token: a node begins, followed by its NUL-terminated name.
pub const FDT_BEGIN_NODE: u32 = 0x1;
/// Struct-block token: the current node ends.
pub const FDT_END_NODE: u32 = 0x2;
/// Struct-block token: a property, followed by length, name offset, value.
pub const FDT_PROP: u32 = 0x3;
/// Struct-block token: padding, skipped.
pub const FDT_NOP: u32 = 0x4;
/// Struct-block token: the block ends.
pub const FDT_END: u32 = 0x9;

/// Header field offsets, in header order.
pub const OFF_MAGIC: usize = 0;
/// See [`OFF_MAGIC`].
pub const OFF_TOTALSIZE: usize = 4;
/// See [`OFF_MAGIC`].
pub const OFF_DT_STRUCT: usize = 8;
/// See [`OFF_MAGIC`].
pub const OFF_DT_STRINGS: usize = 12;
/// See [`OFF_MAGIC`].
pub const OFF_MEM_RSVMAP: usize = 16;
/// See [`OFF_MAGIC`].
pub const OFF_VERSION: usize = 20;
/// See [`OFF_MAGIC`].
pub const OFF_LAST_COMP_VERSION: usize = 24;
/// See [`OFF_MAGIC`].
pub const OFF_BOOT_CPUID_PHYS: usize = 28;
/// See [`OFF_MAGIC`].
pub const OFF_SIZE_DT_STRINGS: usize = 32;
/// See [`OFF_MAGIC`].
pub const OFF_SIZE_DT_STRUCT: usize = 36;

/// A property: a name and its opaque value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prop {
    /// Property name, without a terminating NUL.
    pub name: Vec<u8>,
    /// Value bytes exactly as they appear in the blob.
    pub val: Vec<u8>,
}

/// A node: a name, its properties in order, and its children in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    /// Node name, without a terminating NUL. Empty for the root.
    pub name: Vec<u8>,
    /// Properties, in blob order.
    pub props: Vec<Prop>,
    /// Child nodes, in blob order.
    pub children: Vec<Node>,
}

impl Node {
    /// An empty node with the given name.
    /// # C: O(len)
    pub fn new(name: &[u8]) -> Self {
        Node { name: name.to_vec(), props: Vec::new(), children: Vec::new() }
    }
}

/// A whole tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fdt {
    /// `boot_cpuid_phys`, carried through unchanged.
    pub boot_cpuid_phys: u32,
    /// The memory reservation block: `(address, size)` pairs, without the
    /// terminating zero entry.
    pub rsv: Vec<(u64, u64)>,
    /// The root node.
    pub root: Node,
}

/// Decode a blob.
///
/// `EINVAL` for anything the format does not permit — a bad magic, a version
/// no reader here understands, a block that runs off the end, an unbalanced
/// node nesting. A malformed tree is refused rather than partially accepted:
/// the tree is what the next kernel navigates by, and half of one is worse
/// than none.
/// # C: O(totalsize)
pub fn parse(blob: &[u8]) -> KResult<Fdt> {
    if blob.len() < FDT_HEADER_SIZE { return Err(Error::Inval); }
    if be32(blob, OFF_MAGIC)? != FDT_MAGIC { return Err(Error::Inval); }
    let totalsize = be32(blob, OFF_TOTALSIZE)? as usize;
    if totalsize < FDT_HEADER_SIZE || totalsize > blob.len() { return Err(Error::Inval); }
    if be32(blob, OFF_LAST_COMP_VERSION)? > FDT_LAST_COMP_VERSION { return Err(Error::Inval); }

    let off_struct = be32(blob, OFF_DT_STRUCT)? as usize;
    let size_struct = be32(blob, OFF_SIZE_DT_STRUCT)? as usize;
    let off_strings = be32(blob, OFF_DT_STRINGS)? as usize;
    let size_strings = be32(blob, OFF_SIZE_DT_STRINGS)? as usize;
    let off_rsv = be32(blob, OFF_MEM_RSVMAP)? as usize;
    let boot_cpuid_phys = be32(blob, OFF_BOOT_CPUID_PHYS)?;

    let structs = slice(blob, off_struct, size_struct, totalsize)?;
    let strings = slice(blob, off_strings, size_strings, totalsize)?;

    Ok(Fdt {
        boot_cpuid_phys,
        rsv: parse_rsv(blob, off_rsv, totalsize)?,
        root: parse_struct(structs, strings)?,
    })
}

fn parse_rsv(blob: &[u8], mut at: usize, totalsize: usize) -> KResult<Vec<(u64, u64)>> {
    if at % FDT_RSV_ALIGN != 0 { return Err(Error::Inval); }
    let mut out = Vec::new();
    loop {
        if at + 16 > totalsize { return Err(Error::Inval); }
        let a = be64(blob, at)?;
        let s = be64(blob, at + 8)?;
        at += 16;
        // The block ends at the all-zero entry, which is not itself a
        // reservation. An entry with a zero SIZE and a non-zero address is
        // not the terminator, and treating it as one truncates the block.
        if a == 0 && s == 0 { return Ok(out); }
        out.push((a, s));
    }
}

fn parse_struct(structs: &[u8], strings: &[u8]) -> KResult<Node> {
    let mut at = 0usize;
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;

    loop {
        let tok = be32(structs, at)?;
        at += 4;
        match tok {
            FDT_NOP => {}
            FDT_BEGIN_NODE => {
                let name = cstr(structs, at)?;
                at = align_up(at + name.len() + 1, FDT_TOKEN_ALIGN);
                stack.push(Node::new(name));
            }
            FDT_END_NODE => {
                let done = stack.pop().ok_or(Error::Inval)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(done),
                    None => {
                        if root.is_some() { return Err(Error::Inval); }
                        root = Some(done);
                    }
                }
            }
            FDT_PROP => {
                let len = be32(structs, at)? as usize;
                let nameoff = be32(structs, at + 4)? as usize;
                at += 8;
                if at + len > structs.len() { return Err(Error::Inval); }
                let val = structs[at..at + len].to_vec();
                at = align_up(at + len, FDT_TOKEN_ALIGN);
                let name = cstr(strings, nameoff)?.to_vec();
                stack.last_mut().ok_or(Error::Inval)?.props.push(Prop { name, val });
            }
            FDT_END => {
                if !stack.is_empty() { return Err(Error::Inval); }
                return root.ok_or(Error::Inval);
            }
            _ => return Err(Error::Inval),
        }
    }
}

/// Round `n` up to a multiple of `to`.
/// # C: O(1)
pub fn align_up(n: usize, to: usize) -> usize { n.div_ceil(to) * to }

fn slice<'a>(blob: &'a [u8], off: usize, len: usize, totalsize: usize) -> KResult<&'a [u8]> {
    let end = off.checked_add(len).ok_or(Error::Inval)?;
    if end > totalsize { return Err(Error::Inval); }
    Ok(&blob[off..end])
}

fn cstr(b: &[u8], at: usize) -> KResult<&[u8]> {
    if at >= b.len() { return Err(Error::Inval); }
    let end = b[at..].iter().position(|&c| c == 0).ok_or(Error::Inval)?;
    Ok(&b[at..at + end])
}

fn be32(b: &[u8], at: usize) -> KResult<u32> {
    if at + 4 > b.len() { return Err(Error::Inval); }
    Ok(u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]))
}

fn be64(b: &[u8], at: usize) -> KResult<u64> {
    if at + 8 > b.len() { return Err(Error::Inval); }
    Ok(u64::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3],
                           b[at + 4], b[at + 5], b[at + 6], b[at + 7]]))
}

#[cfg(test)]
mod tests;
