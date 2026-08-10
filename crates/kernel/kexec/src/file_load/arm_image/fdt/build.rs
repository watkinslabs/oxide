// Re-flatten a decoded tree.
//
// The output is already packed — there is no slack to trim, so the reference's
// closing `fdt_pack` has no counterpart here beyond emitting nothing spare.
// `totalsize` is therefore the exact byte count, which is also the size the
// segment reserves: a blob whose header claims more than it contains reserves
// memory the new kernel then treats as tree.

extern crate alloc;
use alloc::vec::Vec;

use super::*;

impl Fdt {
    /// Flatten to a blob.
    /// # C: O(tree size)
    pub fn to_blob(&self) -> Vec<u8> {
        let mut strings: Vec<u8> = Vec::new();
        let mut structs: Vec<u8> = Vec::new();
        emit_node(&self.root, &mut structs, &mut strings);
        put32(&mut structs, FDT_END);

        let mut rsv: Vec<u8> = Vec::new();
        for &(a, s) in &self.rsv { put64(&mut rsv, a); put64(&mut rsv, s); }
        // The terminating all-zero entry is part of the block, not an
        // optional decoration: a reader walks until it sees one.
        put64(&mut rsv, 0);
        put64(&mut rsv, 0);

        let off_rsv = align_up(FDT_HEADER_SIZE, FDT_RSV_ALIGN);
        let off_struct = align_up(off_rsv + rsv.len(), FDT_RSV_ALIGN);
        let off_strings = off_struct + structs.len();
        let totalsize = off_strings + strings.len();

        let mut out: Vec<u8> = Vec::with_capacity(totalsize);
        put32(&mut out, FDT_MAGIC);
        put32(&mut out, totalsize as u32);
        put32(&mut out, off_struct as u32);
        put32(&mut out, off_strings as u32);
        put32(&mut out, off_rsv as u32);
        put32(&mut out, FDT_VERSION);
        put32(&mut out, FDT_LAST_COMP_VERSION);
        put32(&mut out, self.boot_cpuid_phys);
        put32(&mut out, strings.len() as u32);
        put32(&mut out, structs.len() as u32);

        out.resize(off_rsv, 0);
        out.extend_from_slice(&rsv);
        out.resize(off_struct, 0);
        out.extend_from_slice(&structs);
        out.extend_from_slice(&strings);
        out
    }
}

fn emit_node(n: &Node, structs: &mut Vec<u8>, strings: &mut Vec<u8>) {
    put32(structs, FDT_BEGIN_NODE);
    structs.extend_from_slice(&n.name);
    structs.push(0);
    pad(structs, FDT_TOKEN_ALIGN);

    for p in &n.props {
        let nameoff = intern(strings, &p.name);
        put32(structs, FDT_PROP);
        put32(structs, p.val.len() as u32);
        put32(structs, nameoff);
        structs.extend_from_slice(&p.val);
        pad(structs, FDT_TOKEN_ALIGN);
    }
    for c in &n.children { emit_node(c, structs, strings); }
    put32(structs, FDT_END_NODE);
}

/// Offset of `name` in the string table, appending it when absent.
///
/// Exact-match reuse only. A suffix-sharing table is smaller and equally
/// legal, but the sharing is what makes a hand-written table wrong: the
/// offset of a name that is a suffix of another is inside that other name,
/// and one byte out reads a truncated property name that matches nothing.
fn intern(strings: &mut Vec<u8>, name: &[u8]) -> u32 {
    let mut at = 0usize;
    while at < strings.len() {
        let Some(rel) = strings[at..].iter().position(|&c| c == 0) else { break };
        if &strings[at..at + rel] == name { return at as u32; }
        at += rel + 1;
    }
    let off = strings.len() as u32;
    strings.extend_from_slice(name);
    strings.push(0);
    off
}

fn put32(v: &mut Vec<u8>, x: u32) { v.extend_from_slice(&x.to_be_bytes()); }
fn put64(v: &mut Vec<u8>, x: u64) { v.extend_from_slice(&x.to_be_bytes()); }
fn pad(v: &mut Vec<u8>, to: usize) { let n = align_up(v.len(), to); v.resize(n, 0); }
