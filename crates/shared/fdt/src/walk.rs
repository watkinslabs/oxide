// One struct-block walker, shared by every consumer in this crate and by
// the `/sys/firmware/devicetree` exporter.
//
// The blob's struct block is a flat token stream (spec §5.4), so the walk is
// a single forward pass with a depth counter — no recursion, no allocation,
// and no per-consumer copy of the token decoding. Consumers that only want
// one property stop the walk from their callback.

use crate::header::{
    parse_header, read_be_u32, DtbError, FDT_BEGIN_NODE, FDT_END, FDT_END_NODE, FDT_NOP, FDT_PROP,
};

/// One struct-block event. `depth` is 0 for the root node, 1 for its
/// children, and so on; a `Prop` carries the depth of the node that owns it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    /// Node opened. `name` is the unit name (`""` for the root, `cpu@0`, …).
    BeginNode { name: &'a [u8], depth: u32 },
    /// Property of the currently open node, with its raw big-endian bytes.
    Prop { name: &'a [u8], data: &'a [u8], depth: u32 },
    /// Node closed; `depth` matches its `BeginNode`.
    EndNode { depth: u32 },
}

/// Callback verdict: keep walking, or stop and return `Ok(())` immediately.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Flow { Continue, Stop }

/// Walk the struct block of `bytes`, calling `f` for every node open, property
/// and node close in wire order. Returns `Err` when the header or the token
/// stream is malformed — a truncated blob, an unknown token, a property whose
/// length runs off the end of the block, or a name string with no terminator.
/// A blob that is merely empty walks cleanly with no events.
/// # C: O(struct_block_size)
pub fn walk<'a, F>(bytes: &'a [u8], mut f: F) -> Result<(), DtbError>
where F: FnMut(Event<'a>) -> Flow {
    let h = parse_header(bytes)?;
    let stru = block(bytes, h.off_dt_struct, h.size_dt_struct)?;
    let strs = block(bytes, h.off_dt_strings, h.size_dt_strings)?;
    let mut i = 0usize;
    // -1 = outside the root; the first BEGIN_NODE makes it 0.
    let mut depth: i32 = -1;
    while i + 4 <= stru.len() {
        let tok = read_be_u32(stru, i)?;
        i += 4;
        match tok {
            FDT_BEGIN_NODE => {
                depth += 1;
                let start = i;
                while i < stru.len() && stru[i] != 0 { i += 1; }
                if i >= stru.len() { return Err(DtbError::Truncated); }
                let name = &stru[start..i];
                i = (i + 1 + 3) & !3; // skip the NUL, realign to 4.
                if i > stru.len() { return Err(DtbError::Truncated); }
                if f(Event::BeginNode { name, depth: depth as u32 }) == Flow::Stop { return Ok(()); }
            }
            FDT_END_NODE => {
                if depth < 0 { return Err(DtbError::Inval); }
                if f(Event::EndNode { depth: depth as u32 }) == Flow::Stop { return Ok(()); }
                depth -= 1;
            }
            FDT_PROP => {
                if depth < 0 { return Err(DtbError::Inval); }
                let plen  = read_be_u32(stru, i)? as usize;
                let pname = read_be_u32(stru, i + 4)? as usize;
                i += 8;
                let data = stru.get(i..i + plen).ok_or(DtbError::Truncated)?;
                let name = prop_name(strs, pname)?;
                if f(Event::Prop { name, data, depth: depth as u32 }) == Flow::Stop { return Ok(()); }
                i += (plen + 3) & !3;
                if i > stru.len() { return Err(DtbError::Truncated); }
            }
            FDT_NOP => {}
            // FDT_END terminates the block, and every node opened before it
            // must have been closed. A blob whose last node never closes is
            // truncated, however cleanly its bytes happen to run out.
            FDT_END => return if depth == -1 { Ok(()) } else { Err(DtbError::Truncated) },
            _ => return Err(DtbError::Inval),
        }
    }
    if depth != -1 { return Err(DtbError::Truncated); }
    Ok(())
}

/// NUL-terminated property name at `off` in the strings block.
fn prop_name(strs: &[u8], off: usize) -> Result<&[u8], DtbError> {
    let tail = strs.get(off..).ok_or(DtbError::Truncated)?;
    let end = tail.iter().position(|&b| b == 0).ok_or(DtbError::Truncated)?;
    Ok(&tail[..end])
}

/// Bounds-checked `[off, off+len)` slice of the blob.
fn block(bytes: &[u8], off: u32, len: u32) -> Result<&[u8], DtbError> {
    let start = off as usize;
    let end = start.checked_add(len as usize).ok_or(DtbError::Inval)?;
    bytes.get(start..end).ok_or(DtbError::Truncated)
}

/// First property named `want` on the first node matching `pred`, where `pred`
/// sees the node's unit name and depth. The shared shape behind every
/// "read one property out of one well-known node" caller.
/// # C: O(struct_block_size)
pub fn find_prop<'a, P>(bytes: &'a [u8], mut pred: P, want: &[u8]) -> Option<&'a [u8]>
where P: FnMut(&[u8], u32) -> bool {
    let mut in_node = false;
    let mut node_depth = 0u32;
    let mut found: Option<&'a [u8]> = None;
    let _ = walk(bytes, |ev| match ev {
        Event::BeginNode { name, depth } => {
            if !in_node && pred(name, depth) { in_node = true; node_depth = depth; }
            Flow::Continue
        }
        Event::EndNode { depth } => {
            if in_node && depth == node_depth { Flow::Stop } else { Flow::Continue }
        }
        Event::Prop { name, data, depth } => {
            if in_node && depth == node_depth && name == want { found = Some(data); Flow::Stop }
            else { Flow::Continue }
        }
    });
    found
}
