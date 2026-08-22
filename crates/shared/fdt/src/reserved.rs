//! Firmware-owned physical ranges from the reservation map and `/reserved-memory`.

use crate::header::{parse_header, read_be_u32, FDT_RSVMAP_ENTRY_LEN};
use crate::walk::{walk, Event, Flow};

fn be64(bytes: &[u8], off: usize) -> Option<u64> {
    let hi = read_be_u32(bytes, off).ok()? as u64;
    let lo = read_be_u32(bytes, off + 4).ok()? as u64;
    Some((hi << 32) | lo)
}

fn cells(data: &[u8], count: u32) -> Option<u64> {
    if !(1..=2).contains(&count) { return None; }
    let mut value = 0u64;
    for cell in 0..count as usize {
        value = (value << 32) | read_be_u32(data, cell * 4).ok()? as u64;
    }
    Some(value)
}

fn push(out: &mut [(u64, u64)], count: &mut usize, base: u64, len: u64) {
    if len == 0 || base.checked_add(len).is_none() { return; }
    if *count < out.len() { out[*count] = (base, len); }
    *count += 1;
}

/// Decode firmware-owned memory. Returns the complete count even when `out`
/// is short, allowing the boot owner to reject a topology it cannot retain.
/// # C: O(blob)
pub fn reserved_regions(bytes: &[u8], out: &mut [(u64, u64)]) -> usize {
    let Ok(header) = parse_header(bytes) else { return 0 };
    let mut count = 0usize;
    let mut off = header.off_mem_rsvmap as usize;
    while off + FDT_RSVMAP_ENTRY_LEN <= header.off_dt_struct as usize {
        let Some(base) = be64(bytes, off) else { return count };
        let Some(len) = be64(bytes, off + 8) else { return count };
        off += FDT_RSVMAP_ENTRY_LEN;
        if base == 0 && len == 0 { break; }
        push(out, &mut count, base, len);
    }

    let mut address_cells = 2u32;
    let mut size_cells = 1u32;
    let mut reserved_depth = None;
    let mut child_depth = None;
    let _ = walk(bytes, |event| {
        match event {
            Event::BeginNode { name, depth: 1 } if name == b"reserved-memory" => {
                reserved_depth = Some(1);
            }
            Event::BeginNode { depth, .. } if depth > 0 && reserved_depth == Some(depth - 1) => {
                child_depth = Some(depth);
            }
            Event::Prop { name, data, depth: 0 } => match name {
                b"#address-cells" => address_cells = read_be_u32(data, 0).unwrap_or(0),
                b"#size-cells" => size_cells = read_be_u32(data, 0).unwrap_or(0),
                _ => {}
            },
            Event::Prop { name, data, depth } if reserved_depth == Some(depth) => match name {
                b"#address-cells" => address_cells = read_be_u32(data, 0).unwrap_or(0),
                b"#size-cells" => size_cells = read_be_u32(data, 0).unwrap_or(0),
                _ => {}
            },
            Event::Prop { name: b"reg", data, depth } if child_depth == Some(depth) => {
                let stride = (address_cells + size_cells) as usize * 4;
                if stride != 0 {
                    for entry in data.chunks_exact(stride) {
                        let split = address_cells as usize * 4;
                        if let Some((base, len)) = cells(entry, address_cells)
                            .zip(cells(&entry[split..], size_cells))
                        { push(out, &mut count, base, len); }
                    }
                }
            }
            Event::EndNode { depth } if child_depth == Some(depth) => child_depth = None,
            Event::EndNode { depth } if reserved_depth == Some(depth) => reserved_depth = None,
            _ => {}
        }
        Flow::Continue
    });
    count
}
