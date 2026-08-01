use core::sync::atomic::{AtomicU32, Ordering};

use crate::acpi::log::{alog_dec, alog_hex, alog_raw};
use crate::acpi::read::read_u32_le;

const IORT_NODE_HEADER_BYTES: usize = 16;
const IORT_ID_MAP_BYTES: usize = 20;
const IORT_NODE_ITS_GROUP: u8 = 0;
const IORT_NODE_ROOT_COMPLEX: u8 = 2;
const IORT_MAP_SINGLE: u32 = 1;
const IORT_MSI_MAP_SLOTS: usize = 16;

#[derive(Copy, Clone)]
struct MsiMap {
    input: u32,
    count: u32,
    output: u32,
    output_ref: u32,
    flags: u32,
}

static IORT_MSI_IN: [AtomicU32; IORT_MSI_MAP_SLOTS] =
    [const { AtomicU32::new(0) }; IORT_MSI_MAP_SLOTS];
static IORT_MSI_COUNT: [AtomicU32; IORT_MSI_MAP_SLOTS] =
    [const { AtomicU32::new(0) }; IORT_MSI_MAP_SLOTS];
static IORT_MSI_OUT: [AtomicU32; IORT_MSI_MAP_SLOTS] =
    [const { AtomicU32::new(0) }; IORT_MSI_MAP_SLOTS];
static IORT_MSI_FLAGS: [AtomicU32; IORT_MSI_MAP_SLOTS] =
    [const { AtomicU32::new(0) }; IORT_MSI_MAP_SLOTS];

/// Translate a PCI Requester ID through the ACPI IORT MSI map.
/// # C: O(number of stored maps)
pub fn iort_msi_device_id(rid: u32) -> Option<u32> {
    for i in 0..IORT_MSI_MAP_SLOTS {
        let count = IORT_MSI_COUNT[i].load(Ordering::Acquire);
        if count == 0 {
            continue;
        }
        let input = IORT_MSI_IN[i].load(Ordering::Acquire);
        let end = input.saturating_add(count);
        if rid < input || rid >= end {
            continue;
        }
        let output = IORT_MSI_OUT[i].load(Ordering::Acquire);
        let flags = IORT_MSI_FLAGS[i].load(Ordering::Acquire);
        return Some(if (flags & IORT_MAP_SINGLE) != 0 {
            output
        } else {
            output.saturating_add(rid - input)
        });
    }
    None
}

/// Decode ACPI IORT direct root-complex -> ITS ID mappings.
///
/// # SAFETY: caller asserted `iort_pa` came from a valid XSDT entry
/// and is HHDM-mapped contiguously for the table's declared length.
/// # C: O(nodes * maps)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn decode_iort(iort_pa: u64, hhdm_offset: u64) {
    clear_maps();
    let p = (hhdm_offset + iort_pa) as *const u8;
    // SAFETY: iort_pa lies in HHDM-mapped ACPI memory; offset 4 is SDT length.
    let sdt_len = unsafe { read_u32_le(p.add(4)) } as usize;
    if sdt_len < 48 {
        alog_raw(b"[INFO]    iort: too short\n");
        return;
    }
    // SAFETY: HHDM-mapped IORT, sdt_len verified >= 48 above.
    let num_nodes = unsafe { read_u32_le(p.add(36)) } as usize;
    // SAFETY: same HHDM-mapped IORT region; offset 40 is inside the header.
    let node_off0 = unsafe { read_u32_le(p.add(40)) } as usize;
    alog_raw(b"[INFO]    iort num_nodes=");
    alog_dec(num_nodes as u64);
    alog_raw(b" first_node_off=");
    alog_hex(node_off0 as u64);
    alog_raw(b"\n");
    let mut next_slot = 0usize;
    walk_nodes(p, sdt_len, num_nodes, node_off0, &mut next_slot);
}

#[cfg(target_os = "oxide-kernel")]
fn walk_nodes(p: *const u8, len: usize, num_nodes: usize, first: usize, next_slot: &mut usize) {
    let mut off = first;
    let mut idx = 0usize;
    while idx < num_nodes && off + IORT_NODE_HEADER_BYTES <= len {
        // SAFETY: loop guard keeps the common node header in bounds.
        let (nty, nlen) = unsafe { node_type_len(p, off) };
        if nlen < IORT_NODE_HEADER_BYTES || off + nlen > len {
            break;
        }
        log_node(nty, nlen);
        if nty == IORT_NODE_ROOT_COMPLEX {
            // SAFETY: node bounds checked above; helper bounds-checks map array.
            unsafe { decode_root_maps(p, len, off, nlen, next_slot); }
        }
        off += nlen;
        idx += 1;
    }
}

#[cfg(target_os = "oxide-kernel")]
unsafe fn decode_root_maps(
    p: *const u8,
    table_len: usize,
    node_off: usize,
    node_len: usize,
    next_slot: &mut usize,
) {
    // SAFETY: caller proved the common header is in bounds.
    let map_count = unsafe { read_u32_le(p.add(node_off + 8)) } as usize;
    // SAFETY: caller proved the common header is in bounds.
    let map_off = unsafe { read_u32_le(p.add(node_off + 12)) } as usize;
    let abs = node_off.saturating_add(map_off);
    let mut i = 0usize;
    while i < map_count && abs + (i + 1) * IORT_ID_MAP_BYTES <= node_off + node_len {
        let entry = abs + i * IORT_ID_MAP_BYTES;
        // SAFETY: loop bound keeps this 20-byte map entry inside the node.
        let map = unsafe { read_map(p, entry) };
        if target_is_its_group(p, table_len, map.output_ref as usize) {
            store_map(*next_slot, map);
            *next_slot = next_slot.saturating_add(1);
        }
        i += 1;
    }
}

#[cfg(target_os = "oxide-kernel")]
unsafe fn read_map(p: *const u8, off: usize) -> MsiMap {
    // SAFETY: caller ensures the full map entry is readable.
    let input = unsafe { read_u32_le(p.add(off)) };
    // SAFETY: caller ensures the full map entry is readable.
    let count = unsafe { read_u32_le(p.add(off + 4)) };
    // SAFETY: caller ensures the full map entry is readable.
    let output = unsafe { read_u32_le(p.add(off + 8)) };
    // SAFETY: caller ensures the full map entry is readable.
    let output_ref = unsafe { read_u32_le(p.add(off + 12)) };
    // SAFETY: caller ensures the full map entry is readable.
    let flags = unsafe { read_u32_le(p.add(off + 16)) };
    MsiMap { input, count, output, output_ref, flags }
}

#[cfg(target_os = "oxide-kernel")]
fn target_is_its_group(p: *const u8, table_len: usize, off: usize) -> bool {
    if off + IORT_NODE_HEADER_BYTES > table_len {
        return false;
    }
    // SAFETY: `p` is the HHDM-mapped IORT base and `table_len` its SDT length,
    // so the whole `[p, p+table_len)` range is readable; the guard above proved
    // `off + IORT_NODE_HEADER_BYTES <= table_len`, which puts this single node
    // -type byte at `p+off` strictly inside the table.
    unsafe { core::ptr::read_volatile(p.add(off)) == IORT_NODE_ITS_GROUP }
}

#[cfg(target_os = "oxide-kernel")]
unsafe fn node_type_len(p: *const u8, off: usize) -> (u8, usize) {
    // SAFETY: caller ensures at least the common header is readable.
    let nty = unsafe { core::ptr::read_volatile(p.add(off)) };
    // SAFETY: caller ensures at least the common header is readable.
    let lo = unsafe { core::ptr::read_volatile(p.add(off + 1)) } as usize;
    // SAFETY: caller ensures at least the common header is readable.
    let hi = unsafe { core::ptr::read_volatile(p.add(off + 2)) } as usize;
    (nty, lo | (hi << 8))
}

#[cfg(target_os = "oxide-kernel")]
fn store_map(slot: usize, map: MsiMap) {
    if slot >= IORT_MSI_MAP_SLOTS || map.count == 0 {
        return;
    }
    IORT_MSI_IN[slot].store(map.input, Ordering::Release);
    IORT_MSI_OUT[slot].store(map.output, Ordering::Release);
    IORT_MSI_FLAGS[slot].store(map.flags, Ordering::Release);
    IORT_MSI_COUNT[slot].store(map.count, Ordering::Release);
    alog_raw(b"[INFO]      iort-msi-map in=");
    alog_hex(map.input as u64);
    alog_raw(b" count=");
    alog_dec(map.count as u64);
    alog_raw(b" out=");
    alog_hex(map.output as u64);
    alog_raw(b" flags=");
    alog_hex(map.flags as u64);
    alog_raw(b"\n");
}

fn clear_maps() {
    for i in 0..IORT_MSI_MAP_SLOTS {
        IORT_MSI_COUNT[i].store(0, Ordering::Release);
    }
}

#[cfg(target_os = "oxide-kernel")]
fn log_node(nty: u8, nlen: usize) {
    let label: &[u8] = match nty {
        0 => b"ITS-group",
        1 => b"named-component",
        2 => b"root-complex",
        3 => b"SMMUv1/v2",
        4 => b"SMMUv3",
        5 => b"PMCG",
        6 => b"memory-range",
        _ => b"unknown",
    };
    alog_raw(b"[INFO]    iort-node type=");
    alog_dec(nty as u64);
    alog_raw(b" (");
    alog_raw(label);
    alog_raw(b") len=");
    alog_dec(nlen as u64);
    alog_raw(b"\n");
}
