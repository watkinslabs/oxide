// The concrete properties the boot path reads out of the device tree:
// `/chosen/bootargs`, the first `/memory` reg, the `/cpus` MPIDR list, and
// the PL011 reference clock. Each is a thin consumer of `walk`.

use crate::header::{read_be_u32, totalsize_from_prefix};
use crate::walk::{find_prop, walk, Event, Flow};

/// Firmware linear-scanout description decoded from a `simple-framebuffer`
/// device-tree node. Channel offsets are measured from the least-significant
/// bit of each packed pixel.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SimpleFramebuffer {
    pub base_pa: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bpp: u8,
    pub red: (u8, u8),
    pub green: (u8, u8),
    pub blue: (u8, u8),
}

/// MMIO resource of the first enabled ARM PrimeCell PL031 RTC.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Pl031Rtc {
    pub base_pa: u64,
    pub size: u64,
}

fn framebuffer_format(name: &[u8]) -> Option<(u8, (u8, u8), (u8, u8), (u8, u8))> {
    match name {
        b"r5g6b5" => Some((16, (11, 5), (5, 6), (0, 5))),
        b"r5g5b5a1" => Some((16, (11, 5), (6, 5), (1, 5))),
        b"x1r5g5b5" | b"a1r5g5b5" => Some((16, (10, 5), (5, 5), (0, 5))),
        b"r8g8b8" => Some((24, (16, 8), (8, 8), (0, 8))),
        b"x8r8g8b8" | b"a8r8g8b8" => Some((32, (16, 8), (8, 8), (0, 8))),
        b"x8b8g8r8" | b"a8b8g8r8" => Some((32, (0, 8), (8, 8), (16, 8))),
        b"x2r10g10b10" | b"a2r10g10b10" => Some((32, (20, 10), (10, 10), (0, 10))),
        _ => None,
    }
}

fn cells(data: &[u8], count: u32) -> Option<u64> {
    if !(1..=2).contains(&count) || data.len() < count as usize * 4 { return None; }
    let mut value = 0u64;
    for cell in 0..count as usize { value = (value << 32) | read_be_u32(data, cell * 4).ok()? as u64; }
    Some(value)
}

/// Decode the first enabled root-bus `arm,pl031` RTC resource.
///
/// QEMU's ARM `virt` machine exposes the PL031 as a root-bus child. The root
/// bus cell widths therefore govern `reg`; accepting a fixed 64-bit tuple
/// would decode 32-bit board descriptions incorrectly. A missing `status`
/// means enabled, while every explicit value other than `ok`/`okay` is
/// unavailable, matching the DT availability rule.
/// # C: O(struct_block_size)
pub fn pl031_rtc(bytes: &[u8]) -> Option<Pl031Rtc> {
    let mut address_cells = 2u32;
    let mut size_cells = 1u32;
    let mut candidate_depth = u32::MAX;
    let mut compatible = false;
    let mut enabled = true;
    let mut reg = None;
    let mut found = None;
    walk(bytes, |event| {
        match event {
            Event::BeginNode { depth: 1, .. } => {
                candidate_depth = 1;
                compatible = false;
                enabled = true;
                reg = None;
            }
            Event::Prop { name, data, depth: 0 } => match name {
                b"#address-cells" => address_cells = read_be_u32(data, 0).unwrap_or(0),
                b"#size-cells" => size_cells = read_be_u32(data, 0).unwrap_or(0),
                _ => {}
            },
            Event::Prop { name, data, depth } if depth == candidate_depth => match name {
                b"compatible" => compatible = contains_string(data, b"arm,pl031"),
                b"status" => enabled = matches!(data.split(|byte| *byte == 0).next(), Some(b"okay" | b"ok")),
                b"reg" => {
                    let offset = address_cells as usize * 4;
                    reg = cells(data, address_cells)
                        .zip(cells(data.get(offset..).unwrap_or(&[]), size_cells));
                }
                _ => {}
            },
            Event::EndNode { depth } if depth == candidate_depth => {
                if compatible && enabled {
                    if let Some((base_pa, size)) = reg {
                        if base_pa != 0 && size >= core::mem::size_of::<u32>() as u64
                            && base_pa.checked_add(size).is_some()
                        {
                            found = Some(Pl031Rtc { base_pa, size });
                            return Flow::Stop;
                        }
                    }
                }
                candidate_depth = u32::MAX;
            }
            _ => {}
        }
        Flow::Continue
    }).ok()?;
    found
}

fn referenced_resource(bytes: &[u8], target: u32, address_cells: u32, size_cells: u32) -> Option<(u64, u64)> {
    let mut node_depth = u32::MAX;
    let mut phandle = None;
    let mut reg = None;
    let mut found = None;
    walk(bytes, |event| {
        match event {
            Event::BeginNode { depth, .. } => { node_depth = depth; phandle = None; reg = None; }
            Event::Prop { name, data, depth } if depth == node_depth => match name {
                b"phandle" | b"linux,phandle" => phandle = read_be_u32(data, 0).ok(),
                b"reg" => {
                    let offset = address_cells as usize * 4;
                    reg = cells(data, address_cells).zip(cells(data.get(offset..).unwrap_or(&[]), size_cells));
                }
                _ => {}
            },
            Event::EndNode { depth } if depth == node_depth && phandle == Some(target) => {
                found = reg;
                return Flow::Stop;
            }
            _ => {}
        }
        Flow::Continue
    }).ok()?;
    found
}

/// Decode the first valid `simple-framebuffer` node. The backing resource is
/// required to cover its visible scanout, otherwise the node is rejected.
/// # C: O(struct_block_size)
pub fn simple_framebuffer(bytes: &[u8]) -> Option<SimpleFramebuffer> {
    let mut address_cells = 2u32;
    let mut size_cells = 1u32;
    let mut chosen_depth = None;
    let mut candidate_depth = u32::MAX;
    let mut compatible = false;
    let mut enabled = true;
    let mut memory_region = None;
    let mut reg: Option<(u64, u64)> = None;
    let mut width = None;
    let mut height = None;
    let mut stride = None;
    let mut layout = None;
    let mut found: Option<(u32, u32, u32, (u8, (u8, u8), (u8, u8), (u8, u8)), Option<(u64, u64)>, Option<u32>)> = None;
    walk(bytes, |event| {
        match event {
            Event::BeginNode { name, depth } => {
                if depth == 1 && name == b"chosen" { chosen_depth = Some(depth); }
                if depth > 0 && chosen_depth == Some(depth - 1) {
                    candidate_depth = depth;
                    compatible = false;
                    enabled = true;
                    memory_region = None;
                    reg = None;
                    width = None;
                    height = None;
                    stride = None;
                    layout = None;
                }
            }
            Event::Prop { name, data, depth } => {
                if depth == 0 && name == b"#address-cells" { address_cells = read_be_u32(data, 0).unwrap_or(0); }
                if depth == 0 && name == b"#size-cells" { size_cells = read_be_u32(data, 0).unwrap_or(0); }
                if depth == candidate_depth {
                    match name {
                        b"compatible" => compatible = contains_string(data, b"simple-framebuffer"),
                        b"status" => enabled = matches!(data.split(|byte| *byte == 0).next(), Some(b"okay" | b"ok")),
                        b"memory-region" => memory_region = Some(read_be_u32(data, 0).unwrap_or(0)),
                        b"reg" => {
                            let offset = address_cells as usize * 4;
                            reg = cells(data, address_cells).zip(cells(data.get(offset..).unwrap_or(&[]), size_cells));
                        }
                        b"width" => width = read_be_u32(data, 0).ok(),
                        b"height" => height = read_be_u32(data, 0).ok(),
                        b"stride" => stride = read_be_u32(data, 0).ok(),
                        b"format" => layout = data.split(|byte| *byte == 0).next().and_then(framebuffer_format),
                        _ => {}
                    }
                }
            }
            Event::EndNode { depth } if depth == candidate_depth && compatible && enabled => {
                if let (Some(width), Some(height), Some(stride), Some(layout)) = (width, height, stride, layout) {
                    let visible = u64::from(stride).checked_mul(u64::from(height));
                    let bpp = layout.0;
                    let min_stride = width.checked_mul(u32::from(bpp).div_ceil(8));
                    if min_stride.is_some_and(|n| stride >= n) && visible.is_some() {
                        found = Some((width, height, stride, layout, reg, memory_region));
                        return Flow::Stop;
                    }
                }
            }
            Event::EndNode { depth } => {
                if chosen_depth == Some(depth) { chosen_depth = None; }
            }
        }
        Flow::Continue
    }).ok()?;
    let (width, height, stride, (bpp, red, green, blue), reg, memory_region) = found?;
    let (base_pa, size) = match memory_region {
        Some(phandle) => referenced_resource(bytes, phandle, address_cells, size_cells)?,
        None => reg?,
    };
    let visible = u64::from(stride).checked_mul(u64::from(height))?;
    (base_pa != 0 && visible <= size).then_some(SimpleFramebuffer { base_pa, size, width, height, stride, bpp, red, green, blue })
}

/// Bytes of `/chosen/bootargs` with trailing NULs trimmed, or `None` when the
/// blob is malformed, `/chosen` is absent, or `bootargs` is unset/empty-after-
/// trim. The slice borrows `bytes`.
/// # C: O(struct_block_size)
pub fn chosen_bootargs(bytes: &[u8]) -> Option<&[u8]> {
    let data = find_prop(bytes, |name, depth| depth == 1 && name == b"chosen", b"bootargs")?;
    // Bootloaders differ on whether the property length includes the NUL.
    let end = data.iter().rposition(|&b| b != 0).map(|x| x + 1).unwrap_or(0);
    Some(&data[..end])
}

/// `/chosen/bootargs` from a blob whose length is not known up front: learn
/// `totalsize` from an 8-byte prefix, hand that length to `full`, then read the
/// property out of the whole blob.
///
/// One function because doing it inline once asked `parse_header` to decode the
/// prefix — a call that structurally cannot succeed, since its `totalsize <=
/// len` check rejects every prefix — so the boot path read no command line
/// from any device tree, on every boot, silently.
/// # C: O(struct_block_size)
pub fn bootargs_via_prefix<'a, F>(prefix: &[u8], full: F) -> Option<&'a [u8]>
where F: FnOnce(usize) -> Option<&'a [u8]> {
    let blob = full(totalsize_from_prefix(prefix)?)?;
    chosen_bootargs(blob)
}

/// First `/memory` node's first `reg` entry → `(base, size)`. Assumes the
/// arm64 `virt` cell layout (`#address-cells=2`, `#size-cells=2`), i.e.
/// `reg = <base_hi base_lo size_hi size_lo>`. `None` when no `/memory` node or
/// `reg` property is present. Drives the self-boot PMM memmap.
/// # C: O(struct_block_size)
pub fn first_memory_region(bytes: &[u8]) -> Option<(u64, u64)> {
    let is_memory = |name: &[u8], depth: u32| {
        depth == 1 && name.starts_with(b"memory")
            && (name.len() == 6 || name.get(6) == Some(&b'@'))
    };
    let reg = find_prop(bytes, is_memory, b"reg")?;
    if reg.len() < 16 { return None; }
    let base = u64::from_be_bytes(reg[0..8].try_into().ok()?);
    let size = u64::from_be_bytes(reg[8..16].try_into().ok()?);
    Some((base, size))
}

/// Every `reg` entry of the first `/memory` node, as `(base, size)` pairs in
/// device-tree order. Fills `out` with up to `out.len()` and returns the total
/// seen. Assumes the arm64 cell layout (`#address-cells=2`, `#size-cells=2`),
/// so each entry is 16 bytes.
///
/// The single-region [`first_memory_region`] is this with `out.len() == 1`; a
/// machine whose RAM is not one contiguous block needs all of them, and a
/// reader that takes only the first silently loses the rest.
/// # C: O(struct_block_size)
pub fn memory_regions(bytes: &[u8], out: &mut [(u64, u64)]) -> usize {
    let is_memory = |name: &[u8], depth: u32| {
        depth == 1 && name.starts_with(b"memory")
            && (name.len() == 6 || name.get(6) == Some(&b'@'))
    };
    let Some(reg) = find_prop(bytes, is_memory, b"reg") else { return 0 };
    let mut n = 0usize;
    for e in reg.chunks_exact(16) {
        let base = u64::from_be_bytes(e[0..8].try_into().unwrap_or([0; 8]));
        let size = u64::from_be_bytes(e[8..16].try_into().unwrap_or([0; 8]));
        if size == 0 { continue; }
        if n < out.len() { out[n] = (base, size); }
        n += 1;
    }
    n
}

/// Enumerate `/cpus/cpu@*` → each CPU's `reg`, which on arm64 is the MPIDR_EL1
/// affinity a PSCI `CPU_ON` targets. Fills `out` with up to `out.len()` MPIDRs
/// in device-tree order (index 0 is typically the boot CPU) and returns the
/// total cpu-node count seen, which may exceed `out.len()`. `/cpus`
/// `#address-cells` (FDT default 2; arm64 QEMU `virt` uses 1) governs how many
/// big-endian cells each `reg` occupies; cells fold low-order into the u64.
/// # C: O(struct_block_size)
pub fn enum_cpus(bytes: &[u8], out: &mut [u64]) -> usize {
    let mut cpus_depth: i32 = -1;
    let mut addr_cells: u32 = 2;
    let mut in_cpu = false;
    let mut count = 0usize;
    let _ = walk(bytes, |ev| {
        match ev {
            Event::BeginNode { name, depth } => {
                let d = depth as i32;
                if d == 1 && name == b"cpus" { cpus_depth = d; }
                else if cpus_depth >= 0 && d == cpus_depth + 1
                    && (name == b"cpu" || name.starts_with(b"cpu@")) { in_cpu = true; }
            }
            Event::EndNode { depth } => {
                let d = depth as i32;
                if in_cpu && d == cpus_depth + 1 { in_cpu = false; }
                if d == cpus_depth { cpus_depth = -1; }
            }
            Event::Prop { name, data, depth } => {
                let d = depth as i32;
                if cpus_depth >= 0 && d == cpus_depth && !in_cpu
                    && name == b"#address-cells" && data.len() >= 4 {
                    if let Ok(v) = read_be_u32(data, 0) {
                        if v >= 1 && v <= 2 { addr_cells = v; }
                    }
                }
                if in_cpu && name == b"reg" && data.len() >= 4 * addr_cells as usize {
                    let mut mpidr = 0u64;
                    for c in 0..addr_cells as usize {
                        let cell = read_be_u32(data, c * 4).unwrap_or(0) as u64;
                        mpidr = (mpidr << 32) | cell;
                    }
                    if count < out.len() { out[count] = mpidr; }
                    count += 1;
                }
            }
        }
        Flow::Continue
    });
    count
}

/// PL011 `UARTCLK` in Hz sourced from the device tree's clock tree: find the
/// first node whose `compatible` list contains `arm,pl011`, take the FIRST
/// phandle of its `clocks` property (the UARTCLK input, `clock-names[0] ==
/// "uartclk"`), then resolve that clock node's `clock-frequency`. Falls back to
/// a `clock-frequency` sitting directly on the UART node. `None` when the blob
/// describes no PL011 clock, so the caller keeps its built-in default.
/// # C: O(struct_block_size)
pub fn pl011_clock_hz(bytes: &[u8]) -> Option<u32> {
    // Pass 1: locate the PL011 node; capture its `clocks` first phandle and
    // any `clock-frequency` sitting directly on it.
    let mut pl_depth: i32 = -1;
    let mut clocks_phandle: Option<u32> = None;
    let mut direct_freq: Option<u32> = None;
    let _ = walk(bytes, |ev| {
        match ev {
            Event::EndNode { depth } => {
                if pl_depth >= 0 && depth as i32 == pl_depth { return Flow::Stop; }
            }
            Event::Prop { name, data, depth } => {
                let d = depth as i32;
                if name == b"compatible" && contains_string(data, b"arm,pl011") { pl_depth = d; }
                if pl_depth >= 0 && d == pl_depth {
                    if name == b"clocks" && data.len() >= 4 {
                        clocks_phandle = read_be_u32(data, 0).ok();
                    } else if name == b"clock-frequency" && data.len() >= 4 {
                        direct_freq = read_be_u32(data, 0).ok();
                    }
                }
            }
            Event::BeginNode { .. } => {}
        }
        Flow::Continue
    });
    if let Some(f) = direct_freq { return Some(f); }
    let target = clocks_phandle?;
    // Pass 2: the node whose `phandle`/`linux,phandle` == target carries the
    // reference frequency.
    let mut this_ph: Option<u32> = None;
    let mut this_freq: Option<u32> = None;
    let mut hit: Option<u32> = None;
    let _ = walk(bytes, |ev| {
        match ev {
            Event::BeginNode { .. } => { this_ph = None; this_freq = None; }
            Event::EndNode { .. } => {
                if this_ph == Some(target) { hit = this_freq; return Flow::Stop; }
            }
            Event::Prop { name, data, .. } => {
                if (name == b"phandle" || name == b"linux,phandle") && data.len() >= 4 {
                    this_ph = read_be_u32(data, 0).ok();
                } else if name == b"clock-frequency" && data.len() >= 4 {
                    this_freq = read_be_u32(data, 0).ok();
                }
            }
        }
        Flow::Continue
    });
    hit
}

/// Whether a `<stringlist>` property contains `want` as one whole NUL-delimited
/// element. Substring matching would accept `arm,pl011-foo` for `arm,pl011`.
/// # C: O(len)
pub fn contains_string(data: &[u8], want: &[u8]) -> bool {
    data.split(|&b| b == 0).any(|s| s == want)
}

/// Machine model name (`/` node's `model`, else its first `compatible`
/// element), NUL-trimmed. Linux logs this as "Machine model:".
/// # C: O(struct_block_size)
pub fn machine_model(bytes: &[u8]) -> Option<&[u8]> {
    fn root(_name: &[u8], depth: u32) -> bool { depth == 0 }
    fn pick(d: &[u8]) -> Option<&[u8]> {
        let first = d.split(|&b| b == 0).next()?;
        if first.is_empty() { None } else { Some(first) }
    }
    if let Some(s) = find_prop(bytes, root, b"model").and_then(pick) { return Some(s); }
    find_prop(bytes, root, b"compatible").and_then(pick)
}
