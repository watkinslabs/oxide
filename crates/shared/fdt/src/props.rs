// The concrete properties the boot path reads out of the device tree:
// `/chosen/bootargs`, the first `/memory` reg, the `/cpus` MPIDR list, and
// the PL011 reference clock. Each is a thin consumer of `walk`.

use crate::header::{read_be_u32, totalsize_from_prefix};
use crate::walk::{find_prop, walk, Event, Flow};

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
