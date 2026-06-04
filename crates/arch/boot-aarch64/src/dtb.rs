// Flattened Device Tree (FDT) header per `36§4` U-Boot path. v1
// scope: validate the magic + compatibility version, expose
// totalsize / offsets so the kernel can copy the blob out of the
// bootloader-owned region into BSS before continuing. Full property
// walking lands once we have a real consumer (PMM init, ACPI fallback).
//
// FDT spec: https://devicetree-specification.readthedocs.io/en/v0.4/
// flattened-format.html
//
// Wire format is big-endian; we read u32 / u64 fields with explicit
// `from_be_bytes`.

extern crate alloc;
use core::convert::TryInto;

/// Magic value at the start of every FDT blob (big-endian).
pub const FDT_MAGIC: u32 = 0xd00d_feed;

/// Compatibility version we know how to read; the FDT spec
/// guarantees backward-compat from 17 onwards.
pub const FDT_LAST_COMPAT_VERSION: u32 = 16;

/// FDT header per `flattened-format.html` §5.2. Fields are big-endian
/// on the wire; this struct is the host-order decoded form.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FdtHeader {
    pub magic:             u32,
    pub totalsize:         u32,
    pub off_dt_struct:     u32,
    pub off_dt_strings:    u32,
    pub off_mem_rsvmap:    u32,
    pub version:           u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys:   u32,
    pub size_dt_strings:   u32,
    pub size_dt_struct:    u32,
}

/// Errors from `parse_header`.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DtbError {
    Truncated      = 1,
    BadMagic       = 2,
    UnsupportedVersion = 3,
    Inval          = 22,
}

pub type KResult<T> = core::result::Result<T, DtbError>;

/// Validate + decode the FDT header from `bytes`. Returns `Truncated`
/// if the slice is too short, `BadMagic` if the first u32 isn't
/// `0xd00dfeed`, `UnsupportedVersion` if last_comp_version > our
/// known value.
/// # C: O(1)
pub fn parse_header(bytes: &[u8]) -> KResult<FdtHeader> {
    if bytes.len() < 40 { return Err(DtbError::Truncated); }
    let h = FdtHeader {
        magic:             read_be_u32(bytes,  0)?,
        totalsize:         read_be_u32(bytes,  4)?,
        off_dt_struct:     read_be_u32(bytes,  8)?,
        off_dt_strings:    read_be_u32(bytes, 12)?,
        off_mem_rsvmap:    read_be_u32(bytes, 16)?,
        version:           read_be_u32(bytes, 20)?,
        last_comp_version: read_be_u32(bytes, 24)?,
        boot_cpuid_phys:   read_be_u32(bytes, 28)?,
        size_dt_strings:   read_be_u32(bytes, 32)?,
        size_dt_struct:    read_be_u32(bytes, 36)?,
    };
    if h.magic != FDT_MAGIC { return Err(DtbError::BadMagic); }
    if h.last_comp_version > FDT_LAST_COMPAT_VERSION {
        return Err(DtbError::UnsupportedVersion);
    }
    if h.totalsize as usize > bytes.len() { return Err(DtbError::Truncated); }
    if (h.off_dt_struct  as usize)  > h.totalsize as usize { return Err(DtbError::Inval); }
    if (h.off_dt_strings as usize)  > h.totalsize as usize { return Err(DtbError::Inval); }
    if (h.off_mem_rsvmap as usize)  > h.totalsize as usize { return Err(DtbError::Inval); }
    Ok(h)
}

// FDT struct-block tokens per devicetree-specification §5.4.
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE:   u32 = 2;
const FDT_PROP:       u32 = 3;
const FDT_NOP:        u32 = 4;
const FDT_END:        u32 = 9;

/// Walk a parsed FDT blob and return the bytes of the `/chosen/bootargs`
/// property (without the trailing NUL). Returns `None` if either the
/// blob is malformed, the `chosen` node is missing, or `bootargs` isn't
/// set. The returned slice borrows from `bytes` for its full lifetime.
/// # C: O(struct_block_size)
pub fn chosen_bootargs<'a>(bytes: &'a [u8]) -> Option<&'a [u8]> {
    let h = parse_header(bytes).ok()?;
    let stru = bytes.get(h.off_dt_struct as usize ..
                         (h.off_dt_struct + h.size_dt_struct) as usize)?;
    let strs = bytes.get(h.off_dt_strings as usize ..
                         (h.off_dt_strings + h.size_dt_strings) as usize)?;
    let mut i = 0usize;
    let mut depth: i32 = -1; // -1 = before root; root push makes 0.
    let mut in_chosen = false;
    let mut chosen_depth: i32 = -1;
    while i + 4 <= stru.len() {
        let tok = read_be_u32(stru, i).ok()?;
        i += 4;
        match tok {
            FDT_BEGIN_NODE => {
                depth += 1;
                let start = i;
                while i < stru.len() && stru[i] != 0 { i += 1; }
                if i >= stru.len() { return None; }
                let name = &stru[start..i];
                i = (i + 1 + 3) & !3; // skip NUL, align to 4.
                if depth == 1 && name == b"chosen" {
                    in_chosen = true;
                    chosen_depth = depth;
                }
            }
            FDT_END_NODE => {
                if in_chosen && depth == chosen_depth {
                    in_chosen = false;
                }
                depth -= 1;
            }
            FDT_PROP => {
                if i + 8 > stru.len() { return None; }
                let plen  = read_be_u32(stru, i).ok()? as usize;
                let pname = read_be_u32(stru, i + 4).ok()? as usize;
                i += 8;
                let pdata = stru.get(i .. i + plen)?;
                if in_chosen {
                    let name_end = strs[pname..].iter()
                        .position(|&b| b == 0)?;
                    if &strs[pname..pname + name_end] == b"bootargs" {
                        // Trim trailing NULs that some bootloaders
                        // include in the property length.
                        let end = pdata.iter().rposition(|&b| b != 0)
                            .map(|x| x + 1).unwrap_or(0);
                        return Some(&pdata[..end]);
                    }
                }
                i += (plen + 3) & !3;
            }
            FDT_NOP => {}
            FDT_END => return None,
            _ => return None,
        }
    }
    None
}

/// First `/memory` node's first `reg` entry → `(base, size)`. Assumes
/// the arm64 `virt` cell layout (#address-cells=2, #size-cells=2), i.e.
/// `reg = <base_hi base_lo size_hi size_lo>` (16 bytes). Used by the
/// self-bootstrap path to build the PMM memmap without Limine. Returns
/// `None` if no `/memory` node / `reg` property is found.
/// # C: O(dtb_struct_size)
pub fn first_memory_region(bytes: &[u8]) -> Option<(u64, u64)> {
    let h = parse_header(bytes).ok()?;
    let stru = bytes.get(h.off_dt_struct as usize ..
                         (h.off_dt_struct + h.size_dt_struct) as usize)?;
    let strs = bytes.get(h.off_dt_strings as usize ..
                         (h.off_dt_strings + h.size_dt_strings) as usize)?;
    let mut i = 0usize;
    let mut depth: i32 = -1;
    let mut in_mem = false;
    let mut mem_depth: i32 = -1;
    while i + 4 <= stru.len() {
        let tok = read_be_u32(stru, i).ok()?;
        i += 4;
        match tok {
            FDT_BEGIN_NODE => {
                depth += 1;
                let start = i;
                while i < stru.len() && stru[i] != 0 { i += 1; }
                if i >= stru.len() { return None; }
                let name = &stru[start..i];
                i = (i + 1 + 3) & !3;
                // `memory` or `memory@<addr>` at depth 1.
                if depth == 1 && name.starts_with(b"memory")
                    && (name.len() == 6 || name.get(6) == Some(&b'@')) {
                    in_mem = true;
                    mem_depth = depth;
                }
            }
            FDT_END_NODE => {
                if in_mem && depth == mem_depth { in_mem = false; }
                depth -= 1;
            }
            FDT_PROP => {
                if i + 8 > stru.len() { return None; }
                let plen  = read_be_u32(stru, i).ok()? as usize;
                let pname = read_be_u32(stru, i + 4).ok()? as usize;
                i += 8;
                let pdata = stru.get(i .. i + plen)?;
                if in_mem {
                    let name_end = strs[pname..].iter().position(|&b| b == 0)?;
                    if &strs[pname..pname + name_end] == b"reg" && plen >= 16 {
                        let base = u64::from_be_bytes(pdata[0..8].try_into().ok()?);
                        let size = u64::from_be_bytes(pdata[8..16].try_into().ok()?);
                        return Some((base, size));
                    }
                }
                i += (plen + 3) & !3;
            }
            FDT_NOP => {}
            FDT_END => return None,
            _ => return None,
        }
    }
    None
}

/// Enumerate `/cpus/cpu@*` nodes → each CPU's `reg` value, which on arm64
/// is the MPIDR_EL1 affinity the PSCI `CPU_ON` call targets. Fills `out`
/// with up to `out.len()` MPIDRs (in DTB order; index 0 is typically the
/// boot CPU) and returns the total cpu-node count seen. The `/cpus`
/// `#address-cells` (FDT default 2; arm64 QEMU `virt` uses 1) governs how
/// many big-endian cells each `reg` occupies; cells are folded low-order
/// into the u64. Used by the self-bootstrap SMP path to drive `CPU_ON`.
/// # C: O(dtb_struct_size)
pub fn enum_cpus(bytes: &[u8], out: &mut [u64]) -> usize {
    let h = match parse_header(bytes) { Ok(h) => h, Err(_) => return 0 };
    let stru = match bytes.get(h.off_dt_struct as usize ..
                              (h.off_dt_struct + h.size_dt_struct) as usize) {
        Some(s) => s, None => return 0,
    };
    let strs = match bytes.get(h.off_dt_strings as usize ..
                              (h.off_dt_strings + h.size_dt_strings) as usize) {
        Some(s) => s, None => return 0,
    };
    let mut i = 0usize;
    let mut depth: i32 = -1;
    let mut cpus_depth: i32 = -1;       // depth of the /cpus node (-1 = outside)
    let mut addr_cells: u32 = 2;        // /cpus #address-cells (FDT default)
    let mut in_cpu = false;             // inside a /cpus/cpu@* child
    let mut count = 0usize;
    while i + 4 <= stru.len() {
        let tok = match read_be_u32(stru, i) { Ok(t) => t, Err(_) => return count };
        i += 4;
        match tok {
            FDT_BEGIN_NODE => {
                depth += 1;
                let start = i;
                while i < stru.len() && stru[i] != 0 { i += 1; }
                if i >= stru.len() { return count; }
                let name = &stru[start..i];
                i = (i + 1 + 3) & !3;
                if depth == 1 && name == b"cpus" {
                    cpus_depth = depth;
                } else if cpus_depth >= 0 && depth == cpus_depth + 1
                    && (name == b"cpu" || name.starts_with(b"cpu@")) {
                    in_cpu = true;
                }
            }
            FDT_END_NODE => {
                if in_cpu && depth == cpus_depth + 1 { in_cpu = false; }
                if depth == cpus_depth { cpus_depth = -1; }
                depth -= 1;
            }
            FDT_PROP => {
                if i + 8 > stru.len() { return count; }
                let plen  = match read_be_u32(stru, i)     { Ok(v) => v as usize, Err(_) => return count };
                let pname = match read_be_u32(stru, i + 4) { Ok(v) => v as usize, Err(_) => return count };
                i += 8;
                let pdata = match stru.get(i .. i + plen) { Some(d) => d, None => return count };
                let name_end = match strs.get(pname..).and_then(|s| s.iter().position(|&b| b == 0)) {
                    Some(e) => e, None => return count,
                };
                let pname_str = &strs[pname..pname + name_end];
                // #address-cells on /cpus itself governs each cpu reg width.
                if cpus_depth >= 0 && depth == cpus_depth && !in_cpu
                    && pname_str == b"#address-cells" && plen >= 4 {
                    if let Ok(v) = read_be_u32(pdata, 0) {
                        if v >= 1 && v <= 2 { addr_cells = v; }
                    }
                }
                if in_cpu && pname_str == b"reg" && plen >= 4 * addr_cells as usize {
                    let mut mpidr = 0u64;
                    for c in 0..addr_cells as usize {
                        let cell = read_be_u32(pdata, c * 4).unwrap_or(0) as u64;
                        mpidr = (mpidr << 32) | cell;
                    }
                    if count < out.len() { out[count] = mpidr; }
                    count += 1;
                }
                i += (plen + 3) & !3;
            }
            FDT_NOP => {}
            FDT_END => return count,
            _ => return count,
        }
    }
    count
}

#[inline]
fn read_be_u32(buf: &[u8], off: usize) -> KResult<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)
        .ok_or(DtbError::Truncated)?
        .try_into()
        .map_err(|_| DtbError::Truncated)?;
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(
        magic: u32, totalsize: u32, version: u32, last_comp: u32,
    ) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![0u8; 64];
        v[0..4]  .copy_from_slice(&magic.to_be_bytes());
        v[4..8]  .copy_from_slice(&totalsize.to_be_bytes());
        v[8..12] .copy_from_slice(&40u32.to_be_bytes());
        v[12..16].copy_from_slice(&48u32.to_be_bytes());
        v[16..20].copy_from_slice(&32u32.to_be_bytes());
        v[20..24].copy_from_slice(&version.to_be_bytes());
        v[24..28].copy_from_slice(&last_comp.to_be_bytes());
        v[28..32].copy_from_slice(&0u32.to_be_bytes());
        v[32..36].copy_from_slice(&8u32.to_be_bytes());
        v[36..40].copy_from_slice(&8u32.to_be_bytes());
        v
    }

    // Assemble a minimal FDT: root → /cpus(#address-cells=ac) → N cpu@i
    // nodes each with reg = its index. Returns the full blob.
    fn build_cpus_dtb(ac: u32, mpidrs: &[u64]) -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        // strings block
        let mut strs: Vec<u8> = Vec::new();
        let off_ac = strs.len() as u32; strs.extend_from_slice(b"#address-cells\0");
        let off_reg = strs.len() as u32; strs.extend_from_slice(b"reg\0");
        // struct block
        let mut s: Vec<u8> = Vec::new();
        let tok = |s: &mut Vec<u8>, t: u32| s.extend_from_slice(&t.to_be_bytes());
        let node = |s: &mut Vec<u8>, name: &[u8]| {
            s.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
            s.extend_from_slice(name); s.push(0);
            while s.len() % 4 != 0 { s.push(0); }
        };
        let prop = |s: &mut Vec<u8>, noff: u32, data: &[u8]| {
            s.extend_from_slice(&FDT_PROP.to_be_bytes());
            s.extend_from_slice(&(data.len() as u32).to_be_bytes());
            s.extend_from_slice(&noff.to_be_bytes());
            s.extend_from_slice(data);
            while s.len() % 4 != 0 { s.push(0); }
        };
        node(&mut s, b"");                       // root
        node(&mut s, b"cpus");                   // /cpus
        prop(&mut s, off_ac, &ac.to_be_bytes()); // #address-cells
        for (idx, m) in mpidrs.iter().enumerate() {
            let mut nm = alloc::format!("cpu@{idx}").into_bytes();
            node(&mut s, &nm);
            nm.clear();
            // reg = ac big-endian cells holding the low bits of mpidr
            let mut reg: Vec<u8> = Vec::new();
            for c in (0..ac).rev() {
                reg.extend_from_slice(&(((*m >> (c * 32)) & 0xffff_ffff) as u32).to_be_bytes());
            }
            prop(&mut s, off_reg, &reg);
            tok(&mut s, FDT_END_NODE);           // end cpu@i
        }
        tok(&mut s, FDT_END_NODE);               // end /cpus
        tok(&mut s, FDT_END_NODE);               // end root
        tok(&mut s, FDT_END);
        // header
        let off_struct = 40u32;
        let off_strings = off_struct + s.len() as u32;
        let total = off_strings + strs.len() as u32;
        let mut v = alloc::vec![0u8; 40];
        v[0..4]  .copy_from_slice(&FDT_MAGIC.to_be_bytes());
        v[4..8]  .copy_from_slice(&total.to_be_bytes());
        v[8..12] .copy_from_slice(&off_struct.to_be_bytes());
        v[12..16].copy_from_slice(&off_strings.to_be_bytes());
        v[16..20].copy_from_slice(&total.to_be_bytes()); // off_mem_rsvmap (empty)
        v[20..24].copy_from_slice(&17u32.to_be_bytes());
        v[24..28].copy_from_slice(&FDT_LAST_COMPAT_VERSION.to_be_bytes());
        v[28..32].copy_from_slice(&0u32.to_be_bytes());
        v[32..36].copy_from_slice(&(strs.len() as u32).to_be_bytes());
        v[36..40].copy_from_slice(&(s.len() as u32).to_be_bytes());
        v.extend_from_slice(&s);
        v.extend_from_slice(&strs);
        v
    }

    #[test]
    fn enum_cpus_single_cell() {
        let dtb = build_cpus_dtb(1, &[0, 1, 2, 3]);
        let mut out = [0u64; 8];
        let n = enum_cpus(&dtb, &mut out);
        assert_eq!(n, 4);
        assert_eq!(&out[..4], &[0, 1, 2, 3]);
    }

    #[test]
    fn enum_cpus_two_cell_affinity() {
        // Aff1=1 → MPIDR 0x1_0000_0000 in a 2-cell reg.
        let dtb = build_cpus_dtb(2, &[0x0000_0000, 0x1_0000_0001]);
        let mut out = [0u64; 4];
        let n = enum_cpus(&dtb, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0], 0);
        assert_eq!(out[1], 0x1_0000_0001);
    }

    #[test]
    fn enum_cpus_counts_beyond_out_capacity() {
        let dtb = build_cpus_dtb(1, &[0, 1, 2, 3]);
        let mut out = [0u64; 2];
        let n = enum_cpus(&dtb, &mut out);
        assert_eq!(n, 4);                 // total seen
        assert_eq!(&out[..2], &[0, 1]);   // only first 2 stored
    }

    #[test]
    fn rejects_truncated() {
        let buf = alloc::vec![0u8; 16];
        assert_eq!(parse_header(&buf).err(), Some(DtbError::Truncated));
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = build(0xdead_beef, 64, 17, FDT_LAST_COMPAT_VERSION);
        assert_eq!(parse_header(&buf).err(), Some(DtbError::BadMagic));
    }

    #[test]
    fn accepts_known_version() {
        let buf = build(FDT_MAGIC, 64, 17, FDT_LAST_COMPAT_VERSION);
        let h = parse_header(&buf).unwrap();
        assert_eq!(h.magic, FDT_MAGIC);
        assert_eq!(h.totalsize, 64);
        assert_eq!(h.last_comp_version, FDT_LAST_COMPAT_VERSION);
    }

    #[test]
    fn rejects_future_compat_version() {
        let buf = build(FDT_MAGIC, 64, 99, FDT_LAST_COMPAT_VERSION + 1);
        assert_eq!(parse_header(&buf).err(), Some(DtbError::UnsupportedVersion));
    }

    #[test]
    fn rejects_totalsize_exceeding_buffer() {
        let mut buf = build(FDT_MAGIC, 1024, 17, FDT_LAST_COMPAT_VERSION);
        buf.truncate(64); // claim totalsize=1024 but only 64 B present
        assert_eq!(parse_header(&buf).err(), Some(DtbError::Truncated));
    }

    #[test]
    fn fdt_magic_is_big_endian_d00dfeed() {
        // Pin the constant — bootloaders write the magic in big-endian
        // wire order; we read with `from_be_bytes`.
        assert_eq!(FDT_MAGIC, 0xd00d_feed);
    }
}
