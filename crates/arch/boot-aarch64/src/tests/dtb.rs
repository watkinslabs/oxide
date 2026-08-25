use super::*;

fn build(magic: u32, totalsize: u32, version: u32, last_comp: u32) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; 64];
    v[0..4].copy_from_slice(&magic.to_be_bytes()); v[4..8].copy_from_slice(&totalsize.to_be_bytes());
    v[8..12].copy_from_slice(&40u32.to_be_bytes()); v[12..16].copy_from_slice(&48u32.to_be_bytes());
    v[16..20].copy_from_slice(&32u32.to_be_bytes()); v[20..24].copy_from_slice(&version.to_be_bytes());
    v[24..28].copy_from_slice(&last_comp.to_be_bytes()); v[28..32].copy_from_slice(&0u32.to_be_bytes());
    v[32..36].copy_from_slice(&8u32.to_be_bytes()); v[36..40].copy_from_slice(&8u32.to_be_bytes()); v
}

#[test]
fn rejects_truncated() {
    assert_eq!(parse_header(&alloc::vec![0u8; 16]).err(), Some(DtbError::Truncated));
}

fn build_pl011_fdt(freq: u32, direct: bool) -> alloc::vec::Vec<u8> {
    let mut strs = alloc::vec::Vec::new();
    let off = |s: &mut alloc::vec::Vec<u8>, n: &[u8]| { let o = s.len() as u32; s.extend_from_slice(n); s.push(0); o };
    let o_compat = off(&mut strs, b"compatible"); let o_clocks = off(&mut strs, b"clocks");
    let o_phandle = off(&mut strs, b"phandle"); let o_freq = off(&mut strs, b"clock-frequency");
    let mut st = alloc::vec::Vec::new();
    let tok = |s: &mut alloc::vec::Vec<u8>, t: u32| s.extend_from_slice(&t.to_be_bytes());
    let name = |s: &mut alloc::vec::Vec<u8>, n: &[u8]| { s.extend_from_slice(n); s.push(0); while s.len() % 4 != 0 { s.push(0); } };
    let prop = |s: &mut alloc::vec::Vec<u8>, no: u32, data: &[u8]| { s.extend_from_slice(&FDT_PROP.to_be_bytes()); s.extend_from_slice(&(data.len() as u32).to_be_bytes()); s.extend_from_slice(&no.to_be_bytes()); s.extend_from_slice(data); while s.len() % 4 != 0 { s.push(0); } };
    tok(&mut st, FDT_BEGIN_NODE); name(&mut st, b""); tok(&mut st, FDT_BEGIN_NODE); name(&mut st, b"pl011@9000000");
    prop(&mut st, o_compat, b"arm,pl011\0");
    if direct { prop(&mut st, o_freq, &freq.to_be_bytes()); } else { prop(&mut st, o_clocks, &1u32.to_be_bytes()); }
    tok(&mut st, FDT_END_NODE);
    if !direct { tok(&mut st, FDT_BEGIN_NODE); name(&mut st, b"apb-pclk"); prop(&mut st, o_phandle, &1u32.to_be_bytes()); prop(&mut st, o_freq, &freq.to_be_bytes()); tok(&mut st, FDT_END_NODE); }
    tok(&mut st, FDT_END_NODE); tok(&mut st, FDT_END);
    let off_struct = 40u32; let off_strings = off_struct + st.len() as u32; let total = off_strings + strs.len() as u32;
    let mut v = alloc::vec![0u8; 40]; v[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes()); v[4..8].copy_from_slice(&total.to_be_bytes());
    v[8..12].copy_from_slice(&off_struct.to_be_bytes()); v[12..16].copy_from_slice(&off_strings.to_be_bytes());
    v[16..20].copy_from_slice(&0u32.to_be_bytes()); v[20..24].copy_from_slice(&17u32.to_be_bytes());
    v[24..28].copy_from_slice(&FDT_LAST_COMPAT_VERSION.to_be_bytes()); v[28..32].copy_from_slice(&0u32.to_be_bytes());
    v[32..36].copy_from_slice(&(strs.len() as u32).to_be_bytes()); v[36..40].copy_from_slice(&(st.len() as u32).to_be_bytes());
    v.extend_from_slice(&st); v.extend_from_slice(&strs); v
}

#[test]
fn pl011_clock_via_phandle() { assert_eq!(pl011_clock_hz(&build_pl011_fdt(24_000_000, false)), Some(24_000_000)); }
#[test]
fn pl011_clock_direct_on_node() { assert_eq!(pl011_clock_hz(&build_pl011_fdt(48_000_000, true)), Some(48_000_000)); }
#[test]
fn pl011_clock_absent_returns_none() { assert_eq!(pl011_clock_hz(&build(FDT_MAGIC, 64, 17, FDT_LAST_COMPAT_VERSION)), None); }
#[test]
fn rejects_bad_magic() { assert_eq!(parse_header(&build(0xdead_beef, 64, 17, FDT_LAST_COMPAT_VERSION)).err(), Some(DtbError::BadMagic)); }
#[test]
fn accepts_known_version() { let h = parse_header(&build(FDT_MAGIC, 64, 17, FDT_LAST_COMPAT_VERSION)).unwrap(); assert_eq!((h.magic, h.totalsize, h.last_comp_version), (FDT_MAGIC, 64, FDT_LAST_COMPAT_VERSION)); }
#[test]
fn rejects_future_compat_version() { assert_eq!(parse_header(&build(FDT_MAGIC, 64, 99, FDT_LAST_COMPAT_VERSION + 1)).err(), Some(DtbError::UnsupportedVersion)); }
#[test]
fn rejects_totalsize_exceeding_buffer() { let mut buf = build(FDT_MAGIC, 1024, 17, FDT_LAST_COMPAT_VERSION); buf.truncate(64); assert_eq!(parse_header(&buf).err(), Some(DtbError::Truncated)); }
#[test]
fn fdt_magic_is_big_endian_d00dfeed() { assert_eq!(FDT_MAGIC, 0xd00d_feed); }
