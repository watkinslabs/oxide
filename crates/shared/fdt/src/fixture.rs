// Fixture builder for the FDT reader: a minimal flattened-device-tree writer
// plus the qemu `virt` shape the aarch64 boot path actually parses. Used by
// this crate's own tests and by the kernel-side `/sys/firmware/devicetree`
// exporter's tests, so both exercise the same wire images.

use alloc::vec::Vec;

use crate::header::{FDT_HEADER_LEN, FDT_LAST_COMPAT_VERSION, FDT_MAGIC};

const TOK_BEGIN_NODE: u32 = 1;
const TOK_END_NODE: u32 = 2;
const TOK_PROP: u32 = 3;
const TOK_END: u32 = 9;

/// Minimal flattened-device-tree writer: append nodes/properties in wire
/// order, then `finish()` for the assembled blob.
pub struct Fdt { strs: Vec<u8>, st: Vec<u8> }

impl Fdt {
    pub fn new() -> Self { Fdt { strs: Vec::new(), st: Vec::new() } }

    /// Offset of `name` in the strings block, appending it if new.
    fn str_off(&mut self, name: &[u8]) -> u32 {
        let mut i = 0usize;
        while i < self.strs.len() {
            let end = i + self.strs[i..].iter().position(|&b| b == 0).unwrap();
            if &self.strs[i..end] == name { return i as u32; }
            i = end + 1;
        }
        let o = self.strs.len() as u32;
        self.strs.extend_from_slice(name);
        self.strs.push(0);
        o
    }

    fn pad4(&mut self) { while self.st.len() % 4 != 0 { self.st.push(0); } }

    pub fn begin(&mut self, name: &str) -> &mut Self {
        self.st.extend_from_slice(&TOK_BEGIN_NODE.to_be_bytes());
        self.st.extend_from_slice(name.as_bytes());
        self.st.push(0);
        self.pad4();
        self
    }

    pub fn end(&mut self) -> &mut Self {
        self.st.extend_from_slice(&TOK_END_NODE.to_be_bytes());
        self
    }

    pub fn prop(&mut self, name: &str, data: &[u8]) -> &mut Self {
        let off = self.str_off(name.as_bytes());
        self.st.extend_from_slice(&TOK_PROP.to_be_bytes());
        self.st.extend_from_slice(&(data.len() as u32).to_be_bytes());
        self.st.extend_from_slice(&off.to_be_bytes());
        self.st.extend_from_slice(data);
        self.pad4();
        self
    }

    pub fn prop_u32(&mut self, name: &str, v: u32) -> &mut Self { self.prop(name, &v.to_be_bytes()) }

    pub fn prop_str(&mut self, name: &str, v: &str) -> &mut Self {
        let mut b = Vec::from(v.as_bytes());
        b.push(0);
        self.prop(name, &b)
    }

    pub fn finish(&mut self) -> Vec<u8> {
        let mut st = self.st.clone();
        st.extend_from_slice(&TOK_END.to_be_bytes());
        let off_rsvmap = FDT_HEADER_LEN as u32;
        let off_struct = off_rsvmap + 16;
        let off_strings = off_struct + st.len() as u32;
        let total = off_strings + self.strs.len() as u32;
        let mut v = alloc::vec![0u8; FDT_HEADER_LEN + 16];
        v[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        v[4..8].copy_from_slice(&total.to_be_bytes());
        v[8..12].copy_from_slice(&off_struct.to_be_bytes());
        v[12..16].copy_from_slice(&off_strings.to_be_bytes());
        v[16..20].copy_from_slice(&off_rsvmap.to_be_bytes());
        v[20..24].copy_from_slice(&17u32.to_be_bytes());
        v[24..28].copy_from_slice(&FDT_LAST_COMPAT_VERSION.to_be_bytes());
        v[28..32].copy_from_slice(&0u32.to_be_bytes());
        v[32..36].copy_from_slice(&(self.strs.len() as u32).to_be_bytes());
        v[36..40].copy_from_slice(&(st.len() as u32).to_be_bytes());
        v.extend_from_slice(&st);
        v.extend_from_slice(&self.strs);
        v
    }
}

/// The qemu `virt` shape the aarch64 boot path actually parses: a root with
/// `/chosen`, `/memory@40000000`, `/cpus` (1 address cell, two CPUs), a PL011
/// and its `apb-pclk` clock.
pub fn virt_like() -> Vec<u8> {
    let mut f = Fdt::new();
    f.begin("");
    f.prop_str("model", "linux,dummy-virt");
    f.prop_str("compatible", "linux,dummy-virt");
    f.begin("chosen");
    f.prop_str("bootargs", "console=ttyAMA0 root=/dev/vda2");
    f.end();
    f.begin("memory@40000000");
    f.prop_str("device_type", "memory");
    let mut reg = Vec::new();
    reg.extend_from_slice(&0x4000_0000u64.to_be_bytes());
    reg.extend_from_slice(&0x8000_0000u64.to_be_bytes());
    f.prop("reg", &reg);
    f.end();
    f.begin("cpus");
    f.prop_u32("#address-cells", 1);
    f.prop_u32("#size-cells", 0);
    f.begin("cpu@0");
    f.prop_u32("reg", 0);
    f.end();
    f.begin("cpu@1");
    f.prop_u32("reg", 1);
    f.end();
    f.end();
    f.begin("pl011@9000000");
    f.prop_str("compatible", "arm,pl011");
    f.prop_u32("clocks", 1);
    f.end();
    f.begin("apb-pclk");
    f.prop_u32("phandle", 1);
    f.prop_u32("clock-frequency", 24_000_000);
    f.end();
    f.end();
    f.finish()
}
