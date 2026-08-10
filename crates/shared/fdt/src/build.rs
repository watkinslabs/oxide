// Writing a flattened device tree, for the case where the firmware supplied
// none.
//
// An arm64 UEFI machine that describes itself with ACPI publishes no FDT, and
// an arm64 kernel is still expected to have one: userspace depends on it, and
// the kexec loader reads the raw blob and refuses an image without it.
//
// No allocator: the caller supplies the output buffer, which on the boot path
// is a page-aligned BSS block the memmap can reserve. Property names collect
// into a small fixed scratch, since a synthesized tree has a handful of them.

use crate::header::{
    FDT_BEGIN_NODE, FDT_END, FDT_END_NODE, FDT_HEADER_LEN, FDT_LAST_COMPAT_VERSION, FDT_MAGIC,
    FDT_PROP, FDT_RSVMAP_ENTRY_LEN,
};

/// Offset of the memory reservation block. The block is mandatory even when it
/// reserves nothing — a header pointing at 0 is refused outright by a reader
/// enforcing `off >= header_size`, which rejects the whole blob.
const OFF_MEM_RSVMAP: usize = FDT_HEADER_LEN;
/// Offset of the struct block: past the header and the reservation block's
/// terminating all-zero entry.
const OFF_DT_STRUCT: usize = OFF_MEM_RSVMAP + FDT_RSVMAP_ENTRY_LEN;

/// Bytes of property names one synthesized tree may use. The boot-path tree
/// uses under 120; overflowing sets the error flag rather than truncating a
/// name into a different one.
pub const MAX_STRINGS: usize = 256;

/// Appends nodes and properties into `buf`, then stamps the header.
///
/// Errors are latched, not returned per call: a builder that has overflowed
/// its buffer or its string scratch yields `None` from [`Builder::finish`], so
/// a caller cannot accidentally publish a half-written blob by ignoring one
/// intermediate result.
pub struct Builder<'a> {
    buf: &'a mut [u8],
    pos: usize,
    strs: [u8; MAX_STRINGS],
    slen: usize,
    depth: i32,
    err: bool,
    /// Open streamed property: where its length field sits, and where its data
    /// began. `None` when no property is open.
    open_prop: Option<(usize, usize)>,
}

impl<'a> Builder<'a> {
    /// Start a blob in `buf`. The struct block begins right after the header.
    /// # C: O(1)
    pub fn new(buf: &'a mut [u8]) -> Self {
        let err = buf.len() < OFF_DT_STRUCT;
        if !err {
            // Empty reservation block: one all-zero terminating entry.
            for b in buf[OFF_MEM_RSVMAP..OFF_DT_STRUCT].iter_mut() { *b = 0; }
        }
        Builder { buf, pos: OFF_DT_STRUCT, strs: [0; MAX_STRINGS], slen: 0, depth: 0, err, open_prop: None }
    }

    fn put(&mut self, bytes: &[u8]) {
        if self.err { return; }
        let end = self.pos + bytes.len();
        if end > self.buf.len() { self.err = true; return; }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
    }

    fn pad4(&mut self) {
        while !self.err && self.pos % 4 != 0 { self.put(&[0]); }
    }

    fn tok(&mut self, t: u32) { self.put(&t.to_be_bytes()); }

    /// Offset of `name` in the strings block, appending it if new. Reusing an
    /// existing offset is what keeps a repeated property name from spending
    /// the scratch twice.
    fn str_off(&mut self, name: &[u8]) -> u32 {
        let mut i = 0usize;
        while i < self.slen {
            let mut j = i;
            while j < self.slen && self.strs[j] != 0 { j += 1; }
            if &self.strs[i..j] == name { return i as u32; }
            i = j + 1;
        }
        let need = name.len() + 1;
        if self.slen + need > MAX_STRINGS { self.err = true; return 0; }
        self.strs[self.slen..self.slen + name.len()].copy_from_slice(name);
        self.slen += name.len();
        self.strs[self.slen] = 0;
        self.slen += 1;
        (self.slen - need) as u32
    }

    /// Open a node. `""` is the root. # C: O(len)
    pub fn begin_node(&mut self, name: &[u8]) -> &mut Self {
        self.tok(FDT_BEGIN_NODE);
        self.put(name);
        self.put(&[0]);
        self.pad4();
        self.depth += 1;
        self
    }

    /// Close the innermost open node. # C: O(1)
    pub fn end_node(&mut self) -> &mut Self {
        if self.depth <= 0 { self.err = true; return self; }
        self.depth -= 1;
        self.tok(FDT_END_NODE);
        self
    }

    /// Add a property with raw bytes to the innermost open node. Properties
    /// must precede child nodes, as the format requires. # C: O(len)
    pub fn prop(&mut self, name: &[u8], data: &[u8]) -> &mut Self {
        if self.depth <= 0 { self.err = true; return self; }
        let off = self.str_off(name);
        self.tok(FDT_PROP);
        self.put(&(data.len() as u32).to_be_bytes());
        self.put(&off.to_be_bytes());
        self.put(data);
        self.pad4();
        self
    }

    /// One big-endian cell. # C: O(1)
    pub fn prop_u32(&mut self, name: &[u8], v: u32) -> &mut Self { self.prop(name, &v.to_be_bytes()) }

    /// Two big-endian cells, the device-tree spelling of a 64-bit value.
    /// # C: O(1)
    pub fn prop_u64(&mut self, name: &[u8], v: u64) -> &mut Self { self.prop(name, &v.to_be_bytes()) }

    /// NUL-terminated string property. # C: O(len)
    pub fn prop_str(&mut self, name: &[u8], v: &[u8]) -> &mut Self {
        if self.depth <= 0 { self.err = true; return self; }
        let off = self.str_off(name);
        self.tok(FDT_PROP);
        self.put(&((v.len() + 1) as u32).to_be_bytes());
        self.put(&off.to_be_bytes());
        self.put(v);
        self.put(&[0]);
        self.pad4();
        self
    }

    /// Open a property whose value is appended in pieces, for a value built
    /// from a variable number of cells. Close it with [`Builder::end_prop`].
    /// # C: O(1)
    pub fn begin_prop(&mut self, name: &[u8]) -> &mut Self {
        if self.depth <= 0 || self.open_prop.is_some() { self.err = true; return self; }
        let off = self.str_off(name);
        self.tok(FDT_PROP);
        let len_at = self.pos;
        self.put(&0u32.to_be_bytes());
        self.put(&off.to_be_bytes());
        self.open_prop = Some((len_at, self.pos));
        self
    }

    /// Append raw bytes to the open property. # C: O(len)
    pub fn prop_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        if self.open_prop.is_none() { self.err = true; return self; }
        self.put(bytes);
        self
    }

    /// Close the open property, back-patching its length. # C: O(1)
    pub fn end_prop(&mut self) -> &mut Self {
        let Some((len_at, data_at)) = self.open_prop.take() else { self.err = true; return self; };
        if self.err { return self; }
        let len = (self.pos - data_at) as u32;
        self.buf[len_at..len_at + 4].copy_from_slice(&len.to_be_bytes());
        self.pad4();
        self
    }

    /// Close the blob and stamp its header. `None` when anything overflowed,
    /// when a node is still open, or when the strings block does not fit —
    /// every one of which would otherwise produce a blob that parses into
    /// something other than what was written.
    /// # C: O(strings_len)
    pub fn finish(mut self) -> Option<usize> {
        if self.open_prop.is_some() { return None; }
        self.tok(FDT_END);
        if self.err || self.depth != 0 { return None; }
        let struct_len = self.pos - OFF_DT_STRUCT;
        let off_strings = self.pos;
        let total = off_strings + self.slen;
        if total > self.buf.len() { return None; }
        let (slen, strs) = (self.slen, self.strs);
        self.buf[off_strings..off_strings + slen].copy_from_slice(&strs[..slen]);
        let h = &mut self.buf[..FDT_HEADER_LEN];
        h[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&(total as u32).to_be_bytes());
        h[8..12].copy_from_slice(&(OFF_DT_STRUCT as u32).to_be_bytes());
        h[12..16].copy_from_slice(&(off_strings as u32).to_be_bytes());
        h[16..20].copy_from_slice(&(OFF_MEM_RSVMAP as u32).to_be_bytes());
        h[20..24].copy_from_slice(&17u32.to_be_bytes());
        h[24..28].copy_from_slice(&FDT_LAST_COMPAT_VERSION.to_be_bytes());
        h[28..32].copy_from_slice(&0u32.to_be_bytes());
        h[32..36].copy_from_slice(&(slen as u32).to_be_bytes());
        h[36..40].copy_from_slice(&(struct_len as u32).to_be_bytes());
        Some(total)
    }
}

/// What an arm64 UEFI boot knows about itself once the firmware has published
/// no device tree of its own.
///
/// Deliberately carries no firmware-handoff table pointer: a tree advertising
/// one makes the next kernel take the firmware path and then demand the memory
/// map that goes with it, and this stub keeps no copy of that map. Measured — a
/// relocated kernel handed the half version reported the missing property and
/// panicked in early page-table setup with no memory at all. Claiming half a
/// handoff is worse than claiming none.
#[derive(Copy, Clone, Debug, Default)]
pub struct UefiHandoff<'a> {
    /// Kernel command line, without a trailing NUL.
    pub bootargs: &'a [u8],
    /// Usable RAM as `(base, size)` pairs. This is what makes the tree a
    /// description of the machine rather than a container for the command
    /// line, and it is the property the next kernel cannot boot without.
    pub memory: &'a [(u64, u64)],
}

/// Longest `/memory` unit name this writes: `memory@` plus 16 hex digits.
const MEMORY_NODE_NAME_MAX: usize = 7 + 16;

/// Build the tree an arm64 UEFI boot gets when its firmware supplies none: a
/// root with the standard cell counts, a `/memory` node describing usable RAM,
/// and `/chosen` carrying the command line. Returns the blob's length in `buf`.
///
/// The `/memory` node is the point. Everything downstream — this kernel's own
/// PMM on the device-tree path, and any kernel `kexec` hands this tree to —
/// learns where RAM is from it, and a tree without one describes a machine
/// with no memory.
/// # C: O(bootargs.len() + memory.len())
pub fn uefi_stub_tree(buf: &mut [u8], h: &UefiHandoff) -> Option<usize> {
    let mut b = Builder::new(buf);
    b.begin_node(b"");
    b.prop_u32(b"#address-cells", 2);
    b.prop_u32(b"#size-cells", 2);
    if let Some((first, _)) = h.memory.first() {
        let mut name = [0u8; MEMORY_NODE_NAME_MAX];
        let n = memory_node_name(&mut name, *first);
        b.begin_node(&name[..n]);
        b.prop_str(b"device_type", b"memory");
        b.begin_prop(b"reg");
        for (base, size) in h.memory {
            b.prop_bytes(&base.to_be_bytes());
            b.prop_bytes(&size.to_be_bytes());
        }
        b.end_prop();
        b.end_node();
    }
    b.begin_node(b"chosen");
    if !h.bootargs.is_empty() { b.prop_str(b"bootargs", h.bootargs); }
    b.end_node();
    b.end_node();
    b.finish()
}

/// `memory@<hex base>` into `out`, returning its length. Lower-case hex with
/// no leading zeros, the device-tree unit-address convention.
fn memory_node_name(out: &mut [u8; MEMORY_NODE_NAME_MAX], base: u64) -> usize {
    out[..7].copy_from_slice(b"memory@");
    let mut n = 7;
    let mut started = false;
    for shift in (0..16).rev() {
        let d = ((base >> (shift * 4)) & 0xf) as u8;
        if d == 0 && !started && shift != 0 { continue; }
        started = true;
        out[n] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        n += 1;
    }
    n
}
