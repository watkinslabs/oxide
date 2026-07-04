#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
    NotFound,
}

pub type KResult<T> = core::result::Result<T, Error>;

/// (bus, device, function) tuple.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Bdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Bdf {
    /// 16-bit packed encoding for indexing.
    /// # C: O(1)
    pub const fn raw(self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_byte(s: &[u8]) -> Option<u8> {
    Some((hex_nibble(*s.first()?)? << 4) | hex_nibble(*s.get(1)?)?)
}

/// Parse a PCI model address in the kernel's canonical `0000:bb:dd.f` form.
/// # C: O(1)
pub fn parse_bdf_addr(addr: &str) -> Option<Bdf> {
    let b = addr.as_bytes();
    if b.len() != 12 || b[4] != b':' || b[7] != b':' || b[10] != b'.' {
        return None;
    }
    Some(Bdf {
        bus: hex_byte(&b[5..7])?,
        device: hex_byte(&b[8..10])?,
        function: hex_nibble(b[11])?,
    })
}

/// `ConfigSpaceReader`: arch-specific accessor for the per-BDF 256-byte config
/// space. x86 uses CF8/CFC; AArch64 ECAM MMIO.
pub trait ConfigSpaceReader: Send + Sync {
    /// Read a u32 from `(bdf, offset)`. Offset must be 4-aligned.
    fn read32(&self, bdf: Bdf, offset: u8) -> u32;
    /// Optional write (for BAR programming, MSI setup, etc.).
    fn write32(&self, bdf: Bdf, offset: u8, val: u32);
}

/// PCI command register bit: I/O Space Enable.
pub const COMMAND_IO: u16 = 1 << 0;
/// PCI command register bit: Memory Space Enable.
pub const COMMAND_MEMORY: u16 = 1 << 1;
/// PCI command register bit: Bus Master Enable.
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Read the low 16-bit PCI command register. # C: O(1)
pub fn read_command<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u16 {
    (r.read32(bdf, 0x04) & 0xFFFF) as u16
}

/// Write the low 16-bit PCI command register while preserving status bits.
/// # C: O(1)
pub fn write_command<R: ConfigSpaceReader>(r: &R, bdf: Bdf, command: u16) {
    let cur = r.read32(bdf, 0x04);
    r.write32(bdf, 0x04, (cur & 0xFFFF_0000) | command as u32);
}

/// Enable Memory Space and Bus Master for a function claimed by a driver.
/// Returns the previous command value so a driver can restore it on failed
/// probe or remove when it owns that policy.
/// # C: O(1)
pub fn enable_mem_bus_master<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u16 {
    let old = read_command(r, bdf);
    let new = old | COMMAND_MEMORY | COMMAND_BUS_MASTER;
    if new != old {
        write_command(r, bdf, new);
    }
    old
}

/// Disable Memory Space and Bus Master for a function.
///
/// Returns the previous command value so callers can restore it if desired.
/// # C: O(1)
pub fn disable_mem_bus_master<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u16 {
    let old = read_command(r, bdf);
    let restored = old & !(COMMAND_MEMORY | COMMAND_BUS_MASTER);
    if restored != old {
        write_command(r, bdf, restored);
    }
    old
}

/// Per-device decoded summary for the kernel's device list.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PciDevice {
    pub bdf: Bdf,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub header_type: u8,
}

impl PciDevice {
    /// # C: O(1)
    pub fn from_config<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> Option<Self> {
        let id = r.read32(bdf, 0x00);
        if id == 0xFFFF_FFFF || (id & 0xFFFF) == 0xFFFF {
            return None;
        }
        let vendor_id = (id & 0xFFFF) as u16;
        let device_id = (id >> 16) as u16;
        let class_rev = r.read32(bdf, 0x08);
        let revision = (class_rev & 0xFF) as u8;
        let prog_if = ((class_rev >> 8) & 0xFF) as u8;
        let subclass = ((class_rev >> 16) & 0xFF) as u8;
        let class_code = ((class_rev >> 24) & 0xFF) as u8;
        let header_type = ((r.read32(bdf, 0x0C) >> 16) & 0xFF) as u8;
        Some(Self {
            bdf,
            vendor_id,
            device_id,
            class_code,
            subclass,
            prog_if,
            revision,
            header_type,
        })
    }
}
