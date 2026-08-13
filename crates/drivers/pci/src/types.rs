use crate::uapi;
use core::sync::atomic::{AtomicPtr, Ordering};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
    NotFound,
}

pub type KResult<T> = core::result::Result<T, Error>;

/// Maximum ECAM windows early boot can retain and route without allocation.
pub const MAX_ECAM_WINDOWS: usize = 8;

/// Policy invoked immediately before PCI bus mastering becomes live. # type
pub type BusMasterAdmissionFn = fn(Bdf) -> bool;
static BUS_MASTER_ADMISSION: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// PCI segment plus its (bus, device, function) requester identifier.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Bdf {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// One canonical PCI requester alias used for DMA ownership.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DmaAlias { pub requester: Bdf, pub alias: Bdf }

/// PCI-owned explicit DMA requester aliases collected before IOMMU activation.
pub struct DmaAliases { entries: alloc::vec::Vec<DmaAlias> }
impl DmaAliases {
    /// Create an empty PCI DMA-alias inventory. # C: O(1)
    pub const fn new() -> Self { Self { entries: alloc::vec::Vec::new() } }
    /// Record one same-segment requester alias without duplicate entries. # C: O(N)
    pub fn add(&mut self, requester: Bdf, alias: Bdf) -> bool {
        if requester.segment != alias.segment || self.entries.iter().any(|entry| *entry == DmaAlias { requester, alias }) { return false; }
        self.entries.push(DmaAlias { requester, alias }); true
    }
    /// Return aliases registered for one requester. # C: O(N)
    pub fn for_requester(&self, requester: Bdf) -> impl Iterator<Item = Bdf> + '_ {
        self.entries.iter().filter(move |entry| entry.requester == requester).map(|entry| entry.alias)
    }
}

/// Add bridge-derived DMA aliases for `requesters`. `port_type` returns the
/// decoded PCIe type for a bridge, or `None` for conventional PCI. This mirrors
/// Linux's DMA-alias walk: PCIe root/upstream/downstream ports are transparent;
/// translation bridges contribute their own requester identity. # C: O(N^3)
pub fn add_topology_dma_aliases(
    aliases: &mut DmaAliases, requesters: &[Bdf], bridges: &[(Bdf, BridgeBuses)],
    port_type: impl Fn(Bdf) -> Option<crate::PcieType>,
) {
    for requester in requesters.iter().copied() {
        for &(bridge, buses) in bridges {
            if bridge.segment != requester.segment || requester.bus < buses.secondary || requester.bus > buses.subordinate { continue; }
            let translated = match port_type(bridge) {
                Some(crate::PcieType::PcieToPciBridge) => Bdf { segment: bridge.segment, bus: buses.subordinate, device: 0, function: 0 },
                Some(crate::PcieType::PciToPcieBridge) | None => bridge,
                _ => continue,
            };
            let _ = aliases.add(requester, translated);
        }
    }
}

impl Bdf {
/// 16-bit requester identifier. Segment remains a separate ownership key.
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

fn hex_word(s: &[u8]) -> Option<u16> {
    Some(((hex_nibble(*s.first()?)? as u16) << 12) | ((hex_nibble(*s.get(1)?)? as u16) << 8)
        | ((hex_nibble(*s.get(2)?)? as u16) << 4) | hex_nibble(*s.get(3)?)? as u16)
}

/// Parse a PCI model address in the kernel's canonical `0000:bb:dd.f` form.
/// # C: O(1)
pub fn parse_bdf_addr(addr: &str) -> Option<Bdf> {
    let b = addr.as_bytes();
    if b.len() != 12 || b[4] != b':' || b[7] != b':' || b[10] != b'.' {
        return None;
    }
    Some(Bdf {
        segment: hex_word(&b[..4])?,
        bus: hex_byte(&b[5..7])?,
        device: hex_byte(&b[8..10])?,
        function: hex_nibble(b[11])?,
    })
}

/// `ConfigSpaceReader`: arch-specific accessor for a PCI function's
/// configuration space. Production arches use ECAM MMIO or an
/// architecture-provided legacy configuration transport.
pub trait ConfigSpaceReader: Send + Sync {
    /// Read a u32 from `(bdf, offset)`. Offset must be 4-aligned.
    fn read32(&self, bdf: Bdf, offset: u8) -> u32;
    /// Optional write (for BAR programming, MSI setup, etc.).
    fn write32(&self, bdf: Bdf, offset: u8, val: u32);
    /// Read a dword from the complete PCIe configuration window.
    fn read32_ext(&self, bdf: Bdf, offset: u16) -> u32 { self.read32(bdf, offset as u8) }
    /// Write a dword in the complete PCIe configuration window.
    fn write32_ext(&self, bdf: Bdf, offset: u16, val: u32) { self.write32(bdf, offset as u8, val); }
    /// Native byte transaction; never synthesize it by rewriting a dword.
    fn read8_ext(&self, bdf: Bdf, offset: u16) -> u8 {
        (self.read32_ext(bdf, offset & !3) >> ((offset & 3) * 8)) as u8
    }
    /// Native word transaction; never synthesize it by rewriting a dword.
    fn read16_ext(&self, bdf: Bdf, offset: u16) -> u16 {
        (self.read32_ext(bdf, offset & !3) >> ((offset & 3) * 8)) as u16
    }
    /// Native byte transaction; never synthesize it by rewriting a dword.
    fn write8_ext(&self, bdf: Bdf, offset: u16, val: u8) {
        let base = offset & !3;
        let shift = (offset & 3) * 8;
        let old = self.read32_ext(bdf, base);
        self.write32_ext(bdf, base, (old & !(0xFF << shift)) | (u32::from(val) << shift));
    }
    /// Native word transaction; never synthesize it by rewriting a dword.
    fn write16_ext(&self, bdf: Bdf, offset: u16, val: u16) {
        let base = offset & !3;
        let shift = (offset & 3) * 8;
        let old = self.read32_ext(bdf, base);
        self.write32_ext(bdf, base, (old & !(0xFFFF << shift)) | (u32::from(val) << shift));
    }
}

/// Install or clear the sole PCI bus-master admission policy. # C: O(1)
pub fn set_bus_master_admission(f: Option<BusMasterAdmissionFn>) {
    BUS_MASTER_ADMISSION.store(f.map(|f| f as *mut ()).unwrap_or(core::ptr::null_mut()), Ordering::Release);
}

/// Decide whether one requester may acquire the Bus Master command bit. # C: O(1)
pub fn bus_master_admitted(bdf: Bdf) -> bool {
    let raw = BUS_MASTER_ADMISSION.load(Ordering::Acquire);
    if raw.is_null() { return true; }
    // SAFETY: raw originates only from set_bus_master_admission with this exact function signature.
    let f: BusMasterAdmissionFn = unsafe { core::mem::transmute(raw) };
    f(bdf)
}

/// PCI command register bit: I/O Space Enable.
pub const COMMAND_IO: u16 = 1 << 0;
/// PCI command register bit: Memory Space Enable.
pub const COMMAND_MEMORY: u16 = 1 << 1;
/// PCI command register bit: Bus Master Enable.
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;
/// PCI command bit: suppress legacy INTx while MSI/MSI-X is active.
pub const COMMAND_INTX_DISABLE: u16 = 1 << 10;

/// Compute the command-register INTx-disable transition. # C: O(1)
pub const fn intx_command_value(command: u16, disabled: bool) -> u16 {
    if disabled {
        command | COMMAND_INTX_DISABLE
    } else {
        command & !COMMAND_INTX_DISABLE
    }
}

/// Enable or disable legacy INTx while preserving every other command bit.
/// Returns the prior command value for teardown restoration. # C: O(1)
pub fn set_intx_disabled<R: ConfigSpaceReader>(r: &R, bdf: Bdf, disabled: bool) -> u16 {
    let old = read_command(r, bdf);
    let new = intx_command_value(old, disabled);
    if new != old { write_command(r, bdf, new); }
    old
}

/// Restore only the INTx-disable bit from a saved command value. # C: O(1)
pub fn restore_intx_disabled<R: ConfigSpaceReader>(r: &R, bdf: Bdf, previous: u16) -> u16 {
    let old = read_command(r, bdf);
    let restored = (old & !COMMAND_INTX_DISABLE) | (previous & COMMAND_INTX_DISABLE);
    if restored != old { write_command(r, bdf, restored); }
    old
}

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

/// Enable Memory Space decoding without granting DMA bus mastering.
///
/// Display adapters with a CPU-owned framebuffer need their BAR decoded, but
/// do not need (and must not implicitly receive) the Bus Master bit.
/// Returns the prior command value for teardown restoration. # C: O(1)
pub fn enable_mem_decode<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u16 {
    let old = read_command(r, bdf);
    let new = old | COMMAND_MEMORY;
    if new != old { write_command(r, bdf, new); }
    old
}

/// Enable Memory Space and Bus Master for a function claimed by a driver.
/// Returns the previous command value so a driver can restore it on failed
/// probe or remove when it owns that policy.
/// # C: O(1)
pub fn enable_mem_bus_master<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u16 {
    let old = read_command(r, bdf);
    if !bus_master_admitted(bdf) { return old; }
    let new = old | COMMAND_MEMORY | COMMAND_BUS_MASTER;
    if new != old {
        write_command(r, bdf, new);
    }
    old
}

/// Clear Bus Master while preserving I/O and Memory Space decoding.
///
/// Boot uses this to quiesce firmware-configured requesters before an IOMMU
/// domain is installed; the eventual owning driver enables bus mastering.
/// Returns the previous command value.
/// # C: O(1)
pub fn clear_bus_master<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u16 {
    let old = read_command(r, bdf);
    let new = old & !COMMAND_BUS_MASTER;
    if new != old { write_command(r, bdf, new); }
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

/// Restore only the Memory Space and Bus Master bits from a previous command
/// value, preserving all other currently-live command bits.
/// # C: O(1)
pub fn restore_mem_bus_master<R: ConfigSpaceReader>(r: &R, bdf: Bdf, previous: u16) -> u16 {
    let old = read_command(r, bdf);
    let restored = (old & !(COMMAND_MEMORY | COMMAND_BUS_MASTER))
        | (previous & (COMMAND_MEMORY | COMMAND_BUS_MASTER));
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

/// Bus window decoded from a PCI-to-PCI bridge configuration header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BridgeBuses { pub primary: u8, pub secondary: u8, pub subordinate: u8 }

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

/// Return the bus window of a live PCI-to-PCI bridge. # C: O(1)
pub fn bridge_buses<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> Option<BridgeBuses> {
    let d = PciDevice::from_config(r, bdf)?;
    if d.header_type & uapi::HEADER_TYPE_MASK != uapi::HEADER_TYPE_BRIDGE || d.class_code != uapi::CLASS_BRIDGE || d.subclass != uapi::SUBCLASS_PCI_TO_PCI { return None; }
    let buses = r.read32(bdf, uapi::BRIDGE_BUS_NUMBERS);
    let primary = buses as u8;
    let secondary = (buses >> 8) as u8;
    let subordinate = (buses >> 16) as u8;
    if secondary == 0 || secondary <= primary || subordinate < secondary { return None; }
    Some(BridgeBuses { primary, secondary, subordinate })
}

#[cfg(test)]
mod command_tests {
    use super::*;

    #[test]
    fn intx_transition_changes_only_owned_command_bit() {
        let original = COMMAND_IO | COMMAND_MEMORY | COMMAND_BUS_MASTER;
        assert_eq!(
            intx_command_value(original, true),
            original | COMMAND_INTX_DISABLE,
        );
        assert_eq!(
            intx_command_value(original | COMMAND_INTX_DISABLE, false),
            original,
        );
    }

    #[test]
    fn dma_aliases_keep_segments_separate_and_deduplicate() {
        let requester = Bdf { segment: 1, bus: 2, device: 3, function: 0 };
        let alias = Bdf { segment: 1, bus: 2, device: 4, function: 0 };
        let other_segment = Bdf { segment: 2, ..alias };
        let mut aliases = DmaAliases::new();
        assert!(aliases.add(requester, alias));
        assert!(!aliases.add(requester, alias));
        assert!(!aliases.add(requester, other_segment));
        assert_eq!(aliases.for_requester(requester).collect::<alloc::vec::Vec<_>>(), alloc::vec![alias]);
    }
}
