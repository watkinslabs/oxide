//! xHCI command/event TRB rings with controller-visible ownership rules.

/// xHCI uses 16-byte transfer request blocks. # C: O(1)
pub const TRB_BYTES: usize = 16;
/// A hardware segment occupies one 4 KiB page. # C: O(1)
pub const TRBS_PER_SEGMENT: usize = 256;
/// A command ring reserves its last TRB for the link back to its first TRB. # C: O(1)
pub const COMMAND_USABLE_TRBS: usize = TRBS_PER_SEGMENT - 1;
/// Cycle bit changes ownership between software and controller. # C: O(1)
pub const TRB_CYCLE: u32 = 1;
/// Link TRB toggles the producer cycle on a ring wrap. # C: O(1)
pub const LINK_TOGGLE: u32 = 1 << 1;
/// TRB type field shift. # C: O(1)
pub const TRB_TYPE_SHIFT: u32 = 10;
/// Link TRB type. # C: O(1)
pub const TRB_TYPE_LINK: u32 = 6;
/// Enable Slot Command TRB type. # C: O(1)
pub const TRB_TYPE_ENABLE_SLOT: u32 = 9;
/// Disable Slot Command TRB type. # C: O(1)
pub const TRB_TYPE_DISABLE_SLOT: u32 = 10;
/// Address Device Command TRB type. # C: O(1)
pub const TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
/// Command Completion Event TRB type. # C: O(1)
pub const TRB_TYPE_COMMAND_COMPLETION: u32 = 33;
/// Successful xHCI completion code. # C: O(1)
pub const COMPLETION_SUCCESS: u8 = 1;

/// Controller-visible xHCI TRB, little-endian dwords on supported machines.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Trb { pub dword: [u32; 4] }

impl Trb {
    /// Build the terminal command-ring Link TRB. # C: O(1)
    pub fn link(target_pa: u64, cycle: bool) -> Option<Self> {
        if target_pa & 0x3f != 0 { return None; }
        let control = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | LINK_TOGGLE | u32::from(cycle);
        Some(Self { dword: [target_pa as u32, (target_pa >> 32) as u32, 0, control] })
    }

    /// Cycle bit as observed by the ring owner. # C: O(1)
    pub fn cycle(self) -> bool { self.dword[3] & TRB_CYCLE != 0 }

    /// Build an Enable Slot Command for the command ring. # C: O(1)
    pub fn enable_slot() -> Self { Self { dword: [0, 0, 0, TRB_TYPE_ENABLE_SLOT << TRB_TYPE_SHIFT] } }

    /// Build a Disable Slot Command for rollback after failed addressing. # C: O(1)
    pub fn disable_slot(slot: u8) -> Option<Self> {
        (slot != 0).then_some(Self { dword: [0, 0, 0, (TRB_TYPE_DISABLE_SLOT << TRB_TYPE_SHIFT) | ((slot as u32) << 24)] })
    }

    /// Build an Address Device Command naming a 64-byte-aligned input context. # C: O(1)
    pub fn address_device(input_context_pa: u64, slot: u8, block_set_address: bool) -> Option<Self> {
        if input_context_pa & 0x3f != 0 || slot == 0 { return None; }
        let control = (TRB_TYPE_ADDRESS_DEVICE << TRB_TYPE_SHIFT) | ((slot as u32) << 24) | ((block_set_address as u32) << 9);
        Some(Self { dword: [input_context_pa as u32, (input_context_pa >> 32) as u32, 0, control] })
    }

    /// Decode a command-completion event, preserving the command TRB address. # C: O(1)
    pub fn command_completion(self) -> Option<CommandCompletion> {
        if (self.dword[3] >> TRB_TYPE_SHIFT) & 0x3f != TRB_TYPE_COMMAND_COMPLETION { return None; }
        Some(CommandCompletion {
            command_pa: self.dword[0] as u64 | ((self.dword[1] as u64) << 32),
            completion_code: (self.dword[2] >> 24) as u8,
            slot: (self.dword[3] >> 24) as u8,
        })
    }
}

/// One decoded Command Completion Event. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CommandCompletion { pub command_pa: u64, pub completion_code: u8, pub slot: u8 }

/// One-page command ring. Software is producer; the controller is consumer.
pub struct CommandRing {
    trbs: [Trb; TRBS_PER_SEGMENT],
    enqueue: usize,
    cycle: bool,
    pa: u64,
}

impl CommandRing {
    /// Initialize an empty ring with its terminal Link TRB published. # C: O(1)
    pub fn new(pa: u64) -> Option<Self> {
        if pa & 0xfff != 0 { return None; }
        let mut trbs = [Trb::default(); TRBS_PER_SEGMENT];
        trbs[COMMAND_USABLE_TRBS] = Trb::link(pa, true)?;
        Some(Self { trbs, enqueue: 0, cycle: true, pa })
    }

    /// Physical command-ring base for CRCR. # C: O(1)
    pub fn pa(&self) -> u64 { self.pa }
    /// Number of writable commands before the terminal Link TRB. # C: O(1)
    pub fn capacity(&self) -> usize { COMMAND_USABLE_TRBS }
    /// Current producer-cycle state. # C: O(1)
    pub fn cycle(&self) -> bool { self.cycle }
    /// Read one controller-visible TRB for DMA setup/testing. # C: O(1)
    pub fn trb(&self, index: usize) -> Option<Trb> { self.trbs.get(index).copied() }

    /// Publish one command and return its physical TRB address. # C: O(1)
    pub fn push(&mut self, mut trb: Trb) -> (u64, bool) {
        trb.dword[3] = (trb.dword[3] & !TRB_CYCLE) | u32::from(self.cycle);
        let index = self.enqueue;
        self.trbs[index] = trb;
        self.enqueue += 1;
        if self.enqueue == COMMAND_USABLE_TRBS {
            self.enqueue = 0;
            self.cycle = !self.cycle;
            self.trbs[COMMAND_USABLE_TRBS] = Trb::link(self.pa, self.cycle).expect("page-aligned command ring");
        }
        (self.pa + (index * TRB_BYTES) as u64, self.cycle)
    }
}

/// One-page event ring. The controller is producer; software is consumer.
pub struct EventRing { dequeue: usize, cycle: bool, pa: u64 }

impl EventRing {
    /// Begin consuming events from a page-aligned event-ring segment. # C: O(1)
    pub fn new(pa: u64) -> Option<Self> { (pa & 0xfff == 0).then_some(Self { dequeue: 0, cycle: true, pa }) }
    /// Consume a controller-owned event TRB and return its physical position. # C: O(1)
    pub fn consume(&mut self, trb: Trb) -> Option<u64> {
        if trb.cycle() != self.cycle { return None; }
        let pa = self.pa + (self.dequeue * TRB_BYTES) as u64;
        self.dequeue += 1;
        if self.dequeue == TRBS_PER_SEGMENT { self.dequeue = 0; self.cycle = !self.cycle; }
        Some(pa)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_ring_keeps_link_reserved_and_toggles_only_on_wrap() {
        let mut ring = CommandRing::new(0x20_000).unwrap();
        assert_eq!(ring.capacity(), 255);
        assert_eq!(ring.trb(255).unwrap(), Trb::link(0x20_000, true).unwrap());
        for index in 0..255 { assert_eq!(ring.push(Trb::default()).0, 0x20_000 + (index * 16) as u64); }
        assert!(!ring.cycle());
        assert_eq!(ring.trb(255).unwrap(), Trb::link(0x20_000, false).unwrap());
        let _ = ring.push(Trb::default());
        assert!(!ring.trb(0).unwrap().cycle());
    }

    #[test]
    fn event_ring_consumes_only_controller_owned_cycle_then_wraps() {
        let mut ring = EventRing::new(0x30_000).unwrap();
        assert_eq!(ring.consume(Trb::default()), None);
        let owned = Trb { dword: [0, 0, 0, TRB_CYCLE] };
        assert_eq!(ring.consume(owned), Some(0x30_000));
        for _ in 1..256 { assert!(ring.consume(owned).is_some()); }
        assert_eq!(ring.consume(owned), None);
    }

    #[test]
    fn ring_bases_must_have_hardware_alignment() {
        assert!(CommandRing::new(0x20_001).is_none());
        assert!(EventRing::new(0x30_001).is_none());
        assert!(Trb::link(0x20_004, true).is_none());
    }

    #[test]
    fn enumeration_command_trbs_follow_xhci_layout() {
        assert_eq!(Trb::enable_slot().dword[3], TRB_TYPE_ENABLE_SLOT << TRB_TYPE_SHIFT);
        let address = Trb::address_device(0x48_000, 2, false).unwrap();
        assert_eq!(address.dword, [0x48_000, 0, 0, (TRB_TYPE_ADDRESS_DEVICE << TRB_TYPE_SHIFT) | (2 << 24)]);
        assert!(Trb::address_device(0x48_004, 2, false).is_none());
        let completion = Trb { dword: [0x20_000, 0, (COMPLETION_SUCCESS as u32) << 24, (TRB_TYPE_COMMAND_COMPLETION << TRB_TYPE_SHIFT) | (2 << 24)] };
        assert_eq!(completion.command_completion(), Some(CommandCompletion { command_pa: 0x20_000, completion_code: COMPLETION_SUCCESS, slot: 2 }));
    }
}
