//! ACPI SCI and fixed FADT GPE blocks.
//!
//! The hard half only detects, masks, and records active GPEs. AML execution
//! and provider notification run from the scheduler workqueue.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use aml::{RegionAccess, RegionAccessDirection, value::RegionSpace};

use super::fadt::{EventRegisters, Gas, FADT_HW_REDUCED, SPACE_SYSTEM_IO, SPACE_SYSTEM_MEMORY};

const GPE_LIMIT: usize = 256;
const SCI_ENABLE: u64 = 1;
const ACPI_ENABLE_RETRIES: usize = 30_000;
const ACPI_ENABLE_STALL_NS: u64 = 100_000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ModeTransition { Complete, Unsupported, Write(u8) }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Block { gas: Gas, registers: u8, base: u8 }

impl Block {
    fn from_fadt(gas: Gas, bytes: u8, base: u8) -> Option<Self> {
        if gas.address == 0 { return None; }
        if !matches!(gas.space_id, SPACE_SYSTEM_IO | SPACE_SYSTEM_MEMORY) { return None; }
        let registers = bytes / 2;
        let end = usize::from(base).checked_add(usize::from(registers) * 8)?;
        if registers == 0 || end > GPE_LIMIT { return None; }
        Some(Self { gas, registers, base })
    }

    fn contains(&self, number: u8) -> bool {
        let number = usize::from(number);
        number >= usize::from(self.base)
            && number < usize::from(self.base) + usize::from(self.registers) * 8
    }

    fn slot(&self, number: u8) -> Option<(u8, u8)> {
        if !self.contains(number) { return None; }
        let relative = number - self.base;
        Some((relative / 8, 1 << (relative % 8)))
    }
}

struct Method { path: String, edge: bool, pending: AtomicBool }

struct Runtime {
    blocks: Vec<Block>,
    methods: Vec<Option<Method>>,
    worker_queued: AtomicBool,
}

impl Runtime {
    fn method(&self, number: u8) -> Option<&Method> {
        self.methods.get(usize::from(number))?.as_ref()
    }
}

static RUNTIME: AtomicPtr<Runtime> = AtomicPtr::new(core::ptr::null_mut());
static NOTIFY_DISPATCHING: AtomicBool = AtomicBool::new(false);

/// Kernel-owned installation of the FADT SCI interrupt.
pub type SciInstaller = fn(u16) -> bool;
static SCI_INSTALLER: AtomicUsize = AtomicUsize::new(0);

/// Install the architecture IRQ bridge before event initialization. # C: O(1)
pub fn set_sci_installer(installer: SciInstaller) {
    SCI_INSTALLER.store(installer as usize, Ordering::Release);
}

fn runtime() -> Option<&'static Runtime> {
    let pointer = RUNTIME.load(Ordering::Acquire);
    if pointer.is_null() { return None; }
    // SAFETY: init publishes a leaked Box exactly once; it is immutable except
    // for its atomics and remains live for the entire boot.
    Some(unsafe { &*pointer })
}

/// Initialize FADT GPE blocks, install the SCI, and enable only GPEs with a
/// discovered `_Lxx`/`_Exx` method. Returns the number enabled. # C: O(GPEs)
pub fn init() -> usize {
    if runtime().is_some() { return 0; }
    let Some(registers) = super::fadt::event_registers_published() else { return 0; };
    if registers.flags & FADT_HW_REDUCED != 0 { return 0; }
    if !enter_acpi_mode(registers) { return 0; }
    if !disable_fixed_events(registers.pm1a_event, registers.pm1_event_len)
        || !disable_fixed_events(registers.pm1b_event, registers.pm1_event_len) {
        return 0;
    }
    let mut blocks = Vec::new();
    if let Some(block) = Block::from_fadt(registers.gpe0_block, registers.gpe0_block_len, 0) {
        blocks.push(block);
    }
    if let Some(block) = Block::from_fadt(registers.gpe1_block, registers.gpe1_block_len, registers.gpe1_base) {
        if !blocks.iter().any(|old| overlaps(*old, block)) { blocks.push(block); }
    }
    if blocks.is_empty() || registers.sci_interrupt == 0 { return 0; }
    for block in &blocks {
        for index in 0..block.registers {
            if write8(block.gas, block.registers + index, 0).is_none() { return 0; }
            if write8(block.gas, index, u8::MAX).is_none() { return 0; }
        }
    }

    let mut methods: Vec<Option<Method>> = core::iter::repeat_with(|| None).take(GPE_LIMIT).collect();
    for method in super::aml_routes::gpe_methods() {
        if !blocks.iter().any(|block| block.contains(method.number)) { continue; }
        let slot = &mut methods[usize::from(method.number)];
        if slot.is_none() {
            *slot = Some(Method { path: method.path, edge: method.edge, pending: AtomicBool::new(false) });
        }
    }
    if !install_sci(registers.sci_interrupt) { return 0; }
    let owned = Box::new(Runtime { blocks, methods, worker_queued: AtomicBool::new(false) });
    let pointer = Box::into_raw(owned);
    if RUNTIME.compare_exchange(core::ptr::null_mut(), pointer, Ordering::AcqRel, Ordering::Acquire).is_err() {
        // SAFETY: publication failed, so no other owner can observe this Box.
        drop(unsafe { Box::from_raw(pointer) });
        return 0;
    }
    let Some(runtime) = runtime() else { return 0; };
    let mut enabled = 0;
    for number in 0..GPE_LIMIT {
        let Ok(number) = u8::try_from(number) else { continue; };
        if runtime.method(number).is_none() { continue; }
        let Some((block, register, bit)) = locate(runtime, number) else { continue; };
        if write8(block.gas, register, bit).is_none() { continue; }
        let current = read8(block.gas, block.registers + register).unwrap_or(0);
        if write8(block.gas, block.registers + register, current | bit).is_some() { enabled += 1; }
    }
    enabled
}

fn install_sci(interrupt: u16) -> bool {
    let raw = SCI_INSTALLER.load(Ordering::Acquire);
    if raw == 0 { return false; }
    // SAFETY: set_sci_installer stores only a function with this exact ABI.
    let installer: SciInstaller = unsafe { core::mem::transmute(raw) };
    installer(interrupt)
}

fn overlaps(left: Block, right: Block) -> bool {
    let left_start = usize::from(left.base);
    let left_end = left_start + usize::from(left.registers) * 8;
    let right_start = usize::from(right.base);
    let right_end = right_start + usize::from(right.registers) * 8;
    left_start < right_end && right_start < left_end
}

/// Disable the PM1 fixed-event sources until individual handlers own them.
/// Like the GPE block, PM1 event registers are status followed by an equally
/// sized enable half. Disabled sources cannot hold the shared SCI asserted.
fn disable_fixed_events(gas: Gas, bytes: u8) -> bool {
    if gas.address == 0 { return true; }
    let Some((enable, registers)) = fixed_enable_half(bytes) else { return false; };
    for index in 0..registers {
        if write8(gas, enable + index, 0).is_none() { return false; }
    }
    true
}

fn fixed_enable_half(bytes: u8) -> Option<(u8, u8)> {
    let registers = bytes / 2;
    if registers == 0 { return None; }
    Some((registers, registers))
}

fn locate(runtime: &Runtime, number: u8) -> Option<(Block, u8, u8)> {
    for block in &runtime.blocks {
        if let Some((register, bit)) = block.slot(number) { return Some((*block, register, bit)); }
    }
    None
}

/// SCI hard half. Active GPEs are masked before deferred AML execution.
/// # C: O(GPE register bytes) # Ctx: hard IRQ
pub fn handle_sci_irq() -> bool {
    let Some(runtime) = runtime() else { return false; };
    let (handled, deferred) = mask_active(runtime, read8, |gas, offset, value| {
        write8(gas, offset, value)
    });
    if !handled { return false; }
    if !deferred { return true; }
    if !ensure_worker(runtime) {
        for method in runtime.methods.iter().flatten() {
            method.pending.store(false, Ordering::Release);
        }
        return true;
    }
    true
}

fn mask_active(
    runtime: &Runtime,
    mut read: impl FnMut(Gas, u8) -> Option<u8>,
    mut write: impl FnMut(Gas, u8, u8) -> Option<()>,
) -> (bool, bool) {
    let mut handled = false;
    let mut deferred = false;
    for block in &runtime.blocks {
        for register in 0..block.registers {
            let Some(status) = read(block.gas, register) else { continue; };
            let Some(enable) = read(block.gas, block.registers + register) else { continue; };
            let asserted = status & enable;
            if asserted == 0 { continue; }
            let mut masked = enable & !asserted;
            if write(block.gas, block.registers + register, masked).is_none() { continue; }
            handled = true;
            for bit_index in 0..8u8 {
                let bit = 1u8 << bit_index;
                if asserted & bit == 0 { continue; }
                let number = block.base.wrapping_add(register * 8).wrapping_add(bit_index);
                if let Some(method) = runtime.method(number) {
                    if method.edge && write(block.gas, register, bit).is_none() {
                        masked |= bit;
                        continue;
                    }
                    method.pending.store(true, Ordering::Release);
                    deferred = true;
                }
            }
            if masked != enable & !asserted {
                let _ = write(block.gas, block.registers + register, masked);
            }
        }
    }
    (handled, deferred)
}

fn ensure_worker(runtime: &Runtime) -> bool {
    if runtime.worker_queued.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return true;
    }
    if sched::live::workqueue::queue_work(run_worker, 0) { return true; }
    runtime.worker_queued.store(false, Ordering::Release);
    false
}

fn run_worker(_: usize) {
    let Some(runtime) = runtime() else { return; };
    loop {
        let mut ran = false;
        for number in 0..GPE_LIMIT {
            let Some(method) = runtime.methods[number].as_ref() else { continue; };
            if !method.pending.swap(false, Ordering::AcqRel) { continue; }
            ran = true;
            let evaluated = super::aml_routes::invoke_gpe_method(&method.path);
            let Ok(number) = u8::try_from(number) else { continue; };
            let Some((block, register, bit)) = locate(runtime, number) else { continue; };
            let _ = finish_method(evaluated, method.edge, block, register, bit, read8,
                |gas, offset, value| write8(gas, offset, value));
        }
        if !ran { break; }
    }
    runtime.worker_queued.store(false, Ordering::Release);
    if runtime.methods.iter().flatten().any(|method| method.pending.load(Ordering::Acquire)) {
        let _ = ensure_worker(runtime);
    }
}

fn finish_method(
    evaluated: bool,
    edge: bool,
    block: Block,
    register: u8,
    bit: u8,
    mut read: impl FnMut(Gas, u8) -> Option<u8>,
    mut write: impl FnMut(Gas, u8, u8) -> Option<()>,
) -> bool {
    // ACPICA can re-enable after evaluation because its interpreter accepts
    // the complete firmware method. This interpreter is deliberately
    // incomplete: leave a source masked when evaluation fails, or an
    // unconsumed device condition can turn the shared SCI into an IRQ storm.
    if !evaluated { return false; }
    if !edge && write(block.gas, register, bit).is_none() { return false; }
    let Some(enable) = read(block.gas, block.registers + register) else { return false; };
    write(block.gas, block.registers + register, enable | bit).is_some()
}

fn dispatch_notify(path: &str, value: u64) -> bool {
    super::battery::notified(path, value)
        || super::ac::notified(path, value)
        || super::thermal::notified(path, value)
}

/// Deliver every Notify emitted by a completed outer AML evaluation. The
/// serializer prevents a provider refresh that itself executes AML from
/// recursively entering notification delivery; the outer drain consumes any
/// requests it produces. # C: O(N_notifications * N_providers)
pub(crate) fn dispatch_notifications() {
    if NOTIFY_DISPATCHING.compare_exchange(false, true, Ordering::AcqRel,
        Ordering::Acquire).is_err() {
        return;
    }
    loop {
        for (path, value) in super::aml_handler::take_notifications() {
            let _ = dispatch_notify(&path, value);
        }
        NOTIFY_DISPATCHING.store(false, Ordering::Release);
        if !super::aml_handler::has_notifications() { return; }
        if NOTIFY_DISPATCHING.compare_exchange(false, true, Ordering::AcqRel,
            Ordering::Acquire).is_err() {
            return;
        }
    }
}

fn enter_acpi_mode(registers: EventRegisters) -> bool {
    let enabled = registers.smi_command != 0 && sci_enabled(registers);
    let value = match mode_transition(registers, enabled) {
        ModeTransition::Complete => return true,
        ModeTransition::Unsupported => return false,
        ModeTransition::Write(value) => value,
    };
    let smi = Gas { space_id: SPACE_SYSTEM_IO, bit_width: 8, bit_offset: 0,
        access_width: 1, address: u64::from(registers.smi_command) };
    if write_fixed(smi, 8, u64::from(value)).is_none() { return false; }
    for _ in 0..ACPI_ENABLE_RETRIES {
        if sci_enabled(registers) { return true; }
        let deadline = timekeeper::monotonic_ns().saturating_add(ACPI_ENABLE_STALL_NS);
        while timekeeper::monotonic_ns() < deadline { core::hint::spin_loop(); }
    }
    false
}

fn sci_enabled(registers: EventRegisters) -> bool {
    let a = read_fixed(registers.pm1a_control, 16);
    let b_present = registers.pm1b_control.address != 0;
    let b = b_present.then(|| read_fixed(registers.pm1b_control, 16)).flatten();
    combined_sci_enabled(a, b_present, b)
}

fn combined_sci_enabled(a: Option<u64>, b_present: bool, b: Option<u64>) -> bool {
    let Some(a) = a else { return false; };
    let b = if b_present { let Some(b) = b else { return false; }; b } else { 0 };
    (a | b) & SCI_ENABLE != 0
}

fn mode_transition(registers: EventRegisters, sci_enabled: bool) -> ModeTransition {
    if registers.smi_command == 0 || sci_enabled { return ModeTransition::Complete; }
    if registers.acpi_enable == 0 && registers.acpi_disable == 0 {
        return ModeTransition::Unsupported;
    }
    ModeTransition::Write(registers.acpi_enable)
}

fn region_space(space: u8) -> Option<RegionSpace> {
    match space { SPACE_SYSTEM_MEMORY => Some(RegionSpace::SystemMemory), SPACE_SYSTEM_IO => Some(RegionSpace::SystemIo), _ => None }
}

fn read8(gas: Gas, offset: u8) -> Option<u8> { read_fixed_at(gas, u64::from(offset), 8).map(|value| value as u8) }
fn write8(gas: Gas, offset: u8, value: u8) -> Option<()> {
    write_fixed_at(gas, u64::from(offset), 8, u64::from(value)).map(|_| ())
}
fn read_fixed(gas: Gas, width: u64) -> Option<u64> { read_fixed_at(gas, 0, width) }
fn write_fixed(gas: Gas, width: u64, value: u64) -> Option<u64> { write_fixed_at(gas, 0, width, value) }
fn read_fixed_at(gas: Gas, offset: u64, width: u64) -> Option<u64> {
    if gas.address == 0 { return None; }
    super::aml_handler::access_region(RegionAccess { space: region_space(gas.space_id)?,
        base: gas.address, length: u64::from(gas.bit_width.saturating_add(7) / 8), offset,
        width, direction: RegionAccessDirection::Read, pci: None }, 0).ok()
}
fn write_fixed_at(gas: Gas, offset: u64, width: u64, value: u64) -> Option<u64> {
    if gas.address == 0 { return None; }
    super::aml_handler::access_region(RegionAccess { space: region_space(gas.space_id)?,
        base: gas.address, length: u64::from(gas.bit_width.saturating_add(7) / 8), offset,
        width, direction: RegionAccessDirection::Write, pci: None }, value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    fn port(address: u64) -> Gas {
        Gas { space_id: SPACE_SYSTEM_IO, bit_width: 32, bit_offset: 0, access_width: 1, address }
    }

    #[test]
    fn blocks_split_status_from_enable_and_bound_the_number_space() {
        let block = Block::from_fadt(port(0x620), 4, 0x20).unwrap();
        assert_eq!(block.registers, 2);
        assert_eq!(block.slot(0x20), Some((0, 1)));
        assert_eq!(block.slot(0x2f), Some((1, 0x80)));
        assert_eq!(block.slot(0x30), None);
        assert_eq!(Block::from_fadt(port(0x620), 3, 0).unwrap().registers, 1,
            "an unmatched trailing byte does not discard a complete pair");
        assert!(Block::from_fadt(port(0x620), 1, 0).is_none());
        assert!(Block::from_fadt(port(0x620), 4, 0xf8).is_none());
    }

    #[test]
    fn overlapping_fadt_blocks_are_detected() {
        let first = Block::from_fadt(port(0x620), 4, 0).unwrap();
        let overlap = Block::from_fadt(port(0x630), 2, 8).unwrap();
        let separate = Block::from_fadt(port(0x640), 2, 16).unwrap();
        assert!(overlaps(first, overlap));
        assert!(!overlaps(first, separate));
    }

    #[test]
    fn fixed_event_blocks_are_split_into_equal_status_and_enable_halves() {
        assert_eq!(fixed_enable_half(4), Some((2, 2)));
        assert_eq!(fixed_enable_half(2), Some((1, 1)));
        assert_eq!(fixed_enable_half(0), None);
        assert_eq!(fixed_enable_half(3), Some((1, 1)));
        assert_eq!(fixed_enable_half(1), None);
    }

    #[test]
    fn acpi_mode_transition_follows_fadt_capabilities() {
        let mut registers = EventRegisters::default();
        assert_eq!(mode_transition(registers, false), ModeTransition::Complete,
            "zero SMI_CMD means firmware has no legacy mode");
        registers.smi_command = 0xb2;
        assert_eq!(mode_transition(registers, true), ModeTransition::Complete);
        assert_eq!(mode_transition(registers, false), ModeTransition::Unsupported,
            "both zero transition values advertise no mode switch");
        registers.acpi_disable = 0xa1;
        assert_eq!(mode_transition(registers, false), ModeTransition::Write(0),
            "a zero enable value remains meaningful when disable is nonzero");
        registers.acpi_enable = 0xa0;
        assert_eq!(mode_transition(registers, false), ModeTransition::Write(0xa0));
    }

    #[test]
    fn sci_enable_is_the_union_of_the_required_a_and_optional_b_registers() {
        assert!(combined_sci_enabled(Some(0), true, Some(SCI_ENABLE)));
        assert!(combined_sci_enabled(Some(SCI_ENABLE), false, None));
        assert!(!combined_sci_enabled(None, true, Some(SCI_ENABLE)),
            "a failed required register makes the mode unreadable");
        assert!(!combined_sci_enabled(Some(SCI_ENABLE), true, None),
            "a declared B register must also be readable");
    }

    #[test]
    fn an_active_owned_gpe_is_masked_and_marked_for_deferred_execution() {
        let block = Block::from_fadt(port(0x620), 2, 0).unwrap();
        let mut methods: Vec<Option<Method>> = core::iter::repeat_with(|| None)
            .take(GPE_LIMIT).collect();
        methods[0] = Some(Method {
            path: String::from("\\_GPE._L00"),
            edge: false,
            pending: AtomicBool::new(false),
        });
        let runtime = Runtime { blocks: alloc::vec![block], methods,
            worker_queued: AtomicBool::new(false) };
        let masked = Cell::new(None);
        let (handled, deferred) = mask_active(&runtime,
            |_, offset| match offset { 0 => Some(0b11), 1 => Some(0b11), _ => None },
            |_, offset, value| { masked.set(Some((offset, value))); Some(()) });

        assert!(handled);
        assert!(deferred);
        assert_eq!(masked.get(), Some((1, 0)), "owned and unknown active sources are masked");
        assert!(runtime.method(0).unwrap().pending.load(Ordering::Acquire));
        assert!(runtime.method(1).is_none(), "an unknown source is never fabricated as work");
    }

    #[test]
    fn an_edge_gpe_is_cleared_after_masking_and_before_deferred_execution() {
        let block = Block::from_fadt(port(0x620), 2, 0).unwrap();
        let mut methods: Vec<Option<Method>> = core::iter::repeat_with(|| None)
            .take(GPE_LIMIT).collect();
        methods[2] = Some(Method {
            path: String::from("\\_GPE._E02"), edge: true,
            pending: AtomicBool::new(false),
        });
        let runtime = Runtime { blocks: alloc::vec![block], methods,
            worker_queued: AtomicBool::new(false) };
        let writes = core::cell::RefCell::new(Vec::new());
        let (handled, deferred) = mask_active(&runtime,
            |_, offset| match offset { 0 => Some(0b100), 1 => Some(0b100), _ => None },
            |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) });

        assert_eq!((handled, deferred), (true, true));
        assert_eq!(*writes.borrow(), alloc::vec![(1, 0), (0, 0b100)],
            "masking must precede the edge-status clear");
        assert!(runtime.method(2).unwrap().pending.load(Ordering::Acquire));
    }

    #[test]
    fn a_gpe_whose_aml_method_failed_stays_masked() {
        let block = Block::from_fadt(port(0x620), 2, 0).unwrap();
        let writes = core::cell::RefCell::new(Vec::new());
        assert!(!finish_method(false, true, block, 0, 0b100,
            |_, _| Some(0),
            |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) }));
        assert!(writes.borrow().is_empty(),
            "a failed interpreter must not re-enable an unconsumed source");

        assert!(finish_method(true, true, block, 0, 0b100,
            |_, offset| (offset == 1).then_some(0b10),
            |_, offset, value| { writes.borrow_mut().push((offset, value)); Some(()) }));
        assert_eq!(*writes.borrow(), alloc::vec![(1, 0b110)]);
    }
}
