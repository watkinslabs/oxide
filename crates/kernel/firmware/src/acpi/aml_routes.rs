//! AML namespace ownership for PCI INTx routing.

use alloc::{boxed::Box, vec::Vec};
use aml::{AmlContext, AmlName, DebugVerbosity, value::{AmlValue, Args}, pci_routing::{PciRoutingTable, Pin}, resource::{InterruptPolarity, InterruptTrigger}};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::{Devices, Spinlock};
use super::aml_handler::FirmwareHandler;
use super::pci_osc::{self, PciOscControl};
use super::{fadt, power_action, sleep_types};

const MAX_AML_TABLES: usize = 32;
const ACPI_HEADER_BYTES: usize = 36;
const MAX_AML_TABLE_BYTES: usize = 1024 * 1024;

/// One interrupt-controller route evaluated from the AML namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciIntxRoute { pub gsi: u32, pub level: bool, pub active_low: bool }

struct Tables { ssdt_count: AtomicU32, hhdm: AtomicU64, dsdt_pa: AtomicU64, ssdt_pa: [AtomicU64; MAX_AML_TABLES] }
static TABLES: Tables = Tables {
    ssdt_count: AtomicU32::new(0), hhdm: AtomicU64::new(0), dsdt_pa: AtomicU64::new(0),
    ssdt_pa: [const { AtomicU64::new(0) }; MAX_AML_TABLES],
};
struct RootRoutes { segment: u16, bus: u8, table: PciRoutingTable, osc: Option<PciOscControl> }
/// The AML parser owns heap-backed namespace state already; keep its handle
/// heap-resident too so constructing the boot-time route cache does not copy
/// a multi-KiB parser object through the BSP kernel stack.
struct RouteContext { aml: Box<AmlContext>, roots: Vec<RootRoutes> }
static CONTEXT: Spinlock<Option<RouteContext>, Devices> = Spinlock::new(None);

/// Retain the DSDT table for later namespace construction.
///
/// # SAFETY: `pa` is the validated FADT DSDT address and `hhdm_offset` maps
/// its complete ACPI table for the lifetime of this boot. # C: O(1)
pub unsafe fn install_dsdt(pa: u64, hhdm_offset: u64) {
    if pa == 0 || hhdm_offset == 0 { return; }
    let old = TABLES.hhdm.compare_exchange(0, hhdm_offset, Ordering::AcqRel, Ordering::Acquire);
    if old.is_ok() || old == Err(hhdm_offset) { TABLES.dsdt_pa.store(pa, Ordering::Release); }
}

/// Retain one SSDT table for later namespace construction.
///
/// # SAFETY: `pa` is XSDT-listed AML table memory covered by `hhdm_offset`.
/// # C: O(1)
pub unsafe fn install_ssdt(pa: u64, hhdm_offset: u64) {
    if pa == 0 || hhdm_offset == 0 { return; }
    let old = TABLES.hhdm.compare_exchange(0, hhdm_offset, Ordering::AcqRel, Ordering::Acquire);
    if old.is_err_and(|found| found != hhdm_offset) { return; }
    let slot = TABLES.ssdt_count.fetch_add(1, Ordering::AcqRel) as usize;
    if slot >= MAX_AML_TABLES { TABLES.ssdt_count.store(MAX_AML_TABLES as u32, Ordering::Release); return; }
    TABLES.ssdt_pa[slot].store(pa, Ordering::Release);
}

fn build_context() -> Option<RouteContext> {
    let count = (TABLES.ssdt_count.load(Ordering::Acquire) as usize).min(MAX_AML_TABLES);
    let hhdm = TABLES.hhdm.load(Ordering::Acquire);
    let dsdt = TABLES.dsdt_pa.load(Ordering::Acquire);
    if dsdt == 0 || hhdm == 0 { return None; }
    let mut context = Box::new(AmlContext::new(Box::new(FirmwareHandler), DebugVerbosity::None));
    // SAFETY: `install_dsdt` recorded a validated FADT DSDT address whose
    // header and declared extent this boot's HHDM offset maps for the
    // lifetime of the kernel; `aml_table` re-checks the declared length.
    let table = unsafe { aml_table(dsdt, hhdm)? };
    if context.parse_table(table).is_err() { return None; }
    for slot in 0..count {
        let pa = TABLES.ssdt_pa[slot].load(Ordering::Acquire);
        if pa == 0 { continue; }
        // SAFETY: `install_ssdt` recorded an XSDT-listed AML table address
        // covered by the same HHDM offset and live for the lifetime of the
        // kernel; `aml_table` re-checks the declared length.
        let table = unsafe { aml_table(pa, hhdm)? };
        if context.parse_table(table).is_err() { return None; }
    }
    if let (Some(registers), Some((type_a, type_b))) = (power_action::power_registers(), s5_types(&context)) {
        if let Some(action) = fadt::poweroff_action(registers, type_a, type_b) { power_action::set_poweroff_action(action); }
    }
    publish_sleep_types(&context);
    let mut roots = Vec::new();
    for scope in prt_scopes(&mut context) {
        let segment = integer_at(&context, &scope, "_SEG").unwrap_or(0) as u16;
        let bus = integer_at(&context, &scope, "_BBN").unwrap_or(0) as u8;
        let path = AmlName::from_str("_PRT").ok()?.resolve(&scope).ok()?;
        let table = PciRoutingTable::from_prt_path(&path, &mut context).ok()?;
        let osc = pci_osc::negotiate(|cap| eval_osc(&mut context, &scope, cap)).ok();
        roots.push(RootRoutes { segment, bus, table, osc });
    }
    Some(RouteContext { aml: context, roots })
}

/// Evaluate one `_Sx` package into its PM1a/PM1b SLP_TYP pair. The DECODE
/// (including the packed single-value form) belongs to `sleep_types`, so
/// every state reads a package the same way; this only turns AML values
/// into the integers that decision consumes.
fn sx_types(context: &AmlContext, path: &str) -> Option<(u8, u8)> {
    let path = AmlName::from_str(path).ok()?;
    let AmlValue::Package(values) = context.namespace.get_by_path(&path).ok()? else { return None; };
    let mut integers = [0u64; 2];
    let taken = values.len().min(integers.len());
    for slot in 0..taken { integers[slot] = values.get(slot)?.as_integer(context).ok()?; }
    sleep_types::sleep_type_pair(&integers[..taken])
}

fn s5_types(context: &AmlContext) -> Option<(u8, u8)> { sx_types(context, "\\_S5") }

/// Publish the reversible sleep states' SLP_TYP pairs alongside `_S5`'s.
fn publish_sleep_types(context: &AmlContext) {
    for state in sleep_types::EVALUATED {
        if let Some(types) = sx_types(context, state.aml_path()) { sleep_types::set_sleep_types(state, types); }
    }
}

/// # SAFETY: caller supplies one HHDM-mapped AML SDT whose header and declared
/// table length are readable. # C: O(1)
unsafe fn aml_table(pa: u64, hhdm: u64) -> Option<&'static [u8]> {
    let base = hhdm.checked_add(pa)? as *const u8;
    // SAFETY: caller proves the standard ACPI header is readable at `base`.
    let bytes = unsafe { crate::acpi::read::read_u32_le(base.add(4)) as usize };
    if bytes < ACPI_HEADER_BYTES || bytes > MAX_AML_TABLE_BYTES { return None; }
    // SAFETY: caller proves the declared table extent is HHDM-mapped and live.
    Some(unsafe { core::slice::from_raw_parts(base.add(ACPI_HEADER_BYTES), bytes - ACPI_HEADER_BYTES) })
}

fn pin(value: u8) -> Option<Pin> {
    match value { 1 => Some(Pin::IntA), 2 => Some(Pin::IntB), 3 => Some(Pin::IntC), 4 => Some(Pin::IntD), _ => None }
}

fn integer_at(context: &AmlContext, scope: &AmlName, name: &str) -> Option<u64> {
    let name = AmlName::from_str(name).ok()?;
    let (_, handle) = context.namespace.search(&name, scope).ok()?;
    context.namespace.get(handle).ok()?.as_integer(context).ok()
}

fn aml_buffer(bytes: &[u8]) -> AmlValue {
    let value = AmlValue::Buffer(alloc::sync::Arc::new(Default::default()));
    if let AmlValue::Buffer(buffer) = &value { buffer.lock().extend_from_slice(bytes); }
    value
}

/// Evaluate one root bridge's `_OSC` method outside the route-collector
/// closure frame. AML invocation is stack-heavy, so this remains a distinct
/// early-firmware phase rather than being inlined under table collection.
#[inline(never)]
fn eval_osc(context: &mut AmlContext, scope: &AmlName, cap: [u32; 3]) -> Result<[u32; 3], ()> {
    let path = AmlName::from_str("_OSC").map_err(|_| ())?.resolve(scope).map_err(|_| ())?;
    let mut bytes = [0u8; 12];
    for (index, word) in cap.iter().enumerate() { bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes()); }
    let args = Args::from_list(alloc::vec![aml_buffer(&pci_osc::PCI_OSC_UUID), AmlValue::Integer(1),
        AmlValue::Integer(cap.len() as u64), aml_buffer(&bytes)]).map_err(|_| ())?;
    let value = context.invoke_method(&path, args).map_err(|_| ())?;
    let buffer = value.as_buffer(context).map_err(|_| ())?;
    let bytes = buffer.lock();
    if bytes.len() != 12 { return Err(()); }
    let mut result = [0u32; 3];
    for (index, word) in result.iter_mut().enumerate() {
        *word = u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().map_err(|_| ())?);
    }
    Ok(result)
}

fn prt_scopes(context: &mut AmlContext) -> Vec<AmlName> {
    let mut scopes = Vec::new();
    let prt = AmlName::from_str("_PRT").ok();
    if let Some(prt) = prt {
        let _ = context.namespace.traverse(|scope, _| { scopes.push(scope.clone()); Ok(true) });
        scopes.retain(|scope| prt.clone().resolve(scope).ok()
            .is_some_and(|path| context.namespace.get_handle(&path).is_ok()));
    }
    scopes
}

fn route_in_context(context: &mut RouteContext, bdf: pci::Bdf, pin_number: u8) -> Option<PciIntxRoute> {
    let pin = pin(pin_number)?;
    for root in &context.roots {
        if root.segment != bdf.segment || root.bus != bdf.bus { continue; }
        let route = root.table.route(bdf.device as u16, bdf.function as u16, pin, &mut context.aml).ok()?;
        return Some(PciIntxRoute { gsi: route.irq, level: route.trigger == InterruptTrigger::Level,
            active_low: route.polarity == InterruptPolarity::ActiveLow });
    }
    None
}

/// Resolve a PCI function's cached firmware-owned INTx route. # C: O(root routes)
pub fn pci_intx_route(bdf: pci::Bdf, pin: u8) -> Option<PciIntxRoute> {
    let mut context = CONTEXT.lock();
    route_in_context(context.as_mut()?, bdf, pin)
}

/// Return PCI root firmware ownership retained for `segment:bus`. # C: O(root routes)
pub fn pci_osc_control(segment: u16, bus: u8) -> Option<PciOscControl> {
    CONTEXT.lock().as_ref()?.roots.iter().find(|root| root.segment == segment && root.bus == bus)?.osc
}

/// Parse AML and cache every root-bridge routing table before drivers attach.
/// The result reports whether a complete namespace became available; PCI may
/// still operate with MSI/MSI-X when firmware publishes no usable INTx table.
/// # C: O(AML table bytes)
///
/// Keep the parser's deep temporary state out of the caller's boot frame.
/// This is the same stack-phase boundary Linux uses around early firmware
/// table interpretation before driver publication.
#[inline(never)]
pub fn prepare_pci_intx_routes() -> bool {
    let mut context = CONTEXT.lock();
    if context.is_none() { *context = build_context(); }
    context.as_ref().is_some()
}

/// Run `f` against the firmware AML namespace, constructing it on first use.
/// The namespace has one owner; this is the only way a device driver in this
/// crate reaches it, so no second parser handle can exist. Returns `None`
/// when the platform published no AML at all.
/// # C: O(AML table bytes) on first call
#[inline(never)]
pub(crate) fn with_namespace<R>(f: impl FnOnce(&mut AmlContext) -> Option<R>) -> Option<R> {
    let mut context = CONTEXT.lock();
    if context.is_none() { *context = build_context(); }
    f(&mut context.as_mut()?.aml)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn pci_pin_encoding_rejects_no_intx() {
        assert_eq!(pin(0), None);
        assert_eq!(pin(1), Some(Pin::IntA));
        assert_eq!(pin(4), Some(Pin::IntD));
        assert_eq!(pin(5), None);
    }

    #[test]
    fn s5_uses_packed_single_or_first_two_package_values() {
        assert_eq!(sleep_types::sleep_type_pair(&[0x0605]), Some((5, 6)));
        assert_eq!(sleep_types::sleep_type_pair(&[5, 6, 7]), Some((5, 6)));
    }
}
