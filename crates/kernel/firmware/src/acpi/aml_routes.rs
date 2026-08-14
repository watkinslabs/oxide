//! AML namespace ownership for PCI INTx routing.

use alloc::{boxed::Box, vec::Vec};
use aml::{AmlContext, AmlName, DebugVerbosity, pci_routing::{PciRoutingTable, Pin}, resource::{InterruptPolarity, InterruptTrigger}};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::{Devices, Spinlock};
use super::aml_handler::FirmwareHandler;

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
struct RootRoutes { segment: u16, bus: u8, table: PciRoutingTable }
struct RouteContext { aml: AmlContext, roots: Vec<RootRoutes> }
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
    let mut context = AmlContext::new(Box::new(FirmwareHandler), DebugVerbosity::None);
    let table = unsafe { aml_table(dsdt, hhdm)? };
    if context.parse_table(table).is_err() { return None; }
    for slot in 0..count {
        let pa = TABLES.ssdt_pa[slot].load(Ordering::Acquire);
        if pa == 0 { continue; }
        let table = unsafe { aml_table(pa, hhdm)? };
        if context.parse_table(table).is_err() { return None; }
    }
    let mut roots = Vec::new();
    for scope in prt_scopes(&mut context) {
        let segment = integer_at(&context, &scope, "_SEG").unwrap_or(0) as u16;
        let bus = integer_at(&context, &scope, "_BBN").unwrap_or(0) as u8;
        let path = AmlName::from_str("_PRT").ok()?.resolve(&scope).ok()?;
        let table = PciRoutingTable::from_prt_path(&path, &mut context).ok()?;
        roots.push(RootRoutes { segment, bus, table });
    }
    Some(RouteContext { aml: context, roots })
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

/// Parse AML and cache every root-bridge routing table before drivers attach.
/// The result reports whether a complete namespace became available; PCI may
/// still operate with MSI/MSI-X when firmware publishes no usable INTx table.
/// # C: O(AML table bytes)
pub fn prepare_pci_intx_routes() -> bool {
    let mut context = CONTEXT.lock();
    if context.is_none() { *context = build_context(); }
    context.as_ref().is_some()
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
}
