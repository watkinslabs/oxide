//! ACPI AC adapter provider for the power-supply class. The device answers
//! one question — is mains power connected — through `_PSR`.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use power_supply::{PowerSupply, Property, PropVal, PsyType, SupplyDesc, SupplyOps};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use super::aml_eval;
use super::battery::props::device_name;

/// Hardware identifier of an ACPI AC adapter.
pub const AC_HID: &str = "ACPI0003";
/// `_PSR` reporting mains connected.
const AC_ONLINE: u64 = 1;
/// Sentinel for a `_PSR` that could not be evaluated.
const AC_STATE_UNKNOWN: u64 = 0xFF;
/// How long a `_PSR` reading stays usable.
const READING_LIFETIME_NS: u64 = 1_000_000_000;

struct Cached { state: u64, expires_ns: u64 }

/// One ACPI AC adapter.
pub struct AcpiAc {
    scope: String,
    cached: Spinlock<Cached, Devices>,
    published: Spinlock<Weak<PowerSupply>, Devices>,
}

impl AcpiAc {
    /// Re-evaluate `_PSR` unless the cached reading is still current. Returns
    /// whether the connection state moved. # C: O(AML)
    fn refresh(&self) -> bool {
        let now = timekeeper::monotonic_ns();
        {
            let cached = self.cached.lock();
            if now < cached.expires_ns { return false; }
        }
        let state = aml_eval::eval_integer(&self.scope, "_PSR").unwrap_or(AC_STATE_UNKNOWN);
        let mut cached = self.cached.lock();
        let moved = cached.state != state;
        cached.state = state;
        cached.expires_ns = now + READING_LIFETIME_NS;
        moved
    }

    /// Refresh and, when mains changed, tell the class. Every battery that
    /// draws from this adapter is notified by the class before the event
    /// reaches userspace. # C: O(AML + N_supplies)
    fn refresh_and_notify(&self) {
        if !self.refresh() { return; }
        let published = self.published.lock().upgrade();
        if let Some(psy) = published { power_supply::changed(&psy); }
    }
}

impl SupplyOps for AcpiAc {
    fn get_property(&self, prop: Property) -> KResult<PropVal> {
        self.refresh_and_notify();
        let state = self.cached.lock().state;
        if state == AC_STATE_UNKNOWN { return Err(VfsError::Enodev); }
        match prop {
            Property::Online => Ok(PropVal::Int(i32::from(state == AC_ONLINE))),
            _ => Err(VfsError::Einval),
        }
    }
}

/// Scan the firmware namespace for AC adapters and publish each one. Returns
/// how many were registered. # C: O(namespace + AML)
pub fn init() -> usize {
    let mut registered = 0;
    for scope in aml_eval::devices_with_hid(AC_HID) {
        if register_one(&scope).is_some() { registered += 1; }
    }
    registered
}

/// Publish one adapter. An adapter whose `_PSR` cannot be evaluated is not
/// published: an `online` file that always fails is worse than no file.
/// # C: O(AML)
fn register_one(scope: &str) -> Option<Arc<PowerSupply>> {
    let adapter = Arc::new(AcpiAc {
        scope: String::from(scope),
        cached: Spinlock::new(Cached { state: AC_STATE_UNKNOWN, expires_ns: 0 }),
        published: Spinlock::new(Weak::new()),
    });
    adapter.refresh();
    if adapter.cached.lock().state == AC_STATE_UNKNOWN { return None; }

    let desc = SupplyDesc::new(
        &device_name(scope), PsyType::Mains, alloc::vec![Property::Online],
    );
    let psy = power_supply::register(desc, adapter.clone() as Arc<dyn SupplyOps>).ok()?;
    *adapter.published.lock() = Arc::downgrade(&psy);
    Some(psy)
}
