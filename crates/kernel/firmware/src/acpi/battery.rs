//! ACPI control-method battery provider for the power-supply class.
//!
//! Module manifest:
//! - `decode`: `_BIF`/`_BIX`/`_BST` package decoding and unit conversion.
//! - `props`: decoded reading to power-supply property mapping.
//! - this file: namespace scan, the cached reading, and class registration.

pub mod decode;
pub mod props;
#[cfg(test)]
mod tests;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use power_supply::{PowerSupply, Property, PropVal, PsyType, SupplyDesc, SupplyOps};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use super::aml_eval;
use decode::{parse_bif, parse_bix, parse_bst, Info, State};
use props::Reading;

static BATTERIES: Spinlock<Vec<Weak<AcpiBattery>>, Devices> = Spinlock::new(Vec::new());

/// Hardware identifier of a control-method battery.
pub const BATTERY_HID: &str = "PNP0C0A";
/// `_STA` bit reporting that the battery is physically installed.
const STA_BATTERY_PRESENT: u64 = 1 << 4;
/// `_STA` value assumed when the device declares no `_STA` at all: present
/// and enabled, per the firmware convention.
const STA_ASSUMED_PRESENT: u64 = 0x1F;
/// How long a `_BST` reading stays usable. Evaluating it is a firmware call,
/// and a power daemon reads several attributes in a burst.
const READING_LIFETIME_NS: u64 = 1_000_000_000;

struct Cached {
    info: Info,
    state: State,
    present: bool,
    /// Monotonic time after which the reading must be taken again.
    expires_ns: u64,
    /// Whether `info` has ever been read successfully.
    described: bool,
}

/// One control-method battery.
pub struct AcpiBattery {
    scope: String,
    cached: Spinlock<Cached, Devices>,
    published: Spinlock<Weak<PowerSupply>, Devices>,
}

/// A refresh outcome worth telling the class about. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Transition { None, Changed }

impl AcpiBattery {
    /// Read `_STA`, `_BIX`/`_BIF` and `_BST` unless the cached reading is
    /// still current. Returns whether anything a consumer can observe moved.
    /// # C: O(AML)
    fn refresh(&self) -> Transition {
        let now = timekeeper::monotonic_ns();
        {
            let cached = self.cached.lock();
            if now < cached.expires_ns { return Transition::None; }
        }
        let sta = aml_eval::eval_integer(&self.scope, "_STA").unwrap_or(STA_ASSUMED_PRESENT);
        let present = sta & STA_BATTERY_PRESENT != 0;
        let info = if present { self.read_info() } else { None };
        let state = if present { self.read_state(info.as_ref()) } else { None };

        let mut cached = self.cached.lock();
        let before = (cached.present, cached.state);
        cached.present = present;
        cached.expires_ns = now + READING_LIFETIME_NS;
        if let Some(info) = info { cached.info = info; cached.described = true; }
        if let Some(state) = state { cached.state = state; }
        if !present { cached.state = State::default(); }
        let after = (cached.present, cached.state);
        drop(cached);
        if before == after { Transition::None } else { Transition::Changed }
    }

    /// Read the constant description, preferring the extended package.
    /// # C: O(AML)
    fn read_info(&self) -> Option<Info> {
        if let Some(fields) = aml_eval::eval_package(&self.scope, "_BIX") {
            if let Some(info) = parse_bix(&fields) { return Some(info); }
        }
        parse_bif(&aml_eval::eval_package(&self.scope, "_BIF")?)
    }

    /// Read the varying state. # C: O(AML)
    fn read_state(&self, info: Option<&Info>) -> Option<State> {
        let power_unit_ma = info.map_or_else(
            || self.cached.lock().info.power_unit_ma,
            |info| info.power_unit_ma,
        );
        parse_bst(&aml_eval::eval_package(&self.scope, "_BST")?, power_unit_ma)
    }

    /// Program the firmware's charge-level trip point so the platform raises
    /// an event as the battery approaches its warning capacity. # C: O(AML)
    fn arm_trip_point(&self, warning: u32) {
        if warning == 0 || warning == decode::VALUE_UNKNOWN { return; }
        let _ = aml_eval::eval_with_integer(&self.scope, "_BTP", u64::from(warning));
    }

    /// Refresh, then publish a change event when the reading moved. The class
    /// lock is not held across this. # C: O(AML)
    fn refresh_and_notify(&self) {
        if self.refresh() == Transition::None { return; }
        let published = self.published.lock().upgrade();
        if let Some(psy) = published { power_supply::changed(&psy); }
    }
}

impl SupplyOps for AcpiBattery {
    fn get_property(&self, prop: Property) -> KResult<PropVal> {
        self.refresh_and_notify();
        // Resolved before the reading is locked: it queries another supply,
        // and only the charge status depends on it.
        let system_supplied = prop == Property::Status && mains_online();
        let cached = self.cached.lock();
        if !cached.described && cached.present { return Err(VfsError::Enodev); }
        let alarm = if cached.info.design_capacity_warning == decode::VALUE_UNKNOWN {
            None
        } else {
            Some(cached.info.design_capacity_warning)
        };
        props::get(&Reading {
            present: cached.present,
            info: &cached.info,
            state: &cached.state,
            alarm,
            system_supplied,
        }, prop)
    }
}

/// Whether any registered mains supply reports itself online. A battery that
/// claims to discharge at zero rate while the machine is plugged in is not
/// discharging, and reporting it as such is what makes a desktop show a
/// draining battery on a docked laptop. # C: O(N_supplies)
fn mains_online() -> bool {
    power_supply::supplies().iter().any(|psy| {
        psy.ty() == PsyType::Mains
            && psy.get_property(Property::Online) == Ok(PropVal::Int(1))
    })
}

/// Scan the firmware namespace for control-method batteries and publish each
/// one to the power-supply class. Returns how many were registered.
/// # C: O(namespace + AML)
pub fn init() -> usize {
    let mut registered = 0;
    for scope in aml_eval::devices_with_hid(BATTERY_HID) {
        if register_one(&scope).is_some() { registered += 1; }
    }
    registered
}

/// Publish one battery. A battery whose description cannot be read is not
/// published at all: an empty supply directory is worse than an absent one,
/// because a power daemon treats it as a device it should be able to read.
/// # C: O(AML)
fn register_one(scope: &str) -> Option<Arc<PowerSupply>> {
    let battery = Arc::new(AcpiBattery {
        scope: String::from(scope),
        cached: Spinlock::new(Cached {
            info: Info::default(),
            state: State::default(),
            present: false,
            expires_ns: 0,
            described: false,
        }),
        published: Spinlock::new(Weak::new()),
    });
    battery.refresh();
    let cached = battery.cached.lock();
    if !cached.described { return None; }
    let info = cached.info.clone();
    drop(cached);
    battery.arm_trip_point(info.design_capacity_warning);

    let desc = SupplyDesc::new(
        &props::device_name(scope), PsyType::Battery, props::properties(&info),
    );
    let psy = power_supply::register(desc, battery.clone() as Arc<dyn SupplyOps>).ok()?;
    *battery.published.lock() = Arc::downgrade(&psy);
    BATTERIES.lock().push(Arc::downgrade(&battery));
    Some(psy)
}

/// Deliver one AML notification to its exact battery provider. The event
/// invalidates the timed cache and publishes even when the sampled values are
/// unchanged, matching a firmware-originated change indication. # C: O(N)
pub(crate) fn notified(scope: &str, _event: u64) -> bool {
    let battery = BATTERIES.lock().iter().filter_map(Weak::upgrade)
        .find(|battery| battery.scope == scope);
    let Some(battery) = battery else { return false; };
    battery.cached.lock().expires_ns = 0;
    let _ = battery.refresh();
    if let Some(psy) = battery.published.lock().upgrade() { power_supply::changed(&psy); }
    true
}

/// Namespace paths of the batteries the firmware publishes, for callers that
/// only need to know whether the platform has one. # C: O(namespace)
pub fn present_batteries() -> Vec<String> { aml_eval::devices_with_hid(BATTERY_HID) }
