// One registered power supply: what it declares, the driver vtable, and the
// property get/set ladder the class runs before a driver is ever asked.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use sync::{Devices, Spinlock};
use thermal::{Cadence, ZoneDesc, ZoneOps, ThermalZone};
use vfs::{KResult, VfsError};

use crate::uapi::Property;
use crate::values::PsyType;

/// A property value. Integers carry the class units (`uapi`); strings are the
/// three identity properties.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropVal {
    Int(i32),
    Str(String),
}

impl PropVal {
    /// Integer payload, or `EINVAL` when the value is a string. # C: O(1)
    pub fn as_int(&self) -> KResult<i32> {
        match self { PropVal::Int(v) => Ok(*v), PropVal::Str(_) => Err(VfsError::Einval) }
    }
}

/// What a supply declares about itself at registration.
pub struct SupplyDesc {
    pub name: String,
    pub ty: PsyType,
    /// Properties this supply answers for. A property absent here is absent
    /// from sysfs entirely — not merely unreadable.
    pub properties: Vec<Property>,
    /// Bit per `UsbType` ordinal the supply can report.
    pub usb_types: u32,
    /// Bit per `ChargeType` ordinal the supply can report.
    pub charge_types: u32,
    /// Bit per `ChargeBehaviour` ordinal the supply can report.
    pub charge_behaviours: u32,
    /// Names of the supplies this one feeds.
    pub supplied_to: Vec<String>,
    /// Names of the supplies that feed this one.
    pub supplied_from: Vec<String>,
}

impl SupplyDesc {
    /// A supply that declares `properties` and no supply relationships.
    /// # C: O(1)
    pub fn new(name: &str, ty: PsyType, properties: Vec<Property>) -> Self {
        SupplyDesc {
            name: String::from(name),
            ty,
            properties,
            usb_types: 0,
            charge_types: 0,
            charge_behaviours: 0,
            supplied_to: Vec::new(),
            supplied_from: Vec::new(),
        }
    }
}

/// Driver vtable for one supply.
pub trait SupplyOps: Send + Sync {
    /// Read one declared property.
    fn get_property(&self, prop: Property) -> KResult<PropVal>;
    /// Write one writable property. # C: O(driver)
    fn set_property(&self, _prop: Property, _value: &PropVal) -> KResult<()> {
        Err(VfsError::Einval)
    }
    /// Whether `prop` accepts a write. # C: O(1)
    fn property_is_writeable(&self, _prop: Property) -> bool { false }
    /// A supply this one draws from changed state. # C: O(driver)
    fn external_power_changed(&self) {}
}

/// A registered power supply.
pub struct PowerSupply {
    desc: SupplyDesc,
    ops: Spinlock<Option<Arc<dyn SupplyOps>>, Devices>,
    /// Set once registration has finished. Until then a property read reports
    /// `EAGAIN`: the object exists but the driver is not yet ready to answer,
    /// which is a different thing from a supply that has gone away.
    initialized: AtomicBool,
    /// Set at the start of teardown, before the class forgets the device.
    removing: AtomicBool,
    hwmon_id: AtomicU32,
    thermal_zone: Spinlock<Option<Arc<ThermalZone>>, Devices>,
}

impl PowerSupply {
    /// Build a supply. It is not readable until [`PowerSupply::mark_initialized`].
    /// # C: O(1)
    pub fn new(desc: SupplyDesc, ops: Arc<dyn SupplyOps>) -> Self {
        PowerSupply {
            desc,
            ops: Spinlock::new(Some(ops)),
            initialized: AtomicBool::new(false),
            removing: AtomicBool::new(false),
            hwmon_id: AtomicU32::new(u32::MAX),
            thermal_zone: Spinlock::new(None),
        }
    }

    /// Declared identity and property set. # C: O(1)
    pub fn desc(&self) -> &SupplyDesc { &self.desc }

    /// Supply name — the `/sys/class/power_supply/<name>` directory. # C: O(1)
    pub fn name(&self) -> &str { &self.desc.name }

    /// Supply category. Fixed at registration. # C: O(1)
    pub fn ty(&self) -> PsyType { self.desc.ty }

    /// Open the supply for reads. # C: O(1)
    pub fn mark_initialized(&self) { self.initialized.store(true, Ordering::Release); }

    /// Begin teardown: reads report `ENODEV` and uevents stop. # C: O(1)
    pub fn mark_removing(&self) {
        self.removing.store(true, Ordering::Release);
        *self.ops.lock() = None;
    }

    /// Whether teardown has begun. # C: O(1)
    pub fn removing(&self) -> bool { self.removing.load(Ordering::Acquire) }

    /// Assign the hwmon instance number owned by the power-supply registry.
    /// # C: O(1)
    pub(crate) fn set_hwmon_id(&self, id: u32) { self.hwmon_id.store(id, Ordering::Release); }

    /// Return the assigned hwmon instance number, if this supply projects one.
    /// # C: O(1)
    pub fn hwmon_id(&self) -> Option<u32> {
        match self.hwmon_id.load(Ordering::Acquire) { u32::MAX => None, id => Some(id) }
    }

    /// Attach the class-owned thermal projection created for a temperature
    /// provider. # C: O(1)
    pub(crate) fn set_thermal_zone(&self, zone: Arc<ThermalZone>) {
        *self.thermal_zone.lock() = Some(zone);
    }

    /// Take the thermal projection during supply teardown. # C: O(1)
    pub(crate) fn take_thermal_zone(&self) -> Option<Arc<ThermalZone>> {
        self.thermal_zone.lock().take()
    }

    /// Whether this supply declares `prop`. # C: O(N_declared)
    pub fn has_property(&self, prop: Property) -> bool {
        self.desc.properties.iter().any(|declared| *declared == prop)
    }

    /// Driver handle plus the readiness verdict. # C: O(1)
    fn live_ops(&self) -> KResult<Arc<dyn SupplyOps>> {
        if self.removing() { return Err(VfsError::Enodev); }
        if !self.initialized.load(Ordering::Acquire) { return Err(VfsError::Eagain); }
        self.ops.lock().clone().ok_or(VfsError::Enodev)
    }

    /// Read one property. A property this supply does not declare reports
    /// `EINVAL`; a declared property whose value is momentarily unavailable is
    /// the driver's `ENODATA` and reaches the caller unchanged. # C: O(driver)
    pub fn get_property(&self, prop: Property) -> KResult<PropVal> {
        let ops = self.live_ops()?;
        if !self.has_property(prop) { return Err(VfsError::Einval); }
        ops.get_property(prop)
    }

    /// Write one property. # C: O(driver)
    pub fn set_property(&self, prop: Property, value: &PropVal) -> KResult<()> {
        let ops = self.live_ops()?;
        if !self.has_property(prop) { return Err(VfsError::Einval); }
        ops.set_property(prop, value)
    }

    /// Whether `prop` accepts a write. Undeclared properties never do.
    /// # C: O(N_declared)
    pub fn property_is_writeable(&self, prop: Property) -> bool {
        if !self.has_property(prop) { return false; }
        let ops = self.ops.lock().clone();
        ops.is_some_and(|ops| ops.property_is_writeable(prop))
    }

    /// Notify the driver that a supply it draws from changed. # C: O(driver)
    pub fn external_power_changed(&self) {
        let Ok(ops) = self.live_ops() else { return; };
        ops.external_power_changed();
    }

    /// Whether `supplier` feeds this supply. Either side may declare the
    /// relationship. # C: O(N_names)
    pub fn is_supplied_by(&self, supplier: &PowerSupply) -> bool {
        if core::ptr::eq(self, supplier) { return false; }
        self.desc.supplied_from.iter().any(|name| name == supplier.name())
            || supplier.desc.supplied_to.iter().any(|name| name == self.name())
    }
}

/// The generic Linux power-supply-to-thermal adapter. The weak reference is
/// deliberate: the thermal registry owns the zone, while the supply owns its
/// teardown handle, so neither class keeps the other alive.
pub(crate) struct SupplyThermal {
    supply: Weak<PowerSupply>,
}

impl ZoneOps for SupplyThermal {
    fn get_temp(&self) -> KResult<i32> {
        let supply = self.supply.upgrade().ok_or(VfsError::Enodev)?;
        let value = supply.get_property(Property::Temp)?.as_int()?;
        value.checked_mul(100).ok_or(VfsError::Einval)
    }
}

pub(crate) fn thermal_zone(supply: &Arc<PowerSupply>) -> KResult<Option<Arc<ThermalZone>>> {
    if !supply.has_property(Property::Temp) { return Ok(None); }
    let ops = Arc::new(SupplyThermal { supply: Arc::downgrade(supply) });
    thermal::register_zone(
        ZoneDesc::new(supply.name(), Vec::new(), Cadence { polling_ms: 0, passive_ms: 0 }),
        ops,
    ).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    struct Battery { changed: AtomicU32 }

    impl SupplyOps for Battery {
        fn get_property(&self, prop: Property) -> KResult<PropVal> {
            match prop {
                Property::Present => Ok(PropVal::Int(1)),
                Property::Capacity => Ok(PropVal::Int(73)),
                Property::ModelName => Ok(PropVal::Str(String::from("OXP-1"))),
                // Declared, but the reading is not available right now.
                Property::VoltageNow => Err(VfsError::Enodata),
                _ => Err(VfsError::Einval),
            }
        }
        fn set_property(&self, _prop: Property, _value: &PropVal) -> KResult<()> { Ok(()) }
        fn property_is_writeable(&self, prop: Property) -> bool {
            prop == Property::ChargeControlEndThreshold
        }
        fn external_power_changed(&self) { self.changed.fetch_add(1, Ordering::Relaxed); }
    }

    fn declared() -> Vec<Property> {
        alloc::vec![
            Property::Present, Property::Capacity, Property::ModelName, Property::VoltageNow,
            Property::ChargeControlEndThreshold,
        ]
    }

    fn supply() -> (PowerSupply, Arc<Battery>) {
        let ops = Arc::new(Battery { changed: AtomicU32::new(0) });
        let desc = SupplyDesc::new("BAT0", PsyType::Battery, declared());
        (PowerSupply::new(desc, ops.clone()), ops)
    }

    #[test]
    fn a_supply_is_not_readable_until_registration_finishes() {
        let (psy, _) = supply();
        assert_eq!(psy.get_property(Property::Capacity), Err(VfsError::Eagain));
        psy.mark_initialized();
        assert_eq!(psy.get_property(Property::Capacity), Ok(PropVal::Int(73)));
    }

    #[test]
    fn an_undeclared_property_is_einval_not_a_driver_call() {
        let (psy, _) = supply();
        psy.mark_initialized();
        assert_eq!(psy.get_property(Property::Temp), Err(VfsError::Einval));
        assert!(!psy.has_property(Property::Temp));
        assert!(psy.has_property(Property::Capacity));
    }

    #[test]
    fn a_declared_but_unavailable_reading_is_enodata_not_einval() {
        let (psy, _) = supply();
        psy.mark_initialized();
        assert_eq!(psy.get_property(Property::VoltageNow), Err(VfsError::Enodata));
    }

    #[test]
    fn a_removed_supply_reports_enodev_rather_than_eagain() {
        let (psy, _) = supply();
        psy.mark_initialized();
        psy.mark_removing();
        assert!(psy.removing());
        assert_eq!(psy.get_property(Property::Capacity), Err(VfsError::Enodev));
        assert_eq!(psy.set_property(Property::Capacity, &PropVal::Int(1)), Err(VfsError::Enodev));
    }

    #[test]
    fn writability_is_per_property_and_never_true_for_an_undeclared_one() {
        let (psy, _) = supply();
        psy.mark_initialized();
        assert!(psy.property_is_writeable(Property::ChargeControlEndThreshold));
        assert!(!psy.property_is_writeable(Property::Capacity));
        assert!(!psy.property_is_writeable(Property::ChargeControlStartThreshold),
                "an undeclared property must never be writable");
    }

    #[test]
    fn string_and_integer_values_stay_distinct() {
        let (psy, _) = supply();
        psy.mark_initialized();
        assert_eq!(psy.get_property(Property::ModelName), Ok(PropVal::Str(String::from("OXP-1"))));
        assert_eq!(PropVal::Str(String::from("x")).as_int(), Err(VfsError::Einval));
        assert_eq!(PropVal::Int(7).as_int(), Ok(7));
    }

    #[test]
    fn a_supply_relationship_is_recognised_from_either_side() {
        let mut battery = SupplyDesc::new("BAT0", PsyType::Battery, declared());
        battery.supplied_from.push(String::from("ADP1"));
        let battery = PowerSupply::new(battery, Arc::new(Battery { changed: AtomicU32::new(0) }));

        let mut charger = SupplyDesc::new("ADP1", PsyType::Mains, alloc::vec![Property::Online]);
        charger.supplied_to.push(String::from("BAT0"));
        let charger = PowerSupply::new(charger, Arc::new(Battery { changed: AtomicU32::new(0) }));

        assert!(battery.is_supplied_by(&charger));
        assert!(!charger.is_supplied_by(&battery));
        assert!(!battery.is_supplied_by(&battery), "a supply does not feed itself");
    }

    #[test]
    fn external_power_changed_only_reaches_a_live_driver() {
        let (psy, ops) = supply();
        psy.external_power_changed();
        assert_eq!(ops.changed.load(Ordering::Relaxed), 0, "not while still registering");
        psy.mark_initialized();
        psy.external_power_changed();
        assert_eq!(ops.changed.load(Ordering::Relaxed), 1);
        psy.mark_removing();
        psy.external_power_changed();
        assert_eq!(ops.changed.load(Ordering::Relaxed), 1, "not after teardown began");
    }
}
