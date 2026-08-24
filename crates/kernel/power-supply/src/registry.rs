// The power-supply class: the registered supply list, registration and
// teardown ordering, and the change path that fans a state change out to the
// supplies that draw from the one that changed before notifying userspace.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use crate::supply::{thermal_zone, PowerSupply, SupplyDesc, SupplyOps};

/// Change-notification callback, called with the supply name. The sysfs layer
/// installs one to turn a class change into a `change` uevent.
pub type ChangeHook = fn(&str);

static SUPPLIES: Spinlock<Vec<Arc<PowerSupply>>, Devices> = Spinlock::new(Vec::new());
static CHANGE_HOOK: Spinlock<Option<ChangeHook>, Devices> = Spinlock::new(None);
static NEXT_HWMON: AtomicU32 = AtomicU32::new(0);

/// Install the class change-notification callback. # C: O(1)
pub fn set_change_hook(hook: ChangeHook) { *CHANGE_HOOK.lock() = Some(hook); }

/// Register a supply. A supply with no declared properties is refused: it
/// would publish a directory with nothing in it but `type` and `uevent`, which
/// a power daemon reads as a broken device rather than an absent one.
/// A duplicate name is refused with `EEXIST`. # C: O(N_supplies)
pub fn register(desc: SupplyDesc, ops: Arc<dyn SupplyOps>) -> KResult<Arc<PowerSupply>> {
    if desc.name.is_empty() || desc.properties.is_empty() { return Err(VfsError::Einval); }
    let mut supplies = SUPPLIES.lock();
    if supplies.iter().any(|psy| psy.name() == desc.name) { return Err(VfsError::Eexist); }
    let psy = Arc::new(PowerSupply::new(desc, ops));
    if crate::hwmon::has_properties(&psy) {
        psy.set_hwmon_id(NEXT_HWMON.fetch_add(1, Ordering::Relaxed));
    }
    if let Some(zone) = thermal_zone(&psy)? { psy.set_thermal_zone(zone); }
    supplies.push(Arc::clone(&psy));
    drop(supplies);
    // The supply becomes readable only once it is in the list, so the first
    // event cannot hand a consumer a name it cannot then open.
    psy.mark_initialized();
    changed(&psy);
    Ok(psy)
}

/// Unregister a supply. Teardown is marked before the class forgets it, so a
/// read racing the removal reports `ENODEV` rather than reaching a driver that
/// is going away. # C: O(N_supplies)
pub fn unregister(psy: &Arc<PowerSupply>) -> bool {
    psy.mark_removing();
    if let Some(zone) = psy.take_thermal_zone() { let _ = thermal::unregister_zone(&zone); }
    let mut supplies = SUPPLIES.lock();
    let Some(index) = supplies.iter().position(|entry| Arc::ptr_eq(entry, psy)) else { return false; };
    supplies.remove(index);
    true
}

/// Every registered supply, in registration order. # C: O(N_supplies)
pub fn supplies() -> Vec<Arc<PowerSupply>> {
    SUPPLIES.lock().iter().map(Arc::clone).collect()
}

/// Resolve one supply by name. # C: O(N_supplies)
pub fn by_name(name: &str) -> Option<Arc<PowerSupply>> {
    SUPPLIES.lock().iter().find(|psy| psy.name() == name).cloned()
}

/// Number of registered supplies. # C: O(1)
pub fn count() -> usize { SUPPLIES.lock().len() }

/// Publish a state change on `psy`: first tell every supply that draws from
/// it, then notify userspace. The order matters — a battery asked about its
/// charger's new state after the uevent has already fired would answer from
/// stale data. # C: O(N_supplies)
pub fn changed(psy: &Arc<PowerSupply>) {
    for consumer in supplies() {
        if consumer.is_supplied_by(psy) { consumer.external_power_changed(); }
    }
    let hook = *CHANGE_HOOK.lock();
    if let Some(hook) = hook { hook(psy.name()); }
}

/// Empty the registry between tests. # C: O(N_supplies)
#[cfg(test)]
pub fn clear_for_tests() {
    for psy in supplies() { let _ = unregister(&psy); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply::PropVal;
    use crate::uapi::Property;
    use crate::values::PsyType;
    use alloc::string::String;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// One global registry: serialise the tests that mutate it.
    static REGISTRY_LOCK: Mutex<()> = Mutex::new(());
    static NOTIFICATIONS: AtomicU32 = AtomicU32::new(0);

    fn count_notification(_name: &str) { NOTIFICATIONS.fetch_add(1, Ordering::Relaxed); }

    struct Ops { external: AtomicU32 }
    impl SupplyOps for Ops {
        fn get_property(&self, _prop: Property) -> KResult<PropVal> { Ok(PropVal::Int(1)) }
        fn external_power_changed(&self) { self.external.fetch_add(1, Ordering::Relaxed); }
    }

    fn ops() -> Arc<Ops> { Arc::new(Ops { external: AtomicU32::new(0) }) }

    #[test]
    fn a_supply_with_no_properties_is_refused() {
        let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        let desc = SupplyDesc::new("BAT0", PsyType::Battery, Vec::new());
        assert!(matches!(register(desc, ops()), Err(VfsError::Einval)));
        assert_eq!(count(), 0);
        clear_for_tests();
    }

    #[test]
    fn a_duplicate_name_is_refused() {
        let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        let first = register(
            SupplyDesc::new("BAT0", PsyType::Battery, alloc::vec![Property::Present]), ops(),
        ).expect("first");
        assert!(matches!(
            register(SupplyDesc::new("BAT0", PsyType::Battery, alloc::vec![Property::Present]), ops()),
            Err(VfsError::Eexist),
        ));
        assert_eq!(count(), 1);
        assert!(unregister(&first));
        clear_for_tests();
    }

    #[test]
    fn a_registered_supply_is_readable_and_a_removed_one_is_not() {
        let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        let psy = register(
            SupplyDesc::new("ADP1", PsyType::Mains, alloc::vec![Property::Online]), ops(),
        ).expect("register");
        assert_eq!(psy.get_property(Property::Online), Ok(PropVal::Int(1)));
        assert_eq!(by_name("ADP1").map(|p| String::from(p.name())), Some(String::from("ADP1")));
        assert!(unregister(&psy));
        assert_eq!(psy.get_property(Property::Online), Err(VfsError::Enodev));
        assert!(by_name("ADP1").is_none());
        assert!(!unregister(&psy));
        clear_for_tests();
    }

    struct Temperature { tenths_c: i32 }
    impl SupplyOps for Temperature {
        fn get_property(&self, prop: Property) -> KResult<PropVal> {
            match prop {
                Property::Temp => Ok(PropVal::Int(self.tenths_c)),
                _ => Err(VfsError::Einval),
            }
        }
    }

    #[test]
    fn a_temperature_supply_gets_an_event_driven_thermal_zone_in_millidegrees() {
        let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        let psy = register(
            SupplyDesc::new("BAT-TEMP", PsyType::Battery, alloc::vec![Property::Temp]),
            Arc::new(Temperature { tenths_c: 253 }),
        ).expect("temperature supply");
        let zones = thermal::zones();
        let zone = zones.iter().find(|zone| zone.ty() == "BAT-TEMP").expect("thermal zone");
        assert_eq!(zone.cadence(), thermal::Cadence { polling_ms: 0, passive_ms: 0 });
        assert_eq!(zone.ops().get_temp(), Ok(25_300));
        assert!(unregister(&psy));
        assert!(thermal::zones().iter().all(|entry| entry.ty() != "BAT-TEMP"));
        clear_for_tests();
    }

    #[test]
    fn a_change_on_the_charger_reaches_the_battery_that_draws_from_it() {
        let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        set_change_hook(count_notification);
        NOTIFICATIONS.store(0, Ordering::Relaxed);

        let battery_ops = ops();
        let mut battery_desc = SupplyDesc::new("BAT0", PsyType::Battery, alloc::vec![Property::Capacity]);
        battery_desc.supplied_from.push(String::from("ADP1"));
        let battery = register(battery_desc, battery_ops.clone()).expect("battery");

        let charger_ops = ops();
        let charger = register(
            SupplyDesc::new("ADP1", PsyType::Mains, alloc::vec![Property::Online]), charger_ops.clone(),
        ).expect("charger");

        let before = battery_ops.external.load(Ordering::Relaxed);
        changed(&charger);
        assert_eq!(battery_ops.external.load(Ordering::Relaxed), before + 1);
        assert_eq!(charger_ops.external.load(Ordering::Relaxed), 0,
                   "a supply does not notify itself");

        let notifications = NOTIFICATIONS.load(Ordering::Relaxed);
        changed(&battery);
        assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), notifications + 1);
        assert_eq!(charger_ops.external.load(Ordering::Relaxed), 0,
                   "the battery does not feed the charger");

        assert!(unregister(&battery));
        assert!(unregister(&charger));
        clear_for_tests();
    }
}
