//! Canonical ACPI namespace-device and power-resource ownership.
//!
//! Linux embeds wake data in its one `acpi_device` and makes every AML
//! `PowerResource` a shared object with one reference count. This module keeps
//! the same boundary: event code owns GPE registers, while devices own `_PRW`
//! policy and hold indices into this single power-resource registry.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use super::aml_eval;

const RESOURCE_UNKNOWN: u8 = 0;
const RESOURCE_OFF: u8 = 1;
const RESOURCE_ON: u8 = 2;
const S5: u8 = 5;

struct PowerResource {
    path: String,
    system_level: u8,
    order: u16,
    refs: AtomicUsize,
    state: AtomicU8,
}

struct WakeDevice {
    path: String,
    gpe_device: Option<String>,
    gpe: u8,
    deepest: u8,
    resources: Vec<usize>,
    enabled: AtomicBool,
    valid: AtomicBool,
    prepare_count: AtomicUsize,
}

struct Registry { devices: Vec<WakeDevice>, resources: Vec<PowerResource> }

static REGISTRY: AtomicPtr<Registry> = AtomicPtr::new(core::ptr::null_mut());

/// Stable read-side view of one canonical ACPI wake-capable device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakeDeviceInfo {
    pub path: String,
    pub gpe_device: Option<String>,
    pub gpe: u8,
    pub deepest_sleep_state: u8,
    pub enabled: bool,
    pub valid: bool,
    pub power_resources: Vec<String>,
}

fn registry() -> Option<&'static Registry> {
    let pointer = REGISTRY.load(Ordering::Acquire);
    if pointer.is_null() { return None; }
    // SAFETY: init publishes one leaked Box; the registry remains live for boot.
    Some(unsafe { &*pointer })
}

/// Build the one ACPI device/power-resource registry from the AML namespace.
/// # C: O(namespace + devices * resources) # Ctx: boot, single CPU
pub(crate) fn init() -> usize {
    if let Some(registry) = registry() { return registry.devices.len(); }
    let owned = build_registry(aml_eval::power_resources(), aml_eval::wake_devices(), |path| {
        match aml_eval::eval_integer(path, "_STA") {
            Some(value) if value & 1 != 0 => RESOURCE_ON,
            Some(_) => RESOURCE_OFF,
            None => RESOURCE_UNKNOWN,
        }
    });
    let count = owned.devices.len();
    let pointer = Box::into_raw(Box::new(owned));
    if REGISTRY.compare_exchange(core::ptr::null_mut(), pointer,
        Ordering::AcqRel, Ordering::Acquire).is_err() {
        // SAFETY: publication failed, so no reader can own this allocation.
        drop(unsafe { Box::from_raw(pointer) });
        return registry().map_or(0, |registry| registry.devices.len());
    }
    count
}

fn build_registry(
    resource_decls: Vec<aml_eval::PowerResourceDecl>,
    device_decls: Vec<aml_eval::PrwDevice>,
    mut initial_state: impl FnMut(&str) -> u8,
) -> Registry {
    let resources: Vec<PowerResource> = resource_decls.into_iter().map(|decl| {
        let state = initial_state(&decl.path);
        PowerResource { path: decl.path, system_level: decl.system_level,
            order: decl.order, refs: AtomicUsize::new(0), state: AtomicU8::new(state) }
    }).collect();
    let mut devices = Vec::new();
    for decl in device_decls {
        let mut owned = Vec::new();
        let mut complete = true;
        for path in &decl.power_resources {
            let Some(index) = resources.iter().position(|resource| resource.path == *path) else {
                complete = false;
                break;
            };
            if !owned.contains(&index) { owned.push(index); }
        }
        if !complete { continue; }
        owned.sort_by_key(|index| resources[*index].order);
        let deepest = owned.iter().fold(decl.sleep_state,
            |state, index| state.min(resources[*index].system_level.min(S5)));
        devices.push(WakeDevice { path: decl.path, gpe_device: decl.gpe_device,
            gpe: decl.gpe_number, deepest, resources: owned,
            enabled: AtomicBool::new(decl.default_enabled), valid: AtomicBool::new(false),
            prepare_count: AtomicUsize::new(0) });
    }
    Registry { devices, resources }
}

fn wake_control(device: &WakeDevice, enable: bool, state: u8) -> bool {
    let value = u64::from(enable);
    if aml_eval::has_method(&device.path, "_DSW") {
        return aml_eval::eval_with_integers(&device.path, "_DSW",
            &[value, u64::from(state), if enable { 3 } else { 0 }]);
    }
    if aml_eval::has_method(&device.path, "_PSW") {
        return aml_eval::eval_with_integer(&device.path, "_PSW", value);
    }
    true
}

/// Bind fixed-block `_PRW` declarations to event-core GPE ownership. Named
/// GPE devices remain invalid until their own GPE-block driver exists.
pub(crate) fn activate_fixed_gpes(mut contains: impl FnMut(u8) -> bool) {
    let Some(registry) = registry() else { return; };
    for device in &registry.devices {
        if device.gpe_device.is_some() || !contains(device.gpe) { continue; }
        if wake_control(device, false, 0) { device.valid.store(true, Ordering::Release); }
    }
    reconcile_unused_resources(registry);
}

fn reconcile_unused_resources(registry: &Registry) {
    for resource in &registry.resources {
        if resource.refs.load(Ordering::Acquire) == 0
            && resource.state.load(Ordering::Acquire) == RESOURCE_ON
            && aml_eval::eval_no_args(&resource.path, "_OFF") {
            resource.state.store(RESOURCE_OFF, Ordering::Release);
        }
    }
}

fn resource_on(resource: &PowerResource,
               transition: &mut impl FnMut(&str, bool) -> bool) -> bool {
    if resource.refs.fetch_add(1, Ordering::AcqRel) != 0 { return true; }
    if transition(&resource.path, true) {
        resource.state.store(RESOURCE_ON, Ordering::Release);
        return true;
    }
    resource.state.store(RESOURCE_UNKNOWN, Ordering::Release);
    resource.refs.fetch_sub(1, Ordering::AcqRel);
    false
}

fn resource_off(resource: &PowerResource,
                transition: &mut impl FnMut(&str, bool) -> bool) -> bool {
    let Ok(previous) = resource.refs.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |count| (count != 0).then_some(count - 1)) else { return true; };
    if previous > 1 { return true; }
    if transition(&resource.path, false) {
        resource.state.store(RESOURCE_OFF, Ordering::Release);
        return true;
    }
    resource.state.store(RESOURCE_UNKNOWN, Ordering::Release);
    resource.refs.fetch_add(1, Ordering::AcqRel);
    false
}

fn power_on(registry: &Registry, device: &WakeDevice,
            transition: &mut impl FnMut(&str, bool) -> bool) -> bool {
    for (position, index) in device.resources.iter().enumerate() {
        if resource_on(&registry.resources[*index], transition) { continue; }
        for prior in device.resources[..position].iter().rev() {
            let _ = resource_off(&registry.resources[*prior], transition);
        }
        return false;
    }
    true
}

fn power_off(registry: &Registry, device: &WakeDevice,
             transition: &mut impl FnMut(&str, bool) -> bool) -> bool {
    for position in (0..device.resources.len()).rev() {
        if resource_off(&registry.resources[device.resources[position]], transition) { continue; }
        for later in device.resources[position + 1..].iter() {
            let _ = resource_on(&registry.resources[*later], transition);
        }
        return false;
    }
    true
}

fn prepare_one(registry: &Registry, device: &WakeDevice, state: u8) -> bool {
    if device.prepare_count.fetch_add(1, Ordering::AcqRel) != 0 { return true; }
    let mut transition = |path: &str, on: bool| {
        aml_eval::eval_no_args(path, if on { "_ON" } else { "_OFF" })
    };
    if power_on(registry, device, &mut transition) && wake_control(device, true, state) { return true; }
    let _ = power_off(registry, device, &mut transition);
    device.prepare_count.store(0, Ordering::Release);
    device.valid.store(false, Ordering::Release);
    false
}

fn finish_one(registry: &Registry, device: &WakeDevice) -> bool {
    let Ok(previous) = device.prepare_count.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |count| (count != 0).then_some(count - 1)) else { return true; };
    if previous > 1 { return true; }
    if !wake_control(device, false, 0) {
        device.valid.store(false, Ordering::Release);
        return false;
    }
    let mut transition = |path: &str, on: bool| {
        aml_eval::eval_no_args(path, if on { "_ON" } else { "_OFF" })
    };
    if power_off(registry, device, &mut transition) { return true; }
    device.valid.store(false, Ordering::Release);
    false
}

/// Power and program every selected canonical wake device. # C: O(devices * AML)
pub fn prepare_wake_devices(state: u8) -> bool {
    if state > S5 { return false; }
    let Some(registry) = registry() else { return true; };
    let mut prepared = Vec::new();
    for (index, device) in registry.devices.iter().enumerate() {
        if !device.valid.load(Ordering::Acquire)
            || !device.enabled.load(Ordering::Acquire) || state > device.deepest { continue; }
        if prepare_one(registry, device, state) { prepared.push(index); continue; }
        for index in prepared.into_iter().rev() { let _ = finish_one(registry, &registry.devices[index]); }
        return false;
    }
    true
}

/// Disable firmware wake control and release shared resources after resume.
pub fn finish_wake_devices() {
    let Some(registry) = registry() else { return; };
    for device in &registry.devices { let _ = finish_one(registry, device); }
}

/// Whether the canonical owner prepared this fixed GPE for the current sleep.
pub(crate) fn fixed_gpe_prepared(gpe: u8) -> bool {
    registry().is_some_and(|registry| registry.devices.iter().any(|device| {
        device.gpe_device.is_none() && device.gpe == gpe
            && device.prepare_count.load(Ordering::Acquire) != 0
    }))
}

/// Number of decoded ACPI wake-device owners. # C: O(1)
pub fn wake_device_count() -> usize { registry().map_or(0, |registry| registry.devices.len()) }

/// Read one canonical wake-device owner by discovery order. # C: O(resources)
pub fn wake_device_info(index: usize) -> Option<WakeDeviceInfo> {
    let registry = registry()?;
    let device = registry.devices.get(index)?;
    Some(WakeDeviceInfo { path: device.path.clone(), gpe_device: device.gpe_device.clone(),
        gpe: device.gpe, deepest_sleep_state: device.deepest,
        enabled: device.enabled.load(Ordering::Acquire),
        valid: device.valid.load(Ordering::Acquire),
        power_resources: device.resources.iter()
            .map(|index| registry.resources[*index].path.clone()).collect() })
}

/// Set the one policy bit owned by the canonical ACPI device. # C: O(devices)
pub fn set_wake_device_enabled(path: &str, enabled: bool) -> bool {
    let Some(registry) = registry() else { return false; };
    let Some(device) = registry.devices.iter().find(|device| device.path == path) else { return false; };
    device.enabled.store(enabled, Ordering::Release);
    true
}

#[cfg(test)]
#[path = "device_model/tests.rs"]
mod tests;
