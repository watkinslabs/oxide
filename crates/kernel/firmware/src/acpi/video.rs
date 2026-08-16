//! ACPI video backlight provider.
//!
//! Module manifest:
//! - `levels`: `_BCL` level-list normalisation and `_BQC` readback classing.
//! - this file: namespace scan, the `_BCM`/`_BQC` calls, and registration.

pub mod levels;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use backlight::device::{effective_brightness, BacklightOps, Properties};
use backlight::{BacklightScale, BacklightType};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use super::aml_eval;
use levels::{bqc_to_index, classify_bqc, normalise, BqcMode, Levels};

/// Hardware identifier of an ACPI display adapter carrying output devices.
pub const VIDEO_HID: &str = "ACPI0008";
/// The `_HID` most firmware gives the graphics bus that owns `_BCL` outputs.
pub const VIDEO_BUS_HID: &str = "PNP0A08";
/// Class device name prefix; the suffix is the discovery order.
const DEVICE_NAME_PREFIX: &str = "acpi_video";

/// `_DOS`: the OS owns brightness switching, firmware must not act on the
/// hotkeys itself. Bit 0-1 select the BIOS switching policy, bit 2 the
/// brightness policy.
const DOS_OS_OWNS_BRIGHTNESS: u64 = 1 << 2;

struct Panel {
    scope: String,
    levels: Levels,
    bqc: Spinlock<BqcMode, Devices>,
}

impl Panel {
    /// Program a selectable index through `_BCM`. # C: O(AML)
    fn program(&self, index: i32) -> KResult<()> {
        let level = self.levels.level_at(index).ok_or(VfsError::Einval)?;
        if aml_eval::eval_with_integer(&self.scope, "_BCM", u64::from(level)) { return Ok(()); }
        Err(VfsError::Eio)
    }

    /// Read the current index back through `_BQC`. # C: O(AML)
    fn readback(&self) -> Option<i32> {
        let mode = *self.bqc.lock();
        if mode == BqcMode::Unusable { return None; }
        let raw = aml_eval::eval_integer(&self.scope, "_BQC")?;
        bqc_to_index(&self.levels, mode, raw)
    }
}

impl BacklightOps for Panel {
    fn update_status(&self, props: &Properties) -> KResult<()> {
        self.program(effective_brightness(props))
    }

    fn get_brightness(&self, props: &Properties) -> Option<KResult<i32>> {
        // A blanked panel is at zero regardless of what the firmware last
        // latched, so the readback must not contradict the blank state.
        if effective_brightness(props) == 0 && props.brightness != 0 { return Some(Ok(0)); }
        Some(Ok(self.readback()?))
    }
}

/// Settle how this firmware's `_BQC` answers, by programming a level and
/// reading it back. Firmware disagrees on whether the method returns the
/// level or its index, and guessing wrong moves the slider to the wrong place
/// on every hotkey. # C: O(AML)
fn probe_readback(scope: &str, levels: &Levels, current: i32) -> BqcMode {
    // Pick a probe level that is not the one already latched, so a stale
    // readback cannot look like a correct one.
    let probe = if current == levels.max_index() { 0 } else { levels.max_index() };
    let Some(level) = levels.level_at(probe) else { return BqcMode::Unusable; };
    if !aml_eval::eval_with_integer(scope, "_BCM", u64::from(level)) { return BqcMode::Unusable; }
    let Some(raw) = aml_eval::eval_integer(scope, "_BQC") else { return BqcMode::Unusable; };
    let mode = classify_bqc(levels, probe, raw);
    // Put the panel back where it was before the probe.
    if let Some(level) = levels.level_at(current) {
        let _ = aml_eval::eval_with_integer(scope, "_BCM", u64::from(level));
    }
    mode
}

/// Namespace paths of every device that declares a brightness-level list.
/// The list, not the identifier, is what makes a node a backlight: firmware
/// hangs `_BCL` off a display output under the graphics device, and the
/// output's own identifier is not fixed. # C: O(namespace)
fn panels() -> Vec<String> {
    let mut found = Vec::new();
    for hid in [VIDEO_HID, VIDEO_BUS_HID] {
        for scope in aml_eval::devices_with_hid(hid) {
            collect_outputs(&scope, &mut found);
        }
    }
    found
}

/// Depth of output devices below the graphics device in the namespace.
const OUTPUT_DEPTH: usize = 1;

/// Every child of `scope` that declares `_BCL`. # C: O(namespace)
fn collect_outputs(scope: &str, found: &mut Vec<String>) {
    for candidate in aml_eval::children_of(scope, OUTPUT_DEPTH) {
        if aml_eval::has_method(&candidate, "_BCL") && !found.contains(&candidate) {
            found.push(candidate);
        }
    }
    if aml_eval::has_method(scope, "_BCL") && !found.contains(&String::from(scope)) {
        found.push(String::from(scope));
    }
}

/// Scan the firmware namespace for panels with a brightness-level list and
/// publish each one to the backlight class. Returns how many were registered.
/// # C: O(namespace + AML)
pub fn init() -> usize {
    let mut registered = 0;
    for scope in panels() {
        if register_one(&scope, registered) { registered += 1; }
    }
    registered
}

/// Publish one panel. # C: O(AML)
fn register_one(scope: &str, index: usize) -> bool {
    let Some(raw) = aml_eval::eval_package(scope, "_BCL") else { return false; };
    let package: Vec<u32> = raw.iter().filter_map(|field| field.int().map(|v| v as u32)).collect();
    let Some(levels) = normalise(&package) else { return false; };

    // Take ownership of brightness switching before touching the panel, so a
    // firmware hotkey handler cannot fight the class for the level.
    let _ = aml_eval::eval_with_integer(scope, "_DOS", DOS_OS_OWNS_BRIGHTNESS);

    let max = levels.max_index();
    let mode = probe_readback(scope, &levels, 0);
    let panel = Arc::new(Panel { scope: String::from(scope), levels, bqc: Spinlock::new(mode) });
    let current = panel.readback().unwrap_or(max);

    let mut name = String::from(DEVICE_NAME_PREFIX);
    let _ = core::fmt::Write::write_fmt(&mut name, format_args!("{index}"));
    let props = Properties {
        brightness: current,
        max_brightness: max,
        ty: BacklightType::Firmware,
        // Firmware level lists are perceptual curves, not linear ramps.
        scale: BacklightScale::NonLinear,
        ..Properties::default()
    };
    backlight::register(&name, props, panel as Arc<dyn BacklightOps>).is_ok()
}
