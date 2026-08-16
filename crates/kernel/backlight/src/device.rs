// One registered backlight device: its properties, the driver vtable, and the
// blank/brightness/power rules the class enforces before it ever calls a
// driver.

use alloc::string::String;
use alloc::sync::Arc;
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use crate::uapi::{BacklightScale, BacklightType, BACKLIGHT_POWER_ON, BL_CORE_FBBLANK,
                  BL_CORE_SUSPENDED};

/// The properties a backlight device publishes. `max_brightness` is fixed at
/// registration; `brightness` is the level the class last asked the driver
/// for, which is not necessarily the level the panel is currently at (see
/// [`BacklightDevice::actual_brightness`]).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Properties {
    pub brightness: i32,
    pub max_brightness: i32,
    pub power: i32,
    pub ty: BacklightType,
    pub state: u32,
    pub scale: BacklightScale,
}

impl Default for Properties {
    /// A device registered without properties is a full-on raw backlight of
    /// unknown scale. # C: O(1)
    fn default() -> Self {
        Properties {
            brightness: 0,
            max_brightness: 0,
            power: BACKLIGHT_POWER_ON,
            ty: BacklightType::Raw,
            state: 0,
            scale: BacklightScale::Unknown,
        }
    }
}

/// A backlight device is blank when it is powered down or when the class has
/// marked it suspended or its display blanked. # C: O(1)
pub fn is_blank(props: &Properties) -> bool {
    props.power != BACKLIGHT_POWER_ON
        || props.state & (BL_CORE_SUSPENDED | BL_CORE_FBBLANK) != 0
}

/// The level a driver must actually program: zero whenever the device is
/// blank, otherwise the requested brightness. # C: O(1)
pub fn effective_brightness(props: &Properties) -> i32 {
    if is_blank(props) { 0 } else { props.brightness }
}

/// Outcome of validating a `brightness` write before any driver is called.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BrightnessVerdict {
    /// The device has been unregistered; the value is discarded.
    Detached,
    /// Above `max_brightness`. The class rejects rather than clamping, so a
    /// caller cannot mistake a silently clamped write for a honoured one.
    OutOfRange,
    /// Store this level and call the driver.
    Apply(i32),
}

/// Validate a `brightness` write. Only the upper bound is checked: the value
/// arrives from an unsigned conversion, so it can never be negative.
/// # C: O(1)
pub fn classify_brightness(attached: bool, max_brightness: i32, requested: u64) -> BrightnessVerdict {
    if !attached { return BrightnessVerdict::Detached; }
    if max_brightness < 0 || requested > max_brightness as u64 { return BrightnessVerdict::OutOfRange; }
    BrightnessVerdict::Apply(requested as i32)
}

/// Driver vtable for one backlight device.
pub trait BacklightOps: Send + Sync {
    /// Program the panel from `props`. Drivers read the level through
    /// [`effective_brightness`] so a blanked device programs zero.
    fn update_status(&self, props: &Properties) -> KResult<()>;
    /// Read the level back from the hardware. `None` means the driver has no
    /// readback and `actual_brightness` reports the requested level instead.
    /// # C: O(1)
    fn get_brightness(&self, _props: &Properties) -> Option<KResult<i32>> { None }
    /// `BL_CORE_*` option bits. # C: O(1)
    fn options(&self) -> u32 { 0 }
}

struct Inner {
    props: Properties,
    /// Cleared on unregistration. Every store path checks it, which is what
    /// makes a write to a departed device report `ENXIO` instead of touching
    /// a driver that is gone.
    ops: Option<Arc<dyn BacklightOps>>,
}

/// One device in the backlight class.
pub struct BacklightDevice {
    name: String,
    inner: Spinlock<Inner, Devices>,
}

impl BacklightDevice {
    /// Build a device. An out-of-range type is coerced to raw rather than
    /// refused. # C: O(1)
    pub fn new(name: String, props: Properties, ops: Arc<dyn BacklightOps>) -> Self {
        let props = Properties { ty: BacklightType::from_raw(props.ty as u32), ..props };
        BacklightDevice { name, inner: Spinlock::new(Inner { props, ops: Some(ops) }) }
    }

    /// Device name — the `/sys/class/backlight/<name>` directory. # C: O(1)
    pub fn name(&self) -> &str { &self.name }

    /// Snapshot of the current properties. # C: O(1)
    pub fn props(&self) -> Properties { self.inner.lock().props }

    /// Whether a driver is still attached. # C: O(1)
    pub fn attached(&self) -> bool { self.inner.lock().ops.is_some() }

    /// Publish device type without taking a properties snapshot. # C: O(1)
    pub fn device_type(&self) -> BacklightType { self.inner.lock().props.ty }

    /// Drop the driver vtable. After this every store reports `ENXIO` and
    /// `actual_brightness` falls back to the last requested level. # C: O(1)
    pub fn detach(&self) { self.inner.lock().ops = None; }

    /// Call the driver's `update_status`. A device with no driver attached
    /// reports `ENOENT`, distinguishing "nothing to program" from a store to
    /// a departed device. # C: O(driver)
    pub fn update_status(&self) -> KResult<()> {
        let guard = self.inner.lock();
        let ops = guard.ops.clone().ok_or(VfsError::Enoent)?;
        let props = guard.props;
        drop(guard);
        ops.update_status(&props)
    }

    /// `actual_brightness`: the driver's readback when it has one, otherwise
    /// the level the class last requested. # C: O(driver)
    pub fn actual_brightness(&self) -> KResult<i32> {
        let guard = self.inner.lock();
        let ops = guard.ops.clone();
        let props = guard.props;
        drop(guard);
        match ops.as_ref().and_then(|ops| ops.get_brightness(&props)) {
            Some(result) => result,
            None => Ok(props.brightness),
        }
    }

    /// `brightness` store. Rejects an out-of-range level with `EINVAL` and a
    /// write to an unregistered device with `ENXIO`, neither of which reaches
    /// the driver. # C: O(driver)
    pub fn set_brightness(&self, requested: u64) -> KResult<()> {
        let mut guard = self.inner.lock();
        let verdict = classify_brightness(guard.ops.is_some(), guard.props.max_brightness, requested);
        let level = match verdict {
            BrightnessVerdict::Detached => return Err(VfsError::Enxio),
            BrightnessVerdict::OutOfRange => return Err(VfsError::Einval),
            BrightnessVerdict::Apply(level) => level,
        };
        guard.props.brightness = level;
        let ops = guard.ops.clone().ok_or(VfsError::Enxio)?;
        let props = guard.props;
        drop(guard);
        ops.update_status(&props)
    }

    /// `bl_power` store. An unchanged value short-circuits without calling the
    /// driver; a failed change is rolled back so the published value never
    /// claims a state the panel is not in. # C: O(driver)
    pub fn set_power(&self, requested: i32) -> KResult<()> {
        let mut guard = self.inner.lock();
        if guard.ops.is_none() { return Err(VfsError::Enxio); }
        let previous = guard.props.power;
        if previous == requested { return Ok(()); }
        guard.props.power = requested;
        let ops = guard.ops.clone().ok_or(VfsError::Enxio)?;
        let props = guard.props;
        drop(guard);
        match ops.update_status(&props) {
            Ok(()) => Ok(()),
            Err(err) => { self.inner.lock().props.power = previous; Err(err) }
        }
    }

    /// Adopt a level the hardware moved to on its own (a brightness hotkey).
    /// A readback failure leaves the published level untouched. # C: O(driver)
    pub fn adopt_hardware_brightness(&self) {
        let Ok(level) = self.actual_brightness() else { return; };
        self.inner.lock().props.brightness = level;
    }

    /// Set or clear a `props.state` bit (suspend, display blank). # C: O(1)
    pub fn set_state_bit(&self, bit: u32, on: bool) {
        let mut guard = self.inner.lock();
        if on { guard.props.state |= bit; } else { guard.props.state &= !bit; }
    }

    /// Level the driver must program right now. # C: O(1)
    pub fn effective_brightness(&self) -> i32 { effective_brightness(&self.inner.lock().props) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::{BACKLIGHT_POWER_OFF, BACKLIGHT_POWER_REDUCED};
    use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    pub(crate) struct FakePanel {
        pub programmed: AtomicI32,
        pub calls: AtomicU32,
        pub readback: Option<AtomicI32>,
        pub fail: AtomicU32,
    }

    impl FakePanel {
        /// Build a fake panel with an optional readback. # C: O(1)
        pub(crate) fn new(readback: Option<i32>) -> Arc<Self> {
            Arc::new(FakePanel {
                programmed: AtomicI32::new(-1),
                calls: AtomicU32::new(0),
                readback: readback.map(AtomicI32::new),
                fail: AtomicU32::new(0),
            })
        }
    }

    impl BacklightOps for FakePanel {
        fn update_status(&self, props: &Properties) -> KResult<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail.load(Ordering::Relaxed) != 0 { return Err(VfsError::Eio); }
            self.programmed.store(effective_brightness(props), Ordering::Relaxed);
            Ok(())
        }
        fn get_brightness(&self, _props: &Properties) -> Option<KResult<i32>> {
            Some(Ok(self.readback.as_ref()?.load(Ordering::Relaxed)))
        }
    }

    const MAX: i32 = 15;

    fn device(readback: Option<i32>) -> (BacklightDevice, Arc<FakePanel>) {
        let panel = FakePanel::new(readback);
        let props = Properties { max_brightness: MAX, brightness: 5, ..Properties::default() };
        (BacklightDevice::new(String::from("acpi_video0"), props, panel.clone()), panel)
    }

    #[test]
    fn a_level_above_max_is_refused_and_never_reaches_the_driver() {
        let (dev, panel) = device(None);
        assert_eq!(dev.set_brightness(MAX as u64), Ok(()));
        assert_eq!(panel.programmed.load(Ordering::Relaxed), MAX);
        let calls = panel.calls.load(Ordering::Relaxed);
        assert_eq!(dev.set_brightness(MAX as u64 + 1), Err(VfsError::Einval));
        assert_eq!(panel.calls.load(Ordering::Relaxed), calls, "driver must not be called");
        assert_eq!(dev.props().brightness, MAX, "rejected write must not be stored");
    }

    #[test]
    fn zero_is_a_valid_level() {
        let (dev, panel) = device(None);
        assert_eq!(dev.set_brightness(0), Ok(()));
        assert_eq!(panel.programmed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_detached_device_reports_enxio_rather_than_calling_a_gone_driver() {
        let (dev, panel) = device(None);
        dev.detach();
        assert_eq!(dev.set_brightness(1), Err(VfsError::Enxio));
        assert_eq!(dev.set_power(BACKLIGHT_POWER_OFF), Err(VfsError::Enxio));
        assert_eq!(panel.calls.load(Ordering::Relaxed), 0);
        assert_eq!(dev.update_status(), Err(VfsError::Enoent));
    }

    #[test]
    fn actual_brightness_prefers_the_driver_readback() {
        let (with_readback, _) = device(Some(9));
        assert_eq!(with_readback.actual_brightness(), Ok(9));
        assert_eq!(with_readback.props().brightness, 5, "readback does not rewrite the request");
        let (without, _) = device(None);
        assert_eq!(without.actual_brightness(), Ok(5));
    }

    #[test]
    fn a_detached_device_falls_back_to_the_last_requested_level() {
        let (dev, _) = device(Some(9));
        dev.detach();
        assert_eq!(dev.actual_brightness(), Ok(5));
    }

    #[test]
    fn an_unchanged_power_value_does_not_call_the_driver() {
        let (dev, panel) = device(None);
        assert_eq!(dev.props().power, BACKLIGHT_POWER_ON);
        assert_eq!(dev.set_power(BACKLIGHT_POWER_ON), Ok(()));
        assert_eq!(panel.calls.load(Ordering::Relaxed), 0);
        assert_eq!(dev.set_power(BACKLIGHT_POWER_OFF), Ok(()));
        assert_eq!(panel.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_failed_power_change_is_rolled_back() {
        let (dev, panel) = device(None);
        panel.fail.store(1, Ordering::Relaxed);
        assert_eq!(dev.set_power(BACKLIGHT_POWER_REDUCED), Err(VfsError::Eio));
        assert_eq!(dev.props().power, BACKLIGHT_POWER_ON, "power must not claim a state the panel refused");
    }

    #[test]
    fn a_blank_device_programs_zero_without_losing_its_requested_level() {
        let (dev, panel) = device(None);
        assert_eq!(dev.set_brightness(7), Ok(()));
        assert_eq!(panel.programmed.load(Ordering::Relaxed), 7);
        assert_eq!(dev.set_power(BACKLIGHT_POWER_OFF), Ok(()));
        assert_eq!(panel.programmed.load(Ordering::Relaxed), 0);
        assert_eq!(dev.props().brightness, 7);
        assert_eq!(dev.effective_brightness(), 0);
        assert_eq!(dev.set_power(BACKLIGHT_POWER_ON), Ok(()));
        assert_eq!(panel.programmed.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn either_state_bit_blanks_the_device() {
        let (dev, _) = device(None);
        for bit in [BL_CORE_SUSPENDED, BL_CORE_FBBLANK] {
            dev.set_state_bit(bit, true);
            assert!(is_blank(&dev.props()), "state bit {bit:#x} must blank");
            assert_eq!(dev.effective_brightness(), 0);
            dev.set_state_bit(bit, false);
            assert!(!is_blank(&dev.props()));
        }
    }

    #[test]
    fn a_hotkey_readback_updates_the_published_level() {
        let (dev, panel) = device(Some(2));
        dev.adopt_hardware_brightness();
        assert_eq!(dev.props().brightness, 2);
        panel.readback.as_ref().expect("readback").store(11, Ordering::Relaxed);
        dev.adopt_hardware_brightness();
        assert_eq!(dev.props().brightness, 11);
    }

    #[test]
    fn classification_is_independent_of_any_driver() {
        assert_eq!(classify_brightness(false, 10, 1), BrightnessVerdict::Detached);
        assert_eq!(classify_brightness(true, 10, 11), BrightnessVerdict::OutOfRange);
        assert_eq!(classify_brightness(true, 10, 10), BrightnessVerdict::Apply(10));
        assert_eq!(classify_brightness(true, 10, 0), BrightnessVerdict::Apply(0));
        assert_eq!(classify_brightness(true, 10, u64::MAX), BrightnessVerdict::OutOfRange);
        assert_eq!(classify_brightness(true, -1, 0), BrightnessVerdict::OutOfRange);
    }
}
