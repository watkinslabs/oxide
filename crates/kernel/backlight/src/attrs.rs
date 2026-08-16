// The `/sys/class/backlight/<name>/` attribute contract: which files exist,
// which are writable, what each renders, and what a write does. The sysfs
// layer owns inodes; every decision about content and errno lives here so it
// can be exercised without a filesystem.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kstrtox::{kstrtoint, kstrtoul, ParseError, BASE_AUTO};
use vfs::{KResult, VfsError};

use crate::device::BacklightDevice;
use crate::registry;
use crate::uapi::UpdateReason;

/// Read-only attribute mode.
pub const RO_MODE: u16 = 0o444;
/// Read-write attribute mode.
pub const RW_MODE: u16 = 0o644;

/// One attribute of a backlight device.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Attr {
    pub name: &'static str,
    pub mode: u16,
}

/// Every backlight device publishes the same attribute set: the class has no
/// per-device visibility filter, only per-attribute writability.
pub const ATTRS: &[Attr] = &[
    Attr { name: "bl_power",          mode: RW_MODE },
    Attr { name: "brightness",        mode: RW_MODE },
    Attr { name: "actual_brightness", mode: RO_MODE },
    Attr { name: "max_brightness",    mode: RO_MODE },
    Attr { name: "scale",             mode: RO_MODE },
    Attr { name: "type",              mode: RO_MODE },
];

/// Resolve an attribute by file name. # C: O(N_attrs)
pub fn attr(name: &str) -> Option<&'static Attr> { ATTRS.iter().find(|a| a.name == name) }

/// Render `value` the way a sysfs integer attribute does. # C: O(1)
fn int_body(value: i32) -> Vec<u8> {
    let mut body = String::new();
    let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{value}\n"));
    body.into_bytes()
}

/// Render `text` the way a sysfs string attribute does. # C: O(n)
fn text_body(text: &str) -> Vec<u8> {
    let mut body = String::from(text);
    body.push('\n');
    body.into_bytes()
}

/// Attribute `show`. # C: O(driver)
pub fn show(dev: &Arc<BacklightDevice>, name: &str) -> KResult<Vec<u8>> {
    let props = dev.props();
    match name {
        "bl_power" => Ok(int_body(props.power)),
        "brightness" => Ok(int_body(props.brightness)),
        "actual_brightness" => Ok(int_body(dev.actual_brightness()?)),
        "max_brightness" => Ok(int_body(props.max_brightness)),
        "scale" => Ok(text_body(props.scale.text())),
        "type" => Ok(text_body(props.ty.text())),
        _ => Err(VfsError::Enoent),
    }
}

/// Map a conversion failure onto the errno the store reports. # C: O(1)
fn parse_errno(err: ParseError) -> VfsError {
    match err { ParseError::Inval => VfsError::Einval, ParseError::Range => VfsError::Erange }
}

/// Attribute `store`. A `brightness` write always produces a change
/// notification, including when the driver refused it: a consumer's cached
/// level is stale in both cases. # C: O(driver)
pub fn store(dev: &Arc<BacklightDevice>, name: &str, buf: &[u8]) -> KResult<usize> {
    match name {
        "brightness" => {
            let result = kstrtoul(buf, BASE_AUTO)
                .map_err(parse_errno)
                .and_then(|level| dev.set_brightness(level));
            registry::changed(dev, UpdateReason::Sysfs);
            result.map(|()| buf.len())
        }
        "bl_power" => {
            let power = kstrtoint(buf, BASE_AUTO).map_err(parse_errno)?;
            dev.set_power(power).map(|()| buf.len())
        }
        _ if attr(name).is_some() => Err(VfsError::Eacces),
        _ => Err(VfsError::Enoent),
    }
}

/// `uevent` body / hotplug environment for one backlight device. # C: O(driver)
pub fn uevent_env(dev: &Arc<BacklightDevice>) -> Vec<String> {
    let props = dev.props();
    let actual = dev.actual_brightness().unwrap_or(props.brightness);
    let mut env = Vec::with_capacity(4);
    let mut push = |body: core::fmt::Arguments| {
        let mut line = String::new();
        let _ = core::fmt::Write::write_fmt(&mut line, body);
        env.push(line);
    };
    push(format_args!("BACKLIGHT_TYPE={}", props.ty.text()));
    push(format_args!("BRIGHTNESS={}", props.brightness));
    push(format_args!("ACTUAL_BRIGHTNESS={actual}"));
    push(format_args!("MAX_BRIGHTNESS={}", props.max_brightness));
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{BacklightOps, Properties};
    use crate::uapi::{BacklightScale, BacklightType, BACKLIGHT_POWER_OFF, BACKLIGHT_POWER_ON};

    struct Panel;
    impl BacklightOps for Panel {
        fn update_status(&self, _props: &Properties) -> KResult<()> { Ok(()) }
    }

    const MAX: i32 = 15;

    fn device() -> Arc<BacklightDevice> {
        Arc::new(BacklightDevice::new(
            String::from("acpi_video0"),
            Properties {
                brightness: 5,
                max_brightness: MAX,
                power: BACKLIGHT_POWER_ON,
                ty: BacklightType::Firmware,
                state: 0,
                scale: BacklightScale::NonLinear,
            },
            Arc::new(Panel),
        ))
    }

    #[test]
    fn the_attribute_set_and_its_modes_are_the_published_abi() {
        let names: Vec<&str> = ATTRS.iter().map(|a| a.name).collect();
        assert_eq!(names, alloc::vec![
            "bl_power", "brightness", "actual_brightness", "max_brightness", "scale", "type",
        ]);
        assert_eq!(attr("brightness").map(|a| a.mode), Some(RW_MODE));
        assert_eq!(attr("bl_power").map(|a| a.mode), Some(RW_MODE));
        assert_eq!(attr("actual_brightness").map(|a| a.mode), Some(RO_MODE));
        assert_eq!(attr("max_brightness").map(|a| a.mode), Some(RO_MODE));
        assert_eq!(attr("scale").map(|a| a.mode), Some(RO_MODE));
        assert_eq!(attr("type").map(|a| a.mode), Some(RO_MODE));
        assert!(attr("nonexistent").is_none());
    }

    #[test]
    fn every_attribute_renders_a_newline_terminated_body() {
        let dev = device();
        assert_eq!(show(&dev, "bl_power"), Ok(b"0\n".to_vec()));
        assert_eq!(show(&dev, "brightness"), Ok(b"5\n".to_vec()));
        assert_eq!(show(&dev, "actual_brightness"), Ok(b"5\n".to_vec()));
        assert_eq!(show(&dev, "max_brightness"), Ok(b"15\n".to_vec()));
        assert_eq!(show(&dev, "scale"), Ok(b"non-linear\n".to_vec()));
        assert_eq!(show(&dev, "type"), Ok(b"firmware\n".to_vec()));
        assert_eq!(show(&dev, "nope"), Err(VfsError::Enoent));
    }

    #[test]
    fn a_brightness_write_accepts_the_shell_forms_userspace_sends() {
        let dev = device();
        assert_eq!(store(&dev, "brightness", b"7\n"), Ok(2));
        assert_eq!(dev.props().brightness, 7);
        assert_eq!(store(&dev, "brightness", b"0xa"), Ok(3));
        assert_eq!(dev.props().brightness, 10);
        assert_eq!(store(&dev, "brightness", b"junk"), Err(VfsError::Einval));
        assert_eq!(dev.props().brightness, 10, "a rejected write must not move the level");
    }

    #[test]
    fn a_brightness_write_past_max_is_einval() {
        let dev = device();
        assert_eq!(store(&dev, "brightness", b"16\n"), Err(VfsError::Einval));
        assert_eq!(store(&dev, "brightness", b"15\n"), Ok(3));
        assert_eq!(dev.props().brightness, MAX);
    }

    #[test]
    fn a_read_only_attribute_refuses_a_write_without_claiming_it_is_missing() {
        let dev = device();
        assert_eq!(store(&dev, "max_brightness", b"1"), Err(VfsError::Eacces));
        assert_eq!(store(&dev, "actual_brightness", b"1"), Err(VfsError::Eacces));
        assert_eq!(store(&dev, "type", b"raw"), Err(VfsError::Eacces));
        assert_eq!(store(&dev, "absent", b"1"), Err(VfsError::Enoent));
    }

    #[test]
    fn a_power_write_blanks_the_panel_and_shows_the_new_state() {
        let dev = device();
        assert_eq!(store(&dev, "bl_power", b"4\n"), Ok(2));
        assert_eq!(show(&dev, "bl_power"), Ok(b"4\n".to_vec()));
        assert_eq!(dev.effective_brightness(), 0);
        assert_eq!(show(&dev, "brightness"), Ok(b"5\n".to_vec()),
                   "blanking must not lose the requested level");
        assert_eq!(dev.props().power, BACKLIGHT_POWER_OFF);
    }

    #[test]
    fn an_overflowing_write_is_erange() {
        let dev = device();
        assert_eq!(store(&dev, "brightness", b"99999999999999999999999"), Err(VfsError::Erange));
    }

    #[test]
    fn the_uevent_environment_carries_the_type_and_the_levels() {
        let dev = device();
        assert_eq!(uevent_env(&dev), alloc::vec![
            String::from("BACKLIGHT_TYPE=firmware"),
            String::from("BRIGHTNESS=5"),
            String::from("ACTUAL_BRIGHTNESS=5"),
            String::from("MAX_BRIGHTNESS=15"),
        ]);
    }
}
