use super::super::device::{power_wakeup_show, power_wakeup_store};
use alloc::string::String;
use vfs::VfsError;

fn device() -> drv::Device { drv::Device::new("platform", String::from("wake0"), 0, 0, 0) }

#[test]
fn incapable_devices_have_no_wakeup_attribute_value() {
    let dev = device();
    assert_eq!(power_wakeup_show(&dev), None);
    assert_eq!(power_wakeup_store(&dev, b"enabled\n"), Err(VfsError::Einval));
}

#[test]
fn wakeup_accepts_only_the_two_linux_policy_words() {
    let dev = device();
    dev.set_wakeup_capable(true);
    assert_eq!(power_wakeup_show(&dev), Some(b"disabled\n".to_vec()));
    assert_eq!(power_wakeup_store(&dev, b"enabled\n"), Ok(8));
    assert_eq!(power_wakeup_show(&dev), Some(b"enabled\n".to_vec()));
    assert_eq!(power_wakeup_store(&dev, b"disabled"), Ok(8));
    assert_eq!(power_wakeup_store(&dev, b"1\n"), Err(VfsError::Einval));
}
