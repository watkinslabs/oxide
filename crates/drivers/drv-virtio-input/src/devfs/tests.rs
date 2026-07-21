use alloc::{string::String, sync::Arc};

use vfs::{Dentry, File, OpenFlags, VfsError, POLL_IN};

use crate::devfs::{handle_evdev_ioctl, make_evdev_inode, register_node, unregister_node};
use crate::devfs::shared::EVDEV_DEVICES;
use crate::evdev_queue::MAX_EVDEV;

fn test_file(id: u32) -> Arc<File> {
    let inode = make_evdev_inode(id);
    File::new(
        inode.clone(),
        Dentry::new_anon(inode),
        OpenFlags::O_RDONLY | OpenFlags::O_NONBLOCK,
    )
}

fn test_dev(id: u32) -> crate::VirtioInputDev {
    crate::VirtioInputDev {
        device_key: virtio::VirtioChildDeviceKey::from_raw(0x7000_0000 + id),
        evdev_id: id,
        is_pointer: false,
        name: [0; 128],
        name_len: 0,
        serial: [0; 128],
        serial_len: 0,
        ids: crate::VirtioInputDevIds::default(),
        ev_bits: [0; 32],
        key_bits: crate::CapBitmap::default(),
        rel_bits: crate::CapBitmap::default(),
        abs_bits: crate::CapBitmap::default(),
        led_bits: crate::CapBitmap::default(),
        abs_info: [None; 64],
        prop_bits: [0; 4],
        repeat: crate::DEFAULT_REPEAT,
    }
}

#[test]
fn register_node_is_idempotent_without_republishing() {
    let id = (MAX_EVDEV - 1) as u32;
    let _ = unregister_node(id);

    assert!(register_node(id, None));
    assert!(!register_node(id, None));
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|d| d.bus == "input" && d.addr == alloc::format!("event{id}"))
            .count(),
        1
    );

    assert!(unregister_node(id));
}

#[test]
fn evdev_inode_reports_linux_input_dev_t() {
    let id = 7;
    let inode = make_evdev_inode(id);
    assert_eq!(
        inode.rdev(),
        vfs::Devt::new(crate::INPUT_MAJOR, crate::EVENT_MINOR_BASE + id).raw(),
    );
}

#[test]
fn register_node_records_model_parent() {
    let id = (MAX_EVDEV - 4) as u32;
    let addr = alloc::format!("event{id}");
    let parent_addr = String::from("virtio-input-parent0");
    let _ = unregister_node(id);

    assert!(register_node(id, Some(("virtio", parent_addr.clone()))));
    let dev = drv::devices()
        .into_iter()
        .find(|d| d.bus == "input" && d.addr == addr)
        .expect("registered input event device");
    assert_eq!(dev.parent(), Some(("virtio", parent_addr.as_str())));

    assert!(unregister_node(id));
}

#[test]
fn unregister_then_register_restores_model_owned_event_node() {
    let id = (MAX_EVDEV - 3) as u32;
    let addr = alloc::format!("event{id}");
    let _ = unregister_node(id);

    assert!(register_node(id, None));
    assert!(EVDEV_DEVICES.lock()[id as usize].is_some());
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|d| d.bus == "input" && d.addr == addr)
            .count(),
        1
    );
    assert!(unregister_node(id));
    assert!(EVDEV_DEVICES.lock()[id as usize].is_none());
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|d| d.bus == "input" && d.addr == addr)
            .count(),
        0
    );

    assert!(register_node(id, None));
    assert!(EVDEV_DEVICES.lock()[id as usize].is_some());
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|d| d.bus == "input" && d.addr == addr)
            .count(),
        1
    );
    assert!(unregister_node(id));
}

#[test]
fn register_node_leaves_slot_free_when_model_publication_conflicts() {
    let id = (MAX_EVDEV - 2) as u32;
    let _ = unregister_node(id);
    let addr = alloc::format!("event{id}");
    let conflict = drv::try_device_add(Arc::new(
        drv::Device::new("input", String::from(addr.as_str()), 0, 0, id)
            .with_devnode("input", alloc::format!("input/event{id}"), Some((13, 64 + id))),
    ))
    .expect("conflict device registration");

    assert!(!register_node(id, None));
    assert!(EVDEV_DEVICES.lock()[id as usize].is_none());
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|d| d.bus == "input" && d.addr == addr)
            .count(),
        1
    );

    drv::device_del(&conflict);
    assert!(register_node(id, None));
    assert!(unregister_node(id));
}

#[test]
fn evdev_clockid_ioctl_accepts_only_monotonic_clock() {
    let file = test_file(0);
    let mut monotonic = crate::EVDEV_CLOCK_MONOTONIC;
    let mut realtime = 0i32;
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSCLOCKID, (&mut monotonic as *mut i32) as u64),
        Some(0)
    );
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSCLOCKID, (&mut realtime as *mut i32) as u64),
        Some(-(syscall::errno::Errno::Einval.as_i32() as i64))
    );
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSCLOCKID, 0),
        Some(-(syscall::errno::Errno::Efault.as_i32() as i64))
    );
}

#[test]
fn evdev_repeat_ioctl_round_trips_real_device_state() {
    let id = 4;
    let key = virtio::VirtioChildDeviceKey::from_raw(0x7000_0000 + id);
    let _ = crate::remove_device(key);
    crate::install(test_dev(id));
    let file = test_file(id);
    let mut repeat = [300u32, 45u32];

    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSREP, repeat.as_mut_ptr() as u64),
        Some(0)
    );
    repeat = [0, 0];
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCGREP, repeat.as_mut_ptr() as u64),
        Some(8)
    );
    assert_eq!(repeat, [300, 45]);
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSREP, 0),
        Some(-(syscall::errno::Errno::Efault.as_i32() as i64))
    );

    assert_eq!(crate::remove_device(key), Some(id));
}

#[test]
fn evdev_force_feedback_ioctl_is_not_absinfo_alias() {
    let file = test_file(0);
    let mut effect = [0u8; crate::EVDEV_FF_EFFECT_BYTES];
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSFF, effect.as_mut_ptr() as u64),
        Some(-(syscall::errno::Errno::Enotty.as_i32() as i64))
    );
}

#[test]
fn evdev_grab_is_per_open_file_description() {
    let owner = test_file(1);
    let other = test_file(1);

    assert_eq!(handle_evdev_ioctl(&owner, crate::EVIOCGRAB, 1), Some(0));
    assert_eq!(
        handle_evdev_ioctl(&other, crate::EVIOCGRAB, 1),
        Some(-(syscall::errno::Errno::Ebusy.as_i32() as i64))
    );

    crate::evdev_queue::push_event(1, crate::EV_KEY, 30, 1);
    assert_eq!(owner.poll() & POLL_IN, POLL_IN);
    assert_eq!(other.poll() & POLL_IN, 0);

    let mut buf = [0u8; crate::evdev_queue::INPUT_EVENT_BYTES];
    assert_eq!(other.read(&mut buf).err(), Some(VfsError::Eagain));
    assert_eq!(owner.read(&mut buf).unwrap(), buf.len());

    assert_eq!(handle_evdev_ioctl(&owner, crate::EVIOCGRAB, 0), Some(0));
    assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 1), Some(0));
    assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 0), Some(0));
}

#[test]
fn evdev_grab_is_released_on_last_close() {
    let owner = test_file(2);
    let other = test_file(2);
    assert_eq!(handle_evdev_ioctl(&owner, crate::EVIOCGRAB, 1), Some(0));
    drop(owner);
    assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 1), Some(0));
    assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 0), Some(0));
}

#[test]
fn evdev_revoke_disables_current_open_file() {
    let file = test_file(3);
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCREVOKE, 1), Some(0));
    assert_eq!(file.poll() & vfs::POLL_HUP, vfs::POLL_HUP);
    let mut buf = [0u8; crate::evdev_queue::INPUT_EVENT_BYTES];
    assert_eq!(file.read(&mut buf).err(), Some(VfsError::Enodev));
}
