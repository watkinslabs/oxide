use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{InodeRef, KResult, VfsError};

use super::model::{input_by_identity, InputDevInfo, InputIdentity, INO_INPUT_ATTR};
use crate::kobject::{Attribute, SysfsOps};
use crate::RW_PERM;

const INHIBITED_ATTR: Attribute = Attribute { name: "inhibited", mode: RW_PERM };

fn parse_kstrtobool(buf: &[u8]) -> Option<bool> {
    match buf.first().copied()? {
        b'e' | b'E' | b'y' | b'Y' | b't' | b'T' | b'1' => Some(true),
        b'd' | b'D' | b'n' | b'N' | b'f' | b'F' | b'0' => Some(false),
        b'o' | b'O' => match buf.get(1).copied()? {
            b'n' | b'N' => Some(true),
            b'f' | b'F' => Some(false),
            _ => None,
        },
        _ => None,
    }
}

struct InhibitedOps { identity: InputIdentity }

impl InhibitedOps {
    fn live_identity(&self) -> KResult<(input::VirtioChildDeviceKey, u32, u32)> {
        let info = input_by_identity(&self.identity).ok_or(VfsError::Enoent)?;
        Ok((info.model.device_key, info.model.input_id, info.model.evdev_id))
    }
}

impl SysfsOps for InhibitedOps {
    fn show(&self, _attr: &str) -> KResult<Vec<u8>> {
        let (key, input_id, evdev_id) = self.live_identity()?;
        let inhibited = input::inhibited_by_identity(key, input_id, evdev_id)
            .ok_or(VfsError::Enoent)?;
        Ok(if inhibited { b"1\n".to_vec() } else { b"0\n".to_vec() })
    }

    fn store(&self, _attr: &str, buf: &[u8]) -> KResult<usize> {
        let (key, input_id, evdev_id) = self.live_identity()?;
        let inhibited = parse_kstrtobool(buf).ok_or(VfsError::Einval)?;
        if input::set_inhibited_by_identity(key, input_id, evdev_id, inhibited).is_none() {
            return Err(VfsError::Enoent);
        }
        Ok(buf.len())
    }
}

pub(super) fn make_attr(info: &InputDevInfo) -> InodeRef {
    crate::kobject::make_attr_inode(
        &INHIBITED_ATTR,
        Arc::new(InhibitedOps { identity: info.identity() }),
        INO_INPUT_ATTR,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DEVICE_KEY_RAW: u32 = 0x7a00_0010;
    const ATTR_READ_BUFFER_BYTES: usize = 4;

    #[test]
    fn parser_matches_linux_kstrtobool_forms() {
        for value in [b"1".as_slice(), b"yes", b"true\n", b"enable", b"ON", b"onward"] {
            assert_eq!(parse_kstrtobool(value), Some(true), "{value:?}");
        }
        for value in [b"0".as_slice(), b"no", b"false\n", b"disable", b"OFF", b"offset"] {
            assert_eq!(parse_kstrtobool(value), Some(false), "{value:?}");
        }
        for value in [b"".as_slice(), b"2", b" o", b"o", b"okay", b"\n"] {
            assert_eq!(parse_kstrtobool(value), None, "{value:?}");
        }
    }

    #[test]
    fn input_parent_inhibited_is_live_rw_state() {
        let _serial = super::super::tests::INPUT_TEST_MUTEX.lock()
            .unwrap_or_else(|err| err.into_inner());
        input::clear_devices_for_tests();
        let key = input::VirtioChildDeviceKey::from_raw(TEST_DEVICE_KEY_RAW);
        let (input_id, evdev_id) =
            input::install(input::VirtioInputDev::empty(key)).expect("input model");
        let dev = Arc::new(
            drv::Device::new("input", alloc::format!("event{evdev_id}"), 0, 0, evdev_id)
                .with_sysfs_relpath(alloc::format!(
                    "input{input_id}/event{evdev_id}",
                ))
                .with_devnode(
                    "input",
                    alloc::format!("input/event{evdev_id}"),
                    Some((input::INPUT_MAJOR, input::EVENT_MINOR_BASE + evdev_id)),
                ),
        );
        drv::try_device_add(Arc::clone(&dev)).expect("input registration");
        let parent = super::super::device::make_input_parent_dir(
            alloc::format!("event{evdev_id}"),
        );
        let attr = parent.lookup("inhibited").expect("inhibited attr");
        let mut buf = [0u8; ATTR_READ_BUFFER_BYTES];

        assert_eq!(attr.perm(), Some(RW_PERM));
        assert_eq!(attr.read(0, &mut buf), Ok(2));
        assert_eq!(&buf[..2], b"0\n");
        assert_eq!(attr.write(0, b"enable\n"), Ok(7));
        assert_eq!(attr.write(0, b"true\n"), Ok(5), "idempotent inhibit");
        assert_eq!(attr.read(0, &mut buf), Ok(2));
        assert_eq!(&buf[..2], b"1\n");
        assert_eq!(attr.write(0, b"invalid\n"), Err(VfsError::Einval));
        assert_eq!(attr.read(0, &mut buf), Ok(2));
        assert_eq!(&buf[..2], b"1\n");
        assert_eq!(attr.write(0, b"OFF\n"), Ok(4));
        assert_eq!(attr.read(0, &mut buf), Ok(2));
        assert_eq!(&buf[..2], b"0\n");
        assert_eq!(
            input::inhibited_by_identity(key, input_id, evdev_id),
            Some(false),
        );

        drv::device_del(&dev);
        assert_eq!(input::remove_device(key), Some(evdev_id));
        input::clear_devices_for_tests();
    }
}
