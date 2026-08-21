//! Hibernation-owned `/sys/power` attribute behavior.

use alloc::vec::Vec;

use crate::decide::{Error, KResult};
use crate::suspend::attrs;
use super::{entry, mode, settings};

fn modes() -> mode::Available {
    mode::Available { platform: false, shutdown: true, reboot: true,
        suspend: true, test_resume: true }
}

/// Append the hibernation state only when a restorable image is supported.
/// # C: O(1)
pub fn append_state(mut state: alloc::string::String) -> alloc::string::String {
    if !entry::available() { return state; }
    if state.pop().is_some() { state.push(' '); }
    state.push_str("disk\n");
    state
}

/// Read one hibernation-owned attribute. # C: O(target bytes)
pub fn show(attr: &str) -> Option<KResult<Vec<u8>>> {
    let value = match attr {
        "disk" => if entry::available() { mode::render(modes()) }
                  else { alloc::string::String::from("[disabled]\n") },
        "resume" => settings::get().map(|s| attrs::render_str(s.resume_name()))
            .unwrap_or_else(|| attrs::render_str("")),
        "resume_offset" => attrs::render_u64(settings::get()
            .map(|s| s.resume_offset()).unwrap_or(0)),
        "image_size" => attrs::render_u64(settings::get()
            .map(|s| s.image_size()).unwrap_or(0)),
        "reserved_size" => attrs::render_u64(settings::get()
            .map(|s| s.reserved_size()).unwrap_or(0)),
        _ => return None,
    };
    Some(Ok(attrs::bytes(value)))
}

/// Write one hibernation-owned attribute. # C: O(target bytes)
pub fn store(attr: &str, buf: &[u8]) -> Option<KResult<()>> {
    Some(match attr {
        "disk" => {
            if !entry::available() { Err(Error::Perm) }
            else { with_config_claim(|| mode::select(buf, modes())) }
        }
        // A disabled cold path accepts this write without activating or
        // changing a target; activation becomes part of the restore owner.
        "resume" if !entry::available() => Ok(()),
        "resume" => match with_config_claim(|| settings::set_resume(buf)) {
            Ok(()) => entry::software_resume(), Err(error) => Err(error),
        },
        "resume_offset" => with_config_claim(|| settings::set_resume_offset(buf)),
        "image_size" => with_config_claim(|| settings::set_image_size(buf)),
        "reserved_size" => with_config_claim(|| settings::set_reserved_size(buf)),
        _ => return None,
    })
}

fn with_config_claim(f: impl FnOnce() -> KResult<()>) -> KResult<()> {
    let _claim = crate::transition::try_claim().ok_or(Error::Busy)?;
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> KResult<()> { Ok(()) }
    fn resume() {}

    #[test]
    fn incomplete_restore_path_is_not_advertised() {
        let _g = crate::suspend::test_lock();
        settings::init(100);
        entry::set_machine_hooks(None);
        assert_eq!(append_state(alloc::string::String::from("freeze mem\n")), "freeze mem\n");
        assert_eq!(show("disk").unwrap().unwrap(), b"[disabled]\n".to_vec());
        assert_eq!(store("disk", b"shutdown\n"), Some(Err(Error::Perm)));
    }

    #[test]
    fn numeric_tunables_use_the_canonical_settings() {
        let _g = crate::suspend::test_lock();
        settings::init(0);
        store("resume_offset", b"29\n").unwrap().unwrap();
        store("image_size", b"8192\n").unwrap().unwrap();
        store("reserved_size", b"4096\n").unwrap().unwrap();
        assert_eq!(show("resume_offset").unwrap().unwrap(), b"29\n".to_vec());
        assert_eq!(show("image_size").unwrap().unwrap(), b"8192\n".to_vec());
        assert_eq!(show("reserved_size").unwrap().unwrap(), b"4096\n".to_vec());
    }

    #[test]
    fn installed_machine_hook_makes_disk_state_and_modes_reachable() {
        let _g = crate::suspend::test_lock();
        settings::init(0);
        entry::set_machine_hooks(Some(entry::MachineHooks::new(machine, resume)));
        assert!(entry::available());
        assert_eq!(append_state(alloc::string::String::from("freeze mem\n")),
            "freeze mem disk\n");
        assert_eq!(show("disk").unwrap().unwrap(),
            b"[shutdown] reboot suspend test_resume\n".to_vec());
        entry::set_machine_hooks(None);
    }

    #[test]
    fn transition_contention_refuses_every_mutation_before_parsing_or_store() {
        let _g = crate::suspend::test_lock();
        settings::init(0);
        entry::set_machine_hooks(Some(entry::MachineHooks::new(machine, resume)));
        mode::select(b"shutdown", modes()).unwrap();
        settings::set_resume(b"/dev/vda2").unwrap();
        settings::set_resume_offset(b"29").unwrap();
        settings::set_image_size(b"8192").unwrap();
        settings::set_reserved_size(b"4096").unwrap();
        let before = settings::get().unwrap();
        let claim = crate::transition::try_claim().expect("positive control owns transition");
        for (attr, value) in [("disk", b"reboot".as_slice()),
            ("resume", b"/dev/vda3"), ("resume_offset", b"30"),
            ("image_size", b"16384"), ("reserved_size", b"8192")]
        {
            assert_eq!(store(attr, value), Some(Err(Error::Busy)), "{attr}");
        }
        assert_eq!(mode::selected(), mode::Mode::Shutdown);
        assert_eq!(settings::get(), Some(before));
        drop(claim);
        entry::set_machine_hooks(None);
    }
}
