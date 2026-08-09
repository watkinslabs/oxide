// `kexec_file_load`'s ladder, and the one test that owns the global slots.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

use super::fake::{FakeFrames, PatternSource};
use crate::file_load::{kexec_file_load, probe, FileImage};
use crate::stage::Limits;
use crate::store;
use crate::uapi::*;
use crate::validate::Error;

fn img(cmdline: &[u8]) -> FileImage {
    FileImage { kernel: vec![0x7f, b'E', b'L', b'F'], initrd: Vec::new(), cmdline: cmdline.to_vec() }
}

#[test]
fn no_loader_recognises_a_kernel_file_yet_and_that_answer_is_enoexec() {
    // The reference returns ENOEXEC when no registered loader probes a file
    // successfully. With the loader list empty that is every file — the errno
    // is right today and stays right when the first loader lands.
    assert_eq!(probe(b"\x7fELF").err(), Some(Error::NoExec));
    assert_eq!(probe(b"MZ").err(), Some(Error::NoExec));
    assert_eq!(probe(&[]).err(), Some(Error::NoExec));
}

#[test]
fn the_unload_flag_short_circuits_before_a_descriptor_is_read() {
    // KEXEC_FILE_UNLOAD ignores both fds. Reading them first would make an
    // unload fail on a closed descriptor that the reference never looks at.
    let read_ran = Cell::new(false);
    let mut f = FakeFrames::new(0x80_0000);
    let r = kexec_file_load(&mut f, KEXEC_FILE_UNLOAD, || {
        read_ran.set(true);
        Ok(img(b"\0"))
    });
    assert_eq!(r, Ok(()));
    assert!(!read_ran.get(), "the unload never reads the descriptors");
}

#[test]
fn a_descriptor_error_is_reported_before_the_command_line_is_judged() {
    let mut f = FakeFrames::new(0x80_0000);
    assert_eq!(kexec_file_load(&mut f, 0, || Err(Error::BadFd)), Err(Error::BadFd));
}

#[test]
fn a_command_line_without_its_nul_is_refused_before_the_loader_probe() {
    // EINVAL, not ENOEXEC: the caller's mistake is the command line, and it is
    // decided first — the reference checks the last byte right after the copy.
    let mut f = FakeFrames::new(0x80_0000);
    assert_eq!(kexec_file_load(&mut f, 0, || Ok(img(b"ro quiet"))), Err(Error::Inval));
    assert_eq!(kexec_file_load(&mut f, 0, || Ok(img(b"ro quiet\0"))), Err(Error::NoExec));
    // An empty command line is legal and reaches the probe.
    assert_eq!(kexec_file_load(&mut f, 0, || Ok(img(b""))), Err(Error::NoExec));
}

/// One test owns the process-wide slots and the kexec lock, because they are
/// global: split across parallel test functions these assertions would race
/// each other and flake.
#[test]
fn the_slots_the_lock_and_the_reboot_entry_behave_as_one_state_machine() {
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(PAGE_SIZE as usize);
    let seg = KexecSegment { buf: 0, bufsz: PAGE_SIZE, mem: 0x20_0000, memsz: PAGE_SIZE };

    // Nothing loaded: reboot's KEXEC command is EINVAL, which is why
    // `systemctl kexec` falls back to an ordinary reboot.
    assert!(!store::kexec_loaded());
    assert_eq!(store::kernel_kexec(), Err(Error::Inval));

    // An unload with nothing loaded succeeds — it is not an error to ask for a
    // state the machine is already in.
    assert_eq!(store::do_kexec_load(&mut f, 0, Vec::new(), 0, Limits::default(), &src), Ok(()));

    // Load, and the slot reports itself loaded.
    assert_eq!(store::do_kexec_load(&mut f, 0x20_0000, vec![seg], 0, Limits::default(), &src), Ok(()));
    assert!(store::kexec_loaded());
    assert!(!store::kexec_crash_loaded());
    let staged = f.live_count();
    assert!(staged > 0, "the loaded image owns pages");

    // Reloading replaces the image and frees the old one — the page count does
    // not grow, which is how a repeated `kexec -l` avoids leaking memory.
    assert_eq!(store::do_kexec_load(&mut f, 0x20_0000, vec![seg], 0, Limits::default(), &src), Ok(()));
    assert_eq!(f.live_count(), staged);

    // The machine step refuses; the lock is released so a later call is not
    // EBUSY. A refusal that leaked the lock would wedge every later load.
    assert_eq!(store::kernel_kexec(), Err(Error::NoSys));
    assert_eq!(store::kernel_kexec(), Err(Error::NoSys));

    // A caller that finds the lock held gets EBUSY rather than blocking behind
    // a kexec that may never come back.
    let nested = store::with_kexec_lock(|| store::with_kexec_lock(|| Ok(())));
    assert_eq!(nested, Err(Error::Busy));
    // The failed inner attempt did not clear the outer holder's lock.
    assert_eq!(store::with_kexec_lock(|| Ok(())), Ok(()));

    // Zero segments unloads, and every page comes back.
    assert_eq!(store::do_kexec_load(&mut f, 0, Vec::new(), 0, Limits::default(), &src), Ok(()));
    assert!(!store::kexec_loaded());
    assert_eq!(f.live_count(), 0);
    assert_eq!(store::kernel_kexec(), Err(Error::Inval));

    // The load-disable latch is one-way and is what `load_permitted` consults.
    assert!(store::load_permitted(true));
    assert!(!store::load_permitted(false));
    store::disable_load();
    assert!(!store::load_permitted(true), "no capability survives kexec_load_disabled");
}
