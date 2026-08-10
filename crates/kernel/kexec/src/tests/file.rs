// `kexec_file_load`'s ladder, and the one test that owns the global slots.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

use super::fake::{FakeFrames, PatternSource};
use super::gate::exclusive_store;
use crate::file_load::{kexec_file_load, probe, FileImage};
use crate::stage::Limits;
use crate::store;
use crate::limit::UNLIMITED;
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
    // This case UNLOADS the global slot, so without the gate it can free an
    // image a concurrent case just staged — and it takes the kexec lock, so a
    // concurrent holder makes it EBUSY. Both are real behaviour; neither is
    // what this case is asking about.
    let _g = exclusive_store(&mut f);
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
    let _g = exclusive_store(&mut f);
    assert_eq!(kexec_file_load(&mut f, 0, || Err(Error::BadFd)), Err(Error::BadFd));
}

#[test]
fn a_command_line_without_its_nul_is_refused_before_the_loader_probe() {
    // EINVAL, not ENOEXEC: the caller's mistake is the command line, and it is
    // decided first — the reference checks the last byte right after the copy.
    let mut f = FakeFrames::new(0x80_0000);
    let _g = exclusive_store(&mut f);
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
    let _g = exclusive_store(&mut f);
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
    // a kexec that may never come back. Asserted by nesting the lock EXPLICITLY
    // rather than by racing another test thread: the contract is "held means
    // refused", and a deterministic nest proves that, while a thread race only
    // proves the harness scheduled two cases at once.
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
    assert!(store::load_permitted(true, ImageType::Default));
    assert!(!store::load_permitted(false, ImageType::Default));

    // The two load limits are per image type and are spent independently: a
    // reboot image must not be able to exhaust the panic budget or vice versa.
    // Both are unlimited to begin with, so neither has moved above.
    assert_eq!(store::load_limit(ImageType::Default), UNLIMITED);
    assert_eq!(store::load_limit(ImageType::Crash), UNLIMITED);
    assert!(store::set_load_limit(ImageType::Default, 1));
    assert!(!store::set_load_limit(ImageType::Default, 2), "a limit may only tighten");
    assert!(store::load_permitted(true, ImageType::Default));
    assert_eq!(store::load_limit(ImageType::Default), 0);
    assert!(!store::load_permitted(true, ImageType::Default), "the budget is spent");
    // The crash counter was untouched by every one of those.
    assert_eq!(store::load_limit(ImageType::Crash), UNLIMITED);
    assert!(store::load_permitted(true, ImageType::Crash));

    store::disable_load();
    assert!(!store::load_permitted(true, ImageType::Crash),
            "no capability and no remaining budget survives kexec_load_disabled");
}
