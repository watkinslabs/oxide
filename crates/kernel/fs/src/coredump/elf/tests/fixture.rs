// A crashed process to build images from.

use alloc::vec::Vec;

use crate::coredump::elf::build::CORE_PAGE_SIZE;
use crate::coredump::elf::input::{
    CoreIdentity, CoreSegFile, CoreSegment, CoreState, CoreThread, CoreTimeval, CoreTimes,
    SEG_EXEC, SEG_READ, SEG_WRITE,
};
use crate::coredump::elf::layout::CoreArch;

pub const COMM: &[u8] = b"gnome-shell";
pub const PSARGS: &[u8] = b"gnome-shell\0--mode\0user\0";
pub const SIGSEGV: i32 = 11;
pub const PID: i32 = 1234;
pub const PPID: i32 = 1;
pub const PGRP: i32 = 1200;
pub const SID: i32 = 1100;
pub const UID: u32 = 1000;
pub const GID: u32 = 1000;
pub const TID_MAIN: i32 = 1234;
pub const TID_WORKER: i32 = 1237;

/// A register block whose every byte is distinguishable, so a misplaced copy
/// shows up as a value rather than as a zero.
pub fn regs(arch: CoreArch, seed: u8) -> Vec<u8> {
    (0..arch.gregset_bytes()).map(|i| (i as u8).wrapping_mul(3).wrapping_add(seed)).collect()
}

/// A floating-point block with the same property.
pub fn fpregs(arch: CoreArch, seed: u8) -> Vec<u8> {
    (0..arch.fpregset_bytes()).map(|i| (i as u8).wrapping_mul(5).wrapping_add(seed)).collect()
}

/// An auxiliary vector terminated the way the loader leaves it.
pub fn auxv() -> Vec<u8> {
    let pairs: [u64; 6] = [3, 0x400040, 6, CORE_PAGE_SIZE, 0, 0];
    let mut v = Vec::new();
    for w in pairs.iter() { v.extend_from_slice(&w.to_le_bytes()) }
    v
}

/// The signal descriptor `NT_SIGINFO` carries.
pub fn siginfo() -> Vec<u8> {
    let mut v = alloc::vec![0u8; crate::coredump::elf::uapi::SIGINFO_NOTE_BYTES];
    v[0] = SIGSEGV as u8;
    v
}

pub fn identity() -> CoreIdentity<'static> {
    CoreIdentity {
        pid: PID, ppid: PPID, pgrp: PGRP, sid: SID,
        uid: UID, gid: GID,
        signo: SIGSEGV,
        sigpend: 0x0000_0000_0000_0800,
        sighold: 0x0000_0000_0001_0000,
        state: CoreState::Running,
        nice: -5,
        flag: 0x0040_0100,
        comm: COMM,
        psargs: PSARGS,
        times: CoreTimes {
            utime:  CoreTimeval { sec: 12, usec: 345_678 },
            stime:  CoreTimeval { sec: 3,  usec: 111_222 },
            cutime: CoreTimeval { sec: 1,  usec: 2 },
            cstime: CoreTimeval { sec: 4,  usec: 5 },
        },
    }
}

pub fn thread<'a>(tid: i32, regs: &'a [u8], fp: Option<&'a [u8]>) -> CoreThread<'a> {
    let times = if tid == TID_MAIN {
        CoreTimes { utime: CoreTimeval { sec: 12, usec: 345_678 }, stime: CoreTimeval { sec: 3, usec: 111_222 }, ..CoreTimes::default() }
    } else {
        CoreTimes { utime: CoreTimeval { sec: 7, usec: 8 }, stime: CoreTimeval { sec: 9, usec: 10 }, ..CoreTimes::default() }
    };
    CoreThread { tid, regs, fpregs: fp, xstate: None, times }
}

pub const TEXT_START: u64 = 0x0040_0000;
pub const DATA_START: u64 = 0x0060_0000;
pub const STACK_START: u64 = 0x7fff_ffff_e000;

pub const LIBC_PATH: &[u8] = b"/usr/lib64/libc.so.6";
pub const EXE_PATH: &[u8] = b"/usr/bin/gnome-shell";

/// Three mappings of the shape a crash actually presents: a file-backed text
/// mapping whose contents are elided, a file-backed data mapping that is
/// dumped, and an anonymous stack.
pub fn segments() -> [CoreSegment<'static>; 3] {
    [
        CoreSegment {
            start: TEXT_START, end: TEXT_START + 2 * CORE_PAGE_SIZE,
            prot: SEG_READ | SEG_EXEC, dump_size: 0,
            file: Some(CoreSegFile { path: EXE_PATH, pgoff_pages: 0 }),
        },
        CoreSegment {
            start: DATA_START, end: DATA_START + CORE_PAGE_SIZE,
            prot: SEG_READ | SEG_WRITE, dump_size: CORE_PAGE_SIZE,
            file: Some(CoreSegFile { path: LIBC_PATH, pgoff_pages: 7 }),
        },
        CoreSegment {
            start: STACK_START, end: STACK_START + 2 * CORE_PAGE_SIZE,
            prot: SEG_READ | SEG_WRITE, dump_size: 2 * CORE_PAGE_SIZE,
            file: None,
        },
    ]
}

/// Synthetic memory: byte at `va` is a function of `va`, so a segment written
/// from the wrong address is detectable.
pub fn byte_at(va: u64) -> u8 { (va >> 4) as u8 ^ (va as u8) }

/// The image a two-threaded crash of the fixture process produces.
pub fn image(arch: CoreArch) -> Vec<u8> {
    let r0 = regs(arch, 0x11);
    let r1 = regs(arch, 0x77);
    let fp0 = fpregs(arch, 0x22);
    let threads = [thread(TID_MAIN, &r0, Some(&fp0)), thread(TID_WORKER, &r1, None)];
    let segs = segments();
    let av = auxv();
    let si = siginfo();
    let input = crate::coredump::elf::input::CoreImageInput {
        arch, identity: identity(), threads: &threads, segments: &segs,
        auxv: &av, siginfo: Some(&si),
    };
    let mut mem = full_reader();
    crate::coredump::elf::build::build_core_image(&input, &mut mem).expect("image builds")
}

/// A reader that produces every requested byte.
pub fn full_reader() -> impl FnMut(u64, &mut [u8]) -> usize {
    |va: u64, buf: &mut [u8]| {
        for (i, b) in buf.iter_mut().enumerate() { *b = byte_at(va + i as u64) }
        buf.len()
    }
}

/// A reader that refuses everything at or above `hole_at`, standing in for a
/// mapping whose pages are not resident.
pub fn holed_reader(hole_at: u64) -> impl FnMut(u64, &mut [u8]) -> usize {
    move |va: u64, buf: &mut [u8]| {
        if va >= hole_at { return 0 }
        for (i, b) in buf.iter_mut().enumerate() { *b = byte_at(va + i as u64) }
        buf.len()
    }
}
