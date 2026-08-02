// Hosted coverage for core dumps. Module manifest:
//   expansion  the `%` specifier table and its escaping
//   destination  file path vs program argument vector
//   selection  which mappings the dump contains, and how much of each
//   walk       a live VMA tree through that ladder, and the image it produces
//   gregset    the register and floating-point blocks a thread's notes carry

mod expansion;
mod destination;
mod selection;
mod walk;
mod gregset;

use super::pattern::CoreContext;
use alloc::vec::Vec;

/// A dying process to expand a pattern against.
pub(crate) fn victim() -> CoreContext {
    CoreContext {
        signo: 11,
        vpid: 42, gpid: 4242,
        vtid: 43, gtid: 4243,
        uid: 1000, gid: 100,
        dumpable: 1,
        time_secs: 1_700_000_000,
        hostname: b"oxide".to_vec(),
        comm: b"bash".to_vec(),
        exe: b"/usr/bin/bash".to_vec(),
        rlimit_core: 0xFFFF_FFFF_FFFF_FFFF,
        cpu: 3,
    }
}

pub(crate) fn text(v: &[u8]) -> Vec<u8> { v.to_vec() }
