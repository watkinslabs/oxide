//! F721 host-oracle differential conformance — misc family: nanosleep
//! invalid-timespec `EINVAL`, `clock_gettime`/`clock_nanosleep` invalid
//! clockid `EINVAL`, `pipe2` flag validation. `getrandom` flag validation is
//! documented as a code-reading finding, NOT a harness case — see the
//! `skip` reason on its row.
//!
//! `read_timespec` (`035_nanosleep.rs`) and `clock_id_known`
//! (`time_common.rs`) are pulled in verbatim via `#[path]` — both files
//! already carry `#[cfg(test)]` hosted stand-ins for their own
//! `validate_user_buf`/`monotonic_ns` collaborators (pre-existing, not added
//! by this lane), so no additional stubbing was needed. `pipe2`'s flag mask
//! is mirrored inline from the real `vfs::OpenFlags` bit constants
//! (`293_pipe2.rs`'s `VALID_FLAGS`/`O_NOTIFICATION_PIPE`), documented rather
//! than pulling the whole file (which needs a live `Task`+`FdTable` this
//! lane does not stand up for the misc family).

use conformance::corpus::{run_corpus, Case};
use conformance::oracle;
use conformance::outcome::Outcome;

#[path = "../../syscalls/src/035_nanosleep.rs"]
mod nanosleep_shim;

#[path = "../../syscalls/src/time_common.rs"]
mod time_common_shim;

fn nanosleep_negative_secs_einval() -> (Outcome, Outcome) {
    let req = libc::timespec { tv_sec: -1, tv_nsec: 0 };
    // SAFETY: req is a live, stack-owned timespec; rem ptr is null (not read back).
    let host = Outcome::from_host(unsafe { libc::nanosleep(&req, std::ptr::null_mut()) } as i64);

    let ts: [i64; 2] = [-1, 0];
    let ptr = ts.as_ptr() as u64;
    let oxide = Outcome::from_oxide_rv(nanosleep_shim::read_timespec(ptr).map(|_| 0).unwrap_or_else(|e| e));
    (host, oxide)
}

fn nanosleep_nsec_too_large_einval() -> (Outcome, Outcome) {
    let req = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
    // SAFETY: req is a live, stack-owned timespec; rem ptr is null (not read back).
    let host = Outcome::from_host(unsafe { libc::nanosleep(&req, std::ptr::null_mut()) } as i64);

    let ts: [i64; 2] = [0, 1_000_000_000];
    let ptr = ts.as_ptr() as u64;
    let oxide = Outcome::from_oxide_rv(nanosleep_shim::read_timespec(ptr).map(|_| 0).unwrap_or_else(|e| e));
    (host, oxide)
}

fn nanosleep_zero_ok() -> (Outcome, Outcome) {
    let host = oracle::nanosleep_zero();
    let ts: [i64; 2] = [0, 0];
    let ptr = ts.as_ptr() as u64;
    let oxide = Outcome::from_oxide_rv(nanosleep_shim::read_timespec(ptr).map(|_| 0).unwrap_or_else(|e| e));
    (host, oxide)
}

fn clock_gettime_invalid_clockid_einval() -> (Outcome, Outcome) {
    const BOGUS_CLOCKID: libc::clockid_t = 9999;
    let host = oracle::clock_gettime(BOGUS_CLOCKID);
    let oxide = if time_common_shim::clock_id_known(BOGUS_CLOCKID as u64) { unreachable!() }
        else { Outcome::err(libc::EINVAL) };
    (host, oxide)
}

fn clock_gettime_monotonic_ok() -> (Outcome, Outcome) {
    let host = oracle::clock_gettime(libc::CLOCK_MONOTONIC);
    let oxide = if time_common_shim::clock_id_known(libc::CLOCK_MONOTONIC as u64) { Outcome::ok(0) } else { unreachable!() };
    (host, oxide)
}

/// Mirrors `293_pipe2.rs`'s flag-validation gate verbatim (real
/// `vfs::OpenFlags` bit values, not reinvented literals): unknown bits →
/// `EINVAL`; the notification-pipe alias bit (`O_EXCL`'s value, reused per
/// Linux `pipe2(2)`) → `ENOPKG`.
fn pipe2_invalid_flags_einval() -> (Outcome, Outcome) {
    const BOGUS: i32 = 1 << 20; // not O_CLOEXEC/O_NONBLOCK/O_DIRECT/O_EXCL
    let host = oracle::pipe2(BOGUS);

    let valid_flags = vfs::OpenFlags::O_CLOEXEC.bits() | vfs::OpenFlags::O_NONBLOCK.bits()
        | vfs::OpenFlags::O_DIRECT.bits() | vfs::OpenFlags::O_EXCL.bits();
    let oxide = if (BOGUS as u32) & !valid_flags != 0 { Outcome::err(libc::EINVAL) } else { unreachable!() };
    (host, oxide)
}

fn pipe2_valid_flags_ok() -> (Outcome, Outcome) {
    let host = oracle::pipe2(libc::O_CLOEXEC | libc::O_NONBLOCK);
    let valid_flags = vfs::OpenFlags::O_CLOEXEC.bits() | vfs::OpenFlags::O_NONBLOCK.bits()
        | vfs::OpenFlags::O_DIRECT.bits() | vfs::OpenFlags::O_EXCL.bits();
    let flags = vfs::OpenFlags::O_CLOEXEC.bits() | vfs::OpenFlags::O_NONBLOCK.bits();
    let oxide = if flags & !valid_flags != 0 { unreachable!() } else { Outcome::ok(0) };
    (host, oxide)
}

fn not_run() -> (Outcome, Outcome) { unreachable!("skipped case body must not run") }

const CASES: &[Case] = &[
    Case { id: "nanosleep.negative_secs.einval", known_divergence: None, skip: None, compare_ret_on_success: false, run: nanosleep_negative_secs_einval },
    Case { id: "nanosleep.nsec_too_large.einval", known_divergence: None, skip: None, compare_ret_on_success: false, run: nanosleep_nsec_too_large_einval },
    Case { id: "nanosleep.zero.ok", known_divergence: None, skip: None, compare_ret_on_success: false, run: nanosleep_zero_ok },
    Case { id: "clock_gettime.invalid_clockid.einval", known_divergence: None, skip: None, compare_ret_on_success: false, run: clock_gettime_invalid_clockid_einval },
    Case { id: "clock_gettime.monotonic.ok", known_divergence: None, skip: None, compare_ret_on_success: false, run: clock_gettime_monotonic_ok },
    Case { id: "pipe2.invalid_flags.einval", known_divergence: None, skip: None, compare_ret_on_success: false, run: pipe2_invalid_flags_einval },
    Case { id: "pipe2.valid_flags.ok", known_divergence: None, skip: None, compare_ret_on_success: false, run: pipe2_valid_flags_ok },
    Case {
        id: "getrandom.invalid_flags.einval",
        known_divergence: None,
        skip: Some("NOT harness-run: devfs (uaccess+hwrng) is `#![cfg(target_os=\"oxide-kernel\")]` end-to-end, not stubbable without a whole-crate cfg change. CODE-READING FINDING instead (see README/report): crates/kernel/syscalls/src/318_getrandom.rs sys_getrandom() never reads args.a2 (flags) at all. Linux getrandom(2) EINVALs unknown flag bits; oxide silently accepts and ignores any flags value."),
        compare_ret_on_success: false,
        run: not_run,
    },
];

#[test]
fn misc_family_corpus() {
    run_corpus(CASES);
}
