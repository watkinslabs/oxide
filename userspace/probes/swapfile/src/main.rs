//! `/usr/local/bin/swapfile_probe` — real ext4 swapfile lifecycle probe.
//!
//! Creates a fully initialized, page-aligned regular file on the root ext4,
//! writes the Linux `SWAPSPACE2` header, activates it with `swapon(2)`, verifies
//! the canonical `/proc/swaps` view, runs the memcg pageout accounting proof,
//! then `swapoff(2)`s and removes it.

use std::os::unix::ffi::OsStrExt;
use support::{Verdict, fail_errno, report};

mod cgroup;
mod header;

const PROBE: &str = "swapfile_probe";
const SWAP_FILE_PATH: &str = "/var/tmp/oxide-swapfile-probe";
const PROC_SWAPS_PATH: &str = "/proc/swaps";
/// Owner read/write — a swap file must not be group- or world-readable.
const OWNER_READ_WRITE: u32 = 0o600;

fn main() -> std::process::ExitCode { report(PROBE, run()) }

fn run() -> Verdict {
    let _ = std::fs::remove_file(SWAP_FILE_PATH);
    if let Err(step) = header::create(SWAP_FILE_PATH, OWNER_READ_WRITE) { return fail_errno(step); }

    let path = cstring(SWAP_FILE_PATH);
    // SAFETY: swapon(2) takes a NUL-terminated path that outlives the call; the
    // file was just created, sized and headed by `header::create`.
    if unsafe { libc::swapon(path.as_ptr(), 0) } != 0 {
        let _ = std::fs::remove_file(SWAP_FILE_PATH);
        return fail_errno("swapon");
    }

    let verdict = active_and_accounted();

    // SAFETY: same path, still owned by this process; deactivating is safe
    // whether or not the checks above succeeded.
    let off = unsafe { libc::swapoff(path.as_ptr()) };
    let _ = std::fs::remove_file(SWAP_FILE_PATH);
    match verdict {
        Some(f) => f,
        None if off != 0 => fail_errno("swapoff"),
        None => Verdict::Pass("ext4 swap plus memcg pageout accounting".into()),
    }
}

/// `Some(failure)` on the first broken step, `None` if every check held. # C: O(swaps)
fn active_and_accounted() -> Option<Verdict> {
    match proc_reports_active_swapfile() {
        Ok(true) => {}
        Ok(false) => return Some(support::fail("proc-swaps: swapon succeeded but /proc/swaps omits the file")),
        Err(step) => return Some(fail_errno(step)),
    }
    cgroup::pageout_smoke().err().map(Verdict::Fail)
}

/// Whether `/proc/swaps` lists the activated file — the canonical Linux view, so
/// a `swapon` that returns 0 without registering an area still fails. # C: O(swaps)
fn proc_reports_active_swapfile() -> Result<bool, &'static str> {
    let swaps = std::fs::read_to_string(PROC_SWAPS_PATH).map_err(|_| "proc-swaps")?;
    Ok(swaps.lines().any(|l| l.contains(SWAP_FILE_PATH)))
}

/// NUL-terminated copy of a path for the libc entry points. # C: O(len)
pub(crate) fn cstring(path: &str) -> std::ffi::CString {
    std::ffi::CString::new(std::ffi::OsStr::new(path).as_bytes()).expect("probe paths carry no interior NUL")
}
