//! memcg swap-accounting proof over the activated swapfile.
//!
//! With `memory.swap.max=0` a `MADV_PAGEOUT` must NOT charge swap; raised to one
//! page it must charge exactly one page; unmapping must release the charge. That
//! three-step ladder is what distinguishes real accounting from a counter nobody
//! updates.

use support::errno;

const CGROUP_PATH: &str = "/sys/fs/cgroup/swapfile_probe";
const CGROUP_SUBTREE_CONTROL: &str = "/sys/fs/cgroup/cgroup.subtree_control";
const CGROUP_ROOT_PROCS: &str = "/sys/fs/cgroup/cgroup.procs";
const CGROUP_ENABLE_MEMORY: &str = "+memory";
const PAGE_BYTES: usize = 4096;
/// `memory.swap.max` value that forbids swap entirely.
const NO_SWAP_BYTES: u64 = 0;
/// `memory.swap.max` value that permits exactly one page.
const SWAP_LIMIT_BYTES: u64 = PAGE_BYTES as u64;
/// Directory mode for the probe's own cgroup — owner rwx.
const CGROUP_DIR_MODE: u32 = 0o700;

/// Run the ladder, restoring the process to the root cgroup and removing the
/// probe cgroup whichever way it ends. Returns the failing step. # C: O(1)
pub(crate) fn pageout_smoke() -> Result<(), String> {
    write_text(CGROUP_SUBTREE_CONTROL, CGROUP_ENABLE_MEMORY).map_err(|_| step("enable-memory-controller"))?;
    let _ = std::fs::remove_dir(CGROUP_PATH);
    std::fs::create_dir(CGROUP_PATH)
        .and_then(|_| std::fs::set_permissions(CGROUP_PATH, permissions(CGROUP_DIR_MODE)))
        .map_err(|_| step("create-cgroup"))?;

    let result = ladder();

    // Detach before removing: a cgroup with members cannot be rmdir'd, and
    // leaving the probe parked there would poison the next boot's run.
    let _ = write_text(CGROUP_ROOT_PROCS, &std::process::id().to_string());
    let _ = std::fs::remove_dir(CGROUP_PATH);
    result
}

fn ladder() -> Result<(), String> {
    let swap_max = format!("{CGROUP_PATH}/memory.swap.max");
    let swap_current = format!("{CGROUP_PATH}/memory.swap.current");
    let procs = format!("{CGROUP_PATH}/cgroup.procs");

    write_text(&swap_max, &NO_SWAP_BYTES.to_string()).map_err(|_| step("set-swap-max-zero"))?;
    write_text(&procs, &std::process::id().to_string()).map_err(|_| step("attach-probe-cgroup"))?;

    let page = Anonymous::map().map_err(|_| step("map-anonymous-page"))?;
    page.dirty();

    page.pageout().map_err(|_| step("pageout-with-zero-swap-max"))?;
    expect(&swap_current, NO_SWAP_BYTES, "verify-zero-swap-current")?;

    write_text(&swap_max, &SWAP_LIMIT_BYTES.to_string()).map_err(|_| step("set-one-page-swap-max"))?;
    page.pageout().map_err(|_| step("pageout-with-one-page-swap-max"))?;
    expect(&swap_current, SWAP_LIMIT_BYTES, "verify-one-page-swap-current")?;

    drop(page);
    expect(&swap_current, NO_SWAP_BYTES, "verify-swap-charge-release")
}

/// One anonymous page, unmapped on drop so every exit path releases it.
struct Anonymous { addr: *mut libc::c_void }

impl Anonymous {
    fn map() -> Result<Self, ()> {
        // SAFETY: mmap with a null hint and MAP_ANONYMOUS asks the kernel to
        // choose the address; the result is checked against MAP_FAILED before use.
        let addr = unsafe {
            libc::mmap(std::ptr::null_mut(), PAGE_BYTES, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        if addr == libc::MAP_FAILED { return Err(()); }
        Ok(Self { addr })
    }

    /// Fault the page in and make it non-zero, so it is a real swap candidate
    /// rather than something the kernel can drop for free. # C: O(PAGE_BYTES)
    fn dirty(&self) {
        // SAFETY: `addr` is a live PROT_WRITE mapping of exactly PAGE_BYTES,
        // owned by this struct until Drop unmaps it.
        unsafe { std::ptr::write_bytes(self.addr as *mut u8, u8::MAX, PAGE_BYTES) };
    }

    fn pageout(&self) -> Result<(), ()> {
        // SAFETY: `addr`/PAGE_BYTES describe this struct's own live mapping.
        let rc = unsafe { libc::madvise(self.addr, PAGE_BYTES, libc::MADV_PAGEOUT) };
        if rc == 0 { Ok(()) } else { Err(()) }
    }
}

impl Drop for Anonymous {
    fn drop(&mut self) {
        // SAFETY: unmapping this struct's own mapping exactly once, at end of life.
        unsafe { libc::munmap(self.addr, PAGE_BYTES) };
    }
}

/// Assert a cgroup counter reads exactly `want`. # C: O(1)
fn expect(path: &str, want: u64, step_name: &str) -> Result<(), String> {
    let got = read_number(path).map_err(|_| step(step_name))?;
    if got == want { return Ok(()); }
    Err(format!("{step_name} want={want} got={got}"))
}

fn read_number(path: &str) -> Result<u64, ()> {
    std::fs::read_to_string(path).map_err(|_| ())?.trim().parse().map_err(|_| ())
}

fn write_text(path: &str, text: &str) -> Result<(), ()> {
    std::fs::write(path, text).map_err(|_| ())
}

fn permissions(mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(mode)
}

fn step(name: &str) -> String { format!("{name} errno={}", errno()) }
