// The live protection-key rights register, as the mm's execute-only decision
// needs to see it. Register plumbing only — every decision lives in the mm
// module that owns it (docs/53).

#![cfg(target_os = "oxide-kernel")]

use vmm::pkeys::ExecOnlyRights;

/// `PKEY_DISABLE_ACCESS`, applied to the execute-only key so the mapping it
/// protects can be executed but neither read nor written.
const DISABLE_ACCESS: bool = true;
const DISABLE_WRITE: bool = false;

/// The running task's rights register.
///
/// Both arches implement it because both run the key-override decision; only
/// one of them ever asks the register anything, because only one has an
/// execute-only key. The other's execute-only mappings are a property of the
/// page-table leaf and need no key at all.
pub struct LiveRights;

impl ExecOnlyRights for LiveRights {
    /// # C: O(1)
    fn allows_read(&self, pkey: i32) -> bool { allows_read_arch(pkey) }
    /// # C: O(1)
    fn deny_access(&mut self, pkey: i32) -> bool { deny_access_arch(pkey) }
}

/// # C: O(1)
#[cfg(target_arch = "x86_64")]
fn allows_read_arch(pkey: i32) -> bool {
    if !hal_x86_64::ospke_enabled() { return true; }
    hal_x86_64::pkru::pkru_allows_read(sched::pkey_rights::read_live() as u32, pkey as u16)
}

/// # C: O(1)
#[cfg(target_arch = "x86_64")]
fn deny_access_arch(pkey: i32) -> bool {
    if !hal_x86_64::ospke_enabled() { return false; }
    let next = hal_x86_64::pkru::pkru_set_pkey_access(
        sched::pkey_rights::read_live() as u32, pkey as u16, DISABLE_ACCESS, DISABLE_WRITE);
    sched::pkey_rights::write_live(next as u64);
    true
}

/// # C: O(1)
#[cfg(target_arch = "aarch64")]
fn allows_read_arch(pkey: i32) -> bool {
    if !hal_aarch64::poe_enabled() { return true; }
    hal_aarch64::por::por_allows_read(sched::pkey_rights::read_live(), pkey as u16)
}

/// # C: O(1)
#[cfg(target_arch = "aarch64")]
fn deny_access_arch(pkey: i32) -> bool {
    if !hal_aarch64::poe_enabled() { return false; }
    let next = hal_aarch64::por::por_set_pkey_access(
        sched::pkey_rights::read_live(), pkey as u16, DISABLE_ACCESS, DISABLE_WRITE, false, false);
    sched::pkey_rights::write_live(next);
    true
}

/// `__pkru_allows_pkey` / `por_el0_allows_pkey` against the running thread's
/// live register: does it permit this access through `pkey`?
/// # C: O(1)
pub fn rights_allow(pkey: u8, write: bool, execute: bool) -> bool { rights_allow_arch(pkey, write, execute) }

/// # C: O(1)
#[cfg(target_arch = "x86_64")]
fn rights_allow_arch(pkey: u8, write: bool, _execute: bool) -> bool {
    let r = sched::pkey_rights::read_live() as u32;
    if !hal_x86_64::pkru::pkru_allows_read(r, pkey as u16) { return false; }
    !write || hal_x86_64::pkru::pkru_allows_write(r, pkey as u16)
}

/// # C: O(1)
#[cfg(target_arch = "aarch64")]
fn rights_allow_arch(pkey: u8, write: bool, execute: bool) -> bool {
    let r = sched::pkey_rights::read_live();
    if write { return hal_aarch64::por::por_allows_write(r, pkey as u16); }
    if execute { return hal_aarch64::por::por_allows_exec(r, pkey as u16); }
    hal_aarch64::por::por_allows_read(r, pkey as u16)
}
