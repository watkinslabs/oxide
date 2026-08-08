// The execute-only protection key, and the plain-`mprotect` key override
// built on it.
//
// A PROT_EXEC-only mapping is supposed to be unreadable. Page-table
// permission bits alone cannot say that on either arch here, so the mm
// dedicates one protection key to such mappings and denies access to it in
// the rights register. The key is allocated lazily, on the first plain
// `mprotect(PROT_EXEC)`, and stored back in the mm.
//
// One arch has no execute-only key at all — its execute-only mappings are a
// property of the leaf itself — and there the override is the identity on the
// VMA's own key. `PkeyArch::execute_only_init == None` is what says so.
//
// Ungated on purpose: this is a decision, and the slot files that consume it
// cannot be exercised hosted.

use super::{PkeyArch, PkeyState, EXEC_ONLY_UNSET, PKEY_ALLOC_FAILED, PKEY_DEFAULT, PKEY_KEEP,
            mm_pkey_alloc, mm_set_pkey_free};

/// The rights-register half of dedicating a key to execute-only mappings.
///
/// Split from the decision so the ordering below can be tested on a host with
/// no such register, and so the register's bit layout stays owned by the arch
/// that defines it.
pub trait ExecOnlyRights {
    /// Does the live register still permit reads through `pkey`?
    fn allows_read(&self, pkey: i32) -> bool;
    /// Deny all access through `pkey` in the live register. `false` is the
    /// hardware-absent failure return.
    fn deny_access(&mut self, pkey: i32) -> bool;
}

/// `execute_only_pkey(mm)` — this mm's execute-only key, allocating and
/// arming one on first use.
///
/// [`PKEY_ALLOC_FAILED`] means this mm has no execute-only support; that is a
/// fallback to ordinary permissions, not an error the caller reports.
/// # C: O(1)
pub fn execute_only_pkey(a: &PkeyArch, st: &mut PkeyState, r: &mut impl ExecOnlyRights) -> i32 {
    if !a.pkeys_enabled() { return PKEY_DEFAULT; }
    if a.execute_only_init.is_none() { return PKEY_ALLOC_FAILED; }
    let mut key = st.execute_only;
    let mut need_set = false;
    if key == EXEC_ONLY_UNSET {
        key = mm_pkey_alloc(a, st);
        if key == PKEY_ALLOC_FAILED { return PKEY_ALLOC_FAILED; }
        need_set = true;
    }
    // An already-dedicated key whose reads are already denied is armed; the
    // register write is skipped rather than repeated on every mprotect.
    if !need_set && !r.allows_read(key) { return key; }
    if !r.deny_access(key) {
        // The key was allocated but could not be armed. Release the bit
        // directly: the admission test hides the execute-only key, so the
        // ordinary free would refuse to clear it.
        if need_set { mm_set_pkey_free(st, key); }
        return PKEY_ALLOC_FAILED;
    }
    if need_set { st.execute_only = key; }
    key
}

/// What the override needs to know about the VMA it is running over.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VmaKeyView {
    /// `vma_pkey(vma)` — the key the mapping carries now.
    pub pkey: u8,
    /// Are the VMA's current access permissions exactly "execute"?
    pub access_is_exec_only: bool,
}

/// `arch_override_mprotect_pkey(vma, prot, pkey)` — which key the VMA should
/// carry after this `mprotect`.
///
/// `pkey` is the syscall's key argument: anything but [`PKEY_KEEP`] came from
/// `pkey_mprotect` and is never overridden. `prot_is_exec_only` is whether the
/// REQUESTED protection is exactly execute.
/// # C: O(1)
pub fn arch_override_mprotect_pkey(
    a: &PkeyArch, st: &mut PkeyState,
    prot_is_exec_only: bool, vma: VmaKeyView, pkey: i32,
    r: &mut impl ExecOnlyRights,
) -> i32 {
    if pkey != PKEY_KEEP { return pkey; }
    // The arch without an execute-only key inherits the VMA's key unchanged,
    // with no hardware test of its own.
    if a.execute_only_init.is_none() { return vma.pkey as i32; }
    if !a.pkeys_enabled() { return PKEY_DEFAULT; }
    if prot_is_exec_only {
        let k = execute_only_pkey(a, st, r);
        if k > 0 { return k; }
    } else if vma.access_is_exec_only && vma.pkey as i32 == st.execute_only {
        // The mapping was execute-only and no longer is, so it must stop
        // borrowing the key that made it unreadable.
        return PKEY_DEFAULT;
    }
    vma.pkey as i32
}

#[cfg(test)]
mod tests;
