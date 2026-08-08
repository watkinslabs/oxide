// `arch_vma_access_permitted` — the software half of protection-key
// enforcement.
//
// The hardware denies a key-protected access on its own and reports it in the
// fault code, but that is not enough on its own: a fault handler that resolves
// a mapping the rights register will refuse anyway wastes the work and can
// loop, and every access reaching a user mapping WITHOUT taking a fault (a
// page pinned on behalf of a syscall, a range walked for a caller) has no
// hardware check at all. Both consult this.
//
// Keys are only ever enforced against the CURRENT mm: there is one rights
// register per thread, and nothing names which thread of another process to
// read it from. An access to a foreign mapping is therefore permitted here and
// left to that mapping's own permissions.

use super::PkeyArch;

/// `arch_vma_access_permitted(vma, write, execute, foreign)`.
///
/// `allows(pkey, write, execute)` decodes the CURRENT thread's live rights
/// register for one key; the register's bit layout stays owned by the arch
/// that defines it, and this function owns only the ladder around it.
/// # C: O(1) plus `allows`
pub fn vma_access_permitted(
    a: &PkeyArch, pkey: u8, write: bool, execute: bool, foreign: bool,
    allows: impl FnOnce(u8, bool, bool) -> bool,
) -> bool {
    if !a.pkeys_enabled() { return true; }
    // On an arch whose rights register has no execute term, an instruction
    // fetch is never denied by a key.
    if execute && a.exec_ignores_keys { return true; }
    if foreign { return true; }
    allows(pkey, write, execute)
}

#[cfg(test)]
mod tests;
