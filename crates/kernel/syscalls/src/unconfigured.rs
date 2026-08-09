// Slots whose Linux feature this kernel does not build, answered with the
// errno Linux ITSELF returns when the matching CONFIG is unset — never a
// blanket EPERM.
//
// EPERM is a lie about the reason. It tells the caller "you lack permission",
// so a process already running as root retries forever and no privilege ever
// helps. ENOSYS says "this kernel has no such feature", which is both true and
// the exact byte a Linux built without the option returns — every libc probe,
// `strace` decoder and feature-detect fallback already handles it.
//
// Deliberately NOT kernel-cfg'd (`crate::obsolete` carries the same note): the
// predicate lives here, outside `#![cfg(target_os = "oxide-kernel")]`, so its
// tests actually run under `cargo test` instead of compiling out silently.

use syscall::nrs::*;

/// Slots refused with ENOSYS because the feature is not built, each paired
/// with the Linux config that turns it off and the mechanism that proves the
/// errno:
///
/// | Slot | Linux config | Mechanism |
/// |---|---|---|
/// | `kexec_load` | `CONFIG_KEXEC` | `COND_SYSCALL(kexec_load)` |
/// | `kexec_file_load` | `CONFIG_KEXEC_FILE` | `COND_SYSCALL(kexec_file_load)` |
///
/// Why each is refused rather than implemented:
///
/// `modify_ldt` is NOT here. It was, justified as parity with a build lacking
/// `CONFIG_MODIFY_LDT_SYSCALL` — but that option defaults on and is set in the
/// kernel this port targets, so the reference implements the syscall and the
/// refusal was a divergence recorded as compliance. Slot 154 now has a per-`mm`
/// LDT, a per-CPU GDT descriptor and an `lldt` reload on address-space switch
/// (`crate::ldt_abi`, `vmm::ldt`, `sched::ldt`).
///
/// `iopl` / `ioperm` are NOT here either, and left for the same reason plus one
/// more. The citation was a `CONFIG_X86_IOPL_IOPERM=n` build; that option is
/// `default y` and is set on the kernels this port targets, so it did not hold.
/// The OTHER objection did: a port grant nothing enforces is a security lie,
/// because the caller believes it holds access it does not have. That was
/// answered by building the enforcement rather than keeping the refusal — a
/// per-task refcounted permission map, the TSS window it is published through,
/// and the context-switch update that makes the grant follow its thread
/// (`syscalls/{172_iopl,173_ioperm}.rs` over `sched::ioport`).
/// - `kexec_load` / `kexec_file_load` load a replacement kernel image for a
///   subsequent `reboot(LINUX_REBOOT_CMD_KEXEC)`. `reboot(2)` already answers
///   the KEXEC command with EINVAL (`syscalls/169_reboot.rs`), so refusing the
///   load keeps the pair consistent: nothing can stage an image that the
///   reboot path would then refuse to boot.
pub const UNCONFIGURED_NRS: [u64; 2] = [
    NR_KEXEC_LOAD, NR_KEXEC_FILE_LOAD,
];

/// True for a slot this kernel deliberately answers with ENOSYS because the
/// backing feature is not built.
///
/// The predicate exists so the refusal is a DECISION with a cited Linux
/// counterpart, not the accidental dispatch fall-through — which is
/// indistinguishable from it at the ABI but carries no evidence that anyone
/// checked what Linux returns.
/// # C: O(3)
pub fn is_unconfigured(nr: u64) -> bool { UNCONFIGURED_NRS.contains(&nr) }

#[cfg(test)]
mod tests {
    use super::*;
    use syscall::errno::Errno;

    /// The slot numbers are pinned literally: an edit that renames a constant
    /// out from under this set, or that "helpfully" adds a slot we do
    /// implement, fails here instead of silently ENOSYS-ing a live syscall.
    #[test]
    fn set_matches_the_pinned_linux_slot_numbers() {
        let expected: [u64; 2] = [
            246, // kexec_load      COND_SYSCALL
            320, // kexec_file_load COND_SYSCALL
        ];
        let mut ours = UNCONFIGURED_NRS;
        ours.sort_unstable();
        assert_eq!(ours, expected, "unconfigured slot set drifted from Linux's numbering");
        assert!(!UNCONFIGURED_NRS.contains(&NR_MODIFY_LDT),
            "modify_ldt is implemented; the reference builds it by default");
    }

    /// The whole point of the lane: none of these may answer EPERM. A caller
    /// that is already root must be able to tell "not permitted" from "not
    /// built", because only one of the two can ever be fixed by privilege.
    #[test]
    fn every_member_refuses_with_enosys_not_eperm() {
        let rv = -(Errno::Enosys.as_i32() as i64);
        assert_ne!(rv, -(Errno::Eperm.as_i32() as i64));
        for nr in UNCONFIGURED_NRS {
            assert!(is_unconfigured(nr), "slot {nr} must be recognised as unconfigured");
        }
    }

    /// A slot we DO implement must never be swallowed by this predicate.
    /// `init_module`/`finit_module`/`delete_module` are the near neighbours
    /// that shared the old blanket-EPERM arm; `acct` is the one this lane
    /// implemented outright.
    #[test]
    fn implemented_neighbours_are_not_members() {
        for nr in [NR_INIT_MODULE, NR_FINIT_MODULE, NR_DELETE_MODULE, NR_ACCT, NR_REBOOT,
                   NR_MODIFY_LDT, NR_IOPL, NR_IOPERM] {
            assert!(!is_unconfigured(nr), "slot {nr} is implemented and must not be refused");
        }
    }

    /// `iopl` / `ioperm` are IMPLEMENTED and must never fall back into this
    /// set. The justification they once carried — parity with
    /// `CONFIG_X86_IOPL_IOPERM=n` — was wrong about the reference, which sets
    /// the option by default; a regression that re-added them here would
    /// resurrect a refusal Linux does not make.
    #[test]
    fn the_port_io_slots_are_implemented_not_refused() {
        assert!(!is_unconfigured(NR_IOPL));
        assert!(!is_unconfigured(NR_IOPERM));
    }
}
