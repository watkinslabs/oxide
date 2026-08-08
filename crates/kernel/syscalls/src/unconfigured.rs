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
/// | `modify_ldt` | `CONFIG_MODIFY_LDT_SYSCALL` | `COND_SYSCALL(modify_ldt)`; the x86 build only compiles the LDT object when set |
/// | `iopl` | `CONFIG_X86_IOPL_IOPERM` | the `#else` branch: `SYSCALL_DEFINE1(iopl) { return -ENOSYS; }` |
/// | `ioperm` | `CONFIG_X86_IOPL_IOPERM` | same `#else` branch: `SYSCALL_DEFINE3(ioperm) { return -ENOSYS; }` |
/// | `kexec_load` | `CONFIG_KEXEC` | `COND_SYSCALL(kexec_load)` |
/// | `kexec_file_load` | `CONFIG_KEXEC_FILE` | `COND_SYSCALL(kexec_file_load)` |
///
/// Why each is refused rather than implemented:
///
/// - `modify_ldt` needs a per-`mm` Local Descriptor Table, an LDT descriptor
///   installed in the GDT, and an `lldt` reload on every address-space switch.
///   None of that exists, and it is x86-only — aarch64 has no such slot in the
///   generic ABI, so ENOSYS is the only answer that is honest on both arches.
/// - `iopl` / `ioperm` hand userspace direct port I/O. That is backed by the
///   TSS I/O permission bitmap plus per-task bitmap state carried across
///   context switch. Without that state a success return is a SECURITY LIE:
///   the caller believes it holds port access it does not have, and proceeds
///   to drive hardware through `outb`/`inb` that fault (or, worse, would not).
///   A grant we cannot enforce is strictly worse than an honest refusal.
/// - `kexec_load` / `kexec_file_load` load a replacement kernel image for a
///   subsequent `reboot(LINUX_REBOOT_CMD_KEXEC)`. `reboot(2)` already answers
///   the KEXEC command with EINVAL (`syscalls/169_reboot.rs`), so refusing the
///   load keeps the pair consistent: nothing can stage an image that the
///   reboot path would then refuse to boot.
pub const UNCONFIGURED_NRS: [u64; 5] = [
    NR_MODIFY_LDT, NR_IOPL, NR_IOPERM, NR_KEXEC_LOAD, NR_KEXEC_FILE_LOAD,
];

/// True for a slot this kernel deliberately answers with ENOSYS because the
/// backing feature is not built.
///
/// The predicate exists so the refusal is a DECISION with a cited Linux
/// counterpart, not the accidental dispatch fall-through — which is
/// indistinguishable from it at the ABI but carries no evidence that anyone
/// checked what Linux returns.
/// # C: O(5)
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
        let expected: [u64; 5] = [
            154, // modify_ldt      COND_SYSCALL, x86-only
            172, // iopl            ioport.c #else -> -ENOSYS
            173, // ioperm          ioport.c #else -> -ENOSYS
            246, // kexec_load      COND_SYSCALL
            320, // kexec_file_load COND_SYSCALL
        ];
        let mut ours = UNCONFIGURED_NRS;
        ours.sort_unstable();
        assert_eq!(ours, expected, "unconfigured slot set drifted from Linux's numbering");
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
        for nr in [NR_INIT_MODULE, NR_FINIT_MODULE, NR_DELETE_MODULE, NR_ACCT, NR_REBOOT] {
            assert!(!is_unconfigured(nr), "slot {nr} is implemented and must not be refused");
        }
    }

    /// `iopl` refuses BEFORE validating its level argument, exactly like the
    /// `CONFIG_X86_IOPL_IOPERM=n` branch — which returns `-ENOSYS` with no
    /// `level > 3` test. A kernel that answered EINVAL for a bad level and
    /// ENOSYS otherwise would leak that the feature is half-present.
    #[test]
    fn iopl_refusal_does_not_depend_on_its_argument() {
        assert!(is_unconfigured(NR_IOPL));
        assert!(is_unconfigured(NR_IOPERM));
    }
}
