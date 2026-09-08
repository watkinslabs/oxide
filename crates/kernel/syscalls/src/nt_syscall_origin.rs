//! Which personality owns a raw syscall word, decided by where the call came
//! from.
//!
//! An NT process on this kernel holds two kinds of caller in ONE address
//! space. The shipped runtime's service stubs are PE code: each loads a bare
//! service ordinal and executes the architecture's syscall instruction,
//! because the shared page's dispatcher-select field is left clear and the
//! kernel owns that instruction. The same process also runs native ELF text —
//! the launcher and the runtime's own Unix-side objects — whose libc issues
//! ordinary Linux syscalls. Both arrive at one kernel entry, and the two
//! numberings overlap: ordinal 21 and `access(2)`, ordinal 0 and `read(2)`,
//! ordinal 231 and `exit_group(2)` are the same word.
//!
//! A host that cannot own the syscall instruction keeps the namespaces apart
//! by construction: its PE side calls an indirect user-mode dispatcher and
//! never executes a syscall, so every syscall it sees is a Linux one. This
//! kernel takes the other leg, so the separation has to be re-established
//! here — by the ORIGIN of the call, not by the task's personality, which is
//! a property of the process and cannot distinguish two callers inside it.
//!
//! The origin is the trapped user return address the entry frame carries. Code
//! inside a mapped PE image is a service stub; anything else is native text.
//! Ungated so the decision is testable: every caller of it is kernel-only.

/// Half-open extent of one PE image mapped into a process address space.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeImageExtent { pub base: u64, pub size: u64 }

/// Where a syscall instruction was executed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SyscallOrigin {
    /// Inside a mapped PE image: a shipped service stub.
    PeImage,
    /// Native ELF text — the launcher, the runtime's Unix objects, libc.
    Native,
}

/// Classify one trapped user return address against the address space's mapped
/// PE images.
///
/// `pc == 0` means no live entry frame was readable. That is not a PE origin:
/// an unattributable word is answered by the Linux tables, whose worst case is
/// a refused call, rather than by a service that would act on foreign
/// arguments.
/// # C: O(N_images)
pub fn origin_of(pc: u64, images: impl IntoIterator<Item = PeImageExtent>) -> SyscallOrigin {
    if pc == 0 { return SyscallOrigin::Native; }
    for image in images {
        if pc >= image.base && pc - image.base < image.size { return SyscallOrigin::PeImage; }
    }
    SyscallOrigin::Native
}

/// Whether the raw (untagged) ordinal tables may claim this syscall word.
///
/// Both conditions are required: the process must run the NT personality, and
/// the word must have been executed by PE text. A tagged service selector is
/// decoded before this question is asked and is unaffected.
/// # C: O(1)
pub fn claims_raw_nt_ordinal(nt_personality: bool, origin: SyscallOrigin) -> bool {
    nt_personality && matches!(origin, SyscallOrigin::PeImage)
}

#[cfg(test)]
#[path = "nt_syscall_origin/tests.rs"]
mod tests;
