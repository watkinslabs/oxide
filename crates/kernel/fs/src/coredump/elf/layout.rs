// Per-arch shapes of the register block and of the two identity structures a
// debugger reads out of a core file.
//
// Both `elf_prstatus` and `elf_prpsinfo` are LP64 C structures, so their leading
// fields sit at the same offsets on every 64-bit arch; only the embedded
// register block differs in length, which moves every field after it.

use super::uapi::{EM_AARCH64, EM_X86_64};

/// Bytes of one `timeval` inside `elf_prstatus` (two LP64 words).
pub const TIMEVAL_BYTES: usize = 16;

// `elf_prstatus` — offsets of the fields ahead of the register block. The
// leading `elf_siginfo` is three `int`s; `pr_cursig` is a `short`; the two
// signal masks and the four `timeval`s are LP64-aligned.
pub const PR_INFO_SIGNO_OFF: usize = 0;
pub const PR_INFO_CODE_OFF:  usize = 4;
pub const PR_INFO_ERRNO_OFF: usize = 8;
pub const PR_CURSIG_OFF:     usize = 12;
pub const PR_SIGPEND_OFF:    usize = 16;
pub const PR_SIGHOLD_OFF:    usize = 24;
pub const PR_PID_OFF:        usize = 32;
pub const PR_PPID_OFF:       usize = 36;
pub const PR_PGRP_OFF:       usize = 40;
pub const PR_SID_OFF:        usize = 44;
pub const PR_UTIME_OFF:      usize = 48;
pub const PR_STIME_OFF:      usize = 64;
pub const PR_CUTIME_OFF:     usize = 80;
pub const PR_CSTIME_OFF:     usize = 96;

/// End of the arch-independent head of `elf_prstatus`; the register block starts
/// here, and `pr_fpvalid` follows it.
pub const PR_REG_OFF: usize = 112;

/// Alignment `elf_prstatus` carries as a whole (its widest member is LP64).
pub const PRSTATUS_ALIGN: usize = 8;

/// Bytes of the `int pr_fpvalid` that closes `elf_prstatus`.
pub const PR_FPVALID_BYTES: usize = 4;

// `elf_prpsinfo` — the same on every LP64 arch, no embedded register block.
pub const PSINFO_STATE_OFF:  usize = 0;
pub const PSINFO_SNAME_OFF:  usize = 1;
pub const PSINFO_ZOMB_OFF:   usize = 2;
pub const PSINFO_NICE_OFF:   usize = 3;
pub const PSINFO_FLAG_OFF:   usize = 8;
pub const PSINFO_UID_OFF:    usize = 16;
pub const PSINFO_GID_OFF:    usize = 20;
pub const PSINFO_PID_OFF:    usize = 24;
pub const PSINFO_PPID_OFF:   usize = 28;
pub const PSINFO_PGRP_OFF:   usize = 32;
pub const PSINFO_SID_OFF:    usize = 36;
pub const PSINFO_FNAME_OFF:  usize = 40;
pub const PSINFO_PSARGS_OFF: usize = 56;

/// Bytes of `pr_fname`, fixed by the ABI rather than by the kernel's own
/// command-name limit.
pub const PSINFO_FNAME_BYTES: usize = 16;
/// Bytes of `pr_psargs`.
pub const PSINFO_PSARGS_BYTES: usize = 80;
/// Bytes of a whole `elf_prpsinfo`.
pub const PRPSINFO_BYTES: usize = 136;

// `Elf64_Shdr` — offsets of the only fields the extended-numbering escape sets.
pub const SH_TYPE_OFF: usize = 4;
pub const SH_SIZE_OFF: usize = 32;
pub const SH_LINK_OFF: usize = 40;
pub const SH_INFO_OFF: usize = 44;

/// Process states `pr_state` enumerates, in the order `pr_sname` indexes.
const SNAME_TABLE: &[u8] = b"RSDTZW";

/// `pr_sname` for a state past the table.
const SNAME_UNKNOWN: u8 = b'.';

/// Zombie's `pr_sname`, which `pr_zomb` restates.
const SNAME_ZOMBIE: u8 = b'Z';

/// Registers of an x86-64 thread as a core file carries them: the general
/// register file plus the syscall number, instruction pointer, flags, stack
/// pointer and the segment bases and selectors.
const X86_64_NGREG: usize = 27;

/// Registers of an aarch64 thread as a core file carries them: `x0`..`x30`,
/// the stack pointer, the program counter and the processor state.
const AARCH64_NGREG: usize = 34;

/// Bytes of one register a core file carries.
const GREG_BYTES: usize = 8;

/// Bytes of the x86-64 floating-point note: the legacy save area.
const X86_64_FPREG_BYTES: usize = 512;

/// Bytes of the aarch64 floating-point note: 32 vector registers plus the
/// status and control words and their reserved tail.
const AARCH64_FPREG_BYTES: usize = 528;

/// Which register file a dump describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CoreArch { X86_64, Aarch64 }

impl CoreArch {
    /// Arch the running kernel dumps for.
    /// # C: O(1)
    pub const fn native() -> Self {
        #[cfg(target_arch = "aarch64")] { CoreArch::Aarch64 }
        #[cfg(not(target_arch = "aarch64"))] { CoreArch::X86_64 }
    }

    /// `e_machine` a debugger dispatches its register decoder on.
    /// # C: O(1)
    pub const fn machine(self) -> u16 {
        match self { CoreArch::X86_64 => EM_X86_64, CoreArch::Aarch64 => EM_AARCH64 }
    }

    /// Registers in the block `NT_PRSTATUS` embeds.
    /// # C: O(1)
    pub const fn ngreg(self) -> usize {
        match self { CoreArch::X86_64 => X86_64_NGREG, CoreArch::Aarch64 => AARCH64_NGREG }
    }

    /// Bytes of the block `NT_PRSTATUS` embeds.
    /// # C: O(1)
    pub const fn gregset_bytes(self) -> usize { self.ngreg() * GREG_BYTES }

    /// Bytes of the descriptor `NT_PRFPREG` carries.
    /// # C: O(1)
    pub const fn fpregset_bytes(self) -> usize {
        match self {
            CoreArch::X86_64  => X86_64_FPREG_BYTES,
            CoreArch::Aarch64 => AARCH64_FPREG_BYTES,
        }
    }

    /// Offset of `pr_fpvalid`, which the register block displaces.
    /// # C: O(1)
    pub const fn pr_fpvalid_off(self) -> usize { PR_REG_OFF + self.gregset_bytes() }

    /// Bytes of a whole `elf_prstatus`, tail padding included.
    /// # C: O(1)
    pub const fn prstatus_bytes(self) -> usize {
        let end = self.pr_fpvalid_off() + PR_FPVALID_BYTES;
        (end + PRSTATUS_ALIGN - 1) / PRSTATUS_ALIGN * PRSTATUS_ALIGN
    }
}

/// `pr_sname`, the printable form of the numeric `pr_state`.
/// # C: O(1)
pub fn sname_of(state: u8) -> u8 {
    match SNAME_TABLE.get(state as usize) { Some(c) => *c, None => SNAME_UNKNOWN }
}

/// Whether `pr_zomb` is set for a state, which restates `pr_sname`.
/// # C: O(1)
pub fn zombie_of(state: u8) -> bool { sname_of(state) == SNAME_ZOMBIE }
