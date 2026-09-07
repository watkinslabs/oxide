// Register image -> the CONTEXT and CONTEXT_EX the user exception dispatcher
// frame carries.
//
// The reference runtime builds this record inside its own signal handler, from
// whatever the host kernel handed it. This kernel owns the trap frame, so the
// same record is built directly from the interrupted registers — the layout,
// the advertised component flags and the CONTEXT_EX chunk descriptors are the
// user ABI either way, and are pinned by the tests beside this file rather
// than by a boot.
//
// Only the legacy (non-XSTATE) form is produced: the frame advertises no
// extended state, exactly as the reference does when the interrupted thread
// carried none.

use super::CONTEXT_BYTES;
// The record layout has one owner, so this frame and the loader's startup
// context cannot drift apart.
use pe::nt_context::{CTX_FLAGS, CTX_SEG_CS, CTX_SEG_DS, CTX_SEG_ES, CTX_SEG_FS, CTX_SEG_GS,
    CTX_SEG_SS, CTX_EFLAGS, CTX_RAX, CTX_RIP, CTX_MXCSR, CTX_FLT_SAVE, FXSAVE_MXCSR};

pub use pe::nt_context::CONTEXT_FULL as X64_CONTEXT_FLAGS;
pub use pe::nt_context::FLT_SAVE_BYTES as X64_FLT_SAVE_BYTES;

/// `CONTEXT_EX` sits immediately after the `CONTEXT` in the dispatcher frame.
pub const X64_CONTEXT_EX_OFFSET: usize = CONTEXT_BYTES;
/// `CONTEXT_EX` is three `{ LONG Offset; ULONG Length }` chunks — All, Legacy,
/// XState — plus eight alignment bytes on this architecture.
const CTX_EX_ALL: usize = 0;
const CTX_EX_LEGACY: usize = 8;
const CTX_EX_XSTATE: usize = 16;
pub const X64_CONTEXT_EX_BYTES: usize = 32;
/// The `All` chunk spans the legacy context plus the three chunk descriptors,
/// excluding the alignment tail.
const X64_CONTEXT_EX_DESCRIBED_BYTES: u32 = 24;
/// With no extended state the XState chunk is described as empty at offset
/// zero, with the length the reference publishes for "nothing here".
const X64_EMPTY_XSTATE_LENGTH: u32 = 25;

/// `RFLAGS` bits cleared before the dispatcher runs: trap, direction and
/// alignment-check. Entering a handler with the trap flag live single-steps
/// the dispatcher, and a set direction flag breaks every string operation it
/// performs.
const RFLAGS_TF: u64 = 0x0000_0100;
const RFLAGS_DF: u64 = 0x0000_0400;
const RFLAGS_AC: u64 = 0x0004_0000;

/// The interrupted user registers one dispatcher frame reports.
///
/// A plain data record, not the architecture's trap frame: the encoding below
/// is then provable without a running CPU, which is the whole reason the
/// layout lives here rather than in the target-gated delivery path.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct X64Registers {
    pub rax: u64, pub rcx: u64, pub rdx: u64, pub rbx: u64,
    pub rsp: u64, pub rbp: u64, pub rsi: u64, pub rdi: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u64,
    pub cs: u16, pub ss: u16,
}

impl X64Registers {
    /// The sixteen general registers in `CONTEXT` order, starting at `Rax`.
    const fn general(&self) -> [u64; 16] {
        [self.rax, self.rcx, self.rdx, self.rbx, self.rsp, self.rbp, self.rsi, self.rdi,
         self.r8, self.r9, self.r10, self.r11, self.r12, self.r13, self.r14, self.r15]
    }
}

/// Encode one interrupted register set as the legacy AMD64 `CONTEXT` the
/// dispatcher frame opens with.
///
/// The data segment selectors report the flat user data selector, which is
/// what a 64-bit thread runs with and what the runtime writes into the same
/// fields; nothing in the frame may claim a selector the thread never held.
/// # C: O(1)
pub fn x64_context(regs: &X64Registers, user_ds: u16) -> [u8; CONTEXT_BYTES] {
    let mut context = [0u8; CONTEXT_BYTES];
    context[CTX_FLAGS..CTX_FLAGS + 4].copy_from_slice(&X64_CONTEXT_FLAGS.to_le_bytes());
    for (offset, value) in [(CTX_SEG_CS, regs.cs), (CTX_SEG_SS, regs.ss), (CTX_SEG_DS, user_ds),
                            (CTX_SEG_ES, user_ds), (CTX_SEG_FS, user_ds), (CTX_SEG_GS, user_ds)] {
        context[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    context[CTX_EFLAGS..CTX_EFLAGS + 4].copy_from_slice(&(regs.rflags as u32).to_le_bytes());
    for (index, value) in regs.general().iter().enumerate() {
        let at = CTX_RAX + index * 8;
        context[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    context[CTX_RIP..CTX_RIP + 8].copy_from_slice(&regs.rip.to_le_bytes());
    context
}

/// Write the `CONTEXT_EX` chunk descriptors for a frame carrying no extended
/// state. `frame` is the dispatcher frame; the descriptors land immediately
/// after the legacy context and are relative to their own address.
///
/// Returns `false` when the frame is too short to hold them, so a caller
/// cannot half-build the record.
/// # C: O(1)
pub fn x64_write_context_ex(frame: &mut [u8]) -> bool {
    let base = X64_CONTEXT_EX_OFFSET;
    if frame.len() < base + X64_CONTEXT_EX_BYTES { return false; }
    let legacy_offset = -(CONTEXT_BYTES as i32);
    for (at, offset, length) in
        [(CTX_EX_ALL, legacy_offset, CONTEXT_BYTES as u32 + X64_CONTEXT_EX_DESCRIBED_BYTES),
         (CTX_EX_LEGACY, legacy_offset, CONTEXT_BYTES as u32),
         (CTX_EX_XSTATE, 0, X64_EMPTY_XSTATE_LENGTH)] {
        frame[base + at..base + at + 4].copy_from_slice(&offset.to_le_bytes());
        frame[base + at + 4..base + at + 8].copy_from_slice(&length.to_le_bytes());
    }
    true
}

/// Place one legacy `FXSAVE` image in the context's floating-point fields.
///
/// `CONTEXT.MxCsr` is a second copy of the word inside that image and the two
/// must agree: a continuation reads one of them, and a frame that disagreed
/// with itself would restore a control word the thread never had.
/// # C: O(1)
pub fn x64_write_floating(context: &mut [u8; CONTEXT_BYTES], image: &[u8; X64_FLT_SAVE_BYTES]) {
    context[CTX_FLT_SAVE..CTX_FLT_SAVE + X64_FLT_SAVE_BYTES].copy_from_slice(image);
    context[CTX_MXCSR..CTX_MXCSR + 4].copy_from_slice(&image[FXSAVE_MXCSR..FXSAVE_MXCSR + 4]);
}

/// The `RFLAGS` the dispatcher is entered with. # C: O(1)
pub const fn x64_dispatch_rflags(rflags: u64) -> u64 { rflags & !(RFLAGS_TF | RFLAGS_DF | RFLAGS_AC) }

#[cfg(test)]
#[path = "context/tests.rs"]
mod tests;
