//! The AMD64 `CONTEXT` record: field offsets and the startup image.
//!
//! The record is user ABI. One owner here, so the exception dispatcher's frame
//! and the initial thread's startup context cannot drift apart.
//!
//! The startup image is what the loader hands its own initialization entry:
//! the reference kernel maps the executable and the runtime module, writes a
//! context describing the thread the process is to start on, and enters the
//! runtime's initialization thunk with a pointer to it. The thunk loads the
//! rest of the module graph in user mode, rewrites the entry field to the
//! thread-start routine, and resumes on the context.

/// `sizeof(CONTEXT)` on this architecture.
pub const CONTEXT_BYTES: usize = 0x4d0;

pub const CTX_P1_HOME: usize = 0x00;
pub const CTX_P2_HOME: usize = 0x08;
pub const CTX_MXCSR: usize = 0x34;
pub const CTX_FLAGS: usize = 0x30;
pub const CTX_SEG_CS: usize = 0x38;
pub const CTX_SEG_DS: usize = 0x3a;
pub const CTX_SEG_ES: usize = 0x3c;
pub const CTX_SEG_FS: usize = 0x3e;
pub const CTX_SEG_GS: usize = 0x40;
pub const CTX_SEG_SS: usize = 0x42;
pub const CTX_EFLAGS: usize = 0x44;
pub const CTX_RAX: usize = 0x78;
pub const CTX_RCX: usize = 0x80;
pub const CTX_RDX: usize = 0x88;
pub const CTX_RSP: usize = 0x98;
pub const CTX_RIP: usize = 0xf8;
pub const CTX_FLT_SAVE: usize = 0x100;
/// The legacy `FXSAVE` image occupies `CONTEXT.FltSave`.
pub const FLT_SAVE_BYTES: usize = 512;
/// `MXCSR` within the `FXSAVE` image.
pub const FXSAVE_MXCSR: usize = 0x18;

/// `CONTEXT_AMD64` plus control, integer, segment and floating-point
/// components. Debug registers are not advertised, so a consumer never reads
/// them out of an uninitialised record.
pub const CONTEXT_FULL: u32 = 0x0010_0000 | 0x1 | 0x2 | 0x4 | 0x8;

/// Flat 64-bit user code and data selectors, as the record carries them.
pub const USER_CS: u16 = 0x33;
pub const USER_SS: u16 = 0x2b;
/// The reserved bit the flags register always carries set.
pub const EFLAGS_RESERVED: u64 = 0x0000_0002;
/// Reset `MXCSR`: every exception masked, round to nearest.
pub const MXCSR_INIT: u32 = 0x1f80;

/// The context the loader hands its initialization thunk: a thread that would
/// start at `entry` with `argument` on the stack `stack_pointer` describes.
/// # C: O(CONTEXT_BYTES)
pub fn startup_context(entry: u64, argument: u64, stack_pointer: u64) -> [u8; CONTEXT_BYTES] {
    let mut context = [0u8; CONTEXT_BYTES];
    put32(&mut context, CTX_FLAGS, CONTEXT_FULL);
    put32(&mut context, CTX_MXCSR, MXCSR_INIT);
    put32(&mut context, CTX_FLT_SAVE + FXSAVE_MXCSR, MXCSR_INIT);
    put16(&mut context, CTX_SEG_CS, USER_CS);
    put16(&mut context, CTX_SEG_SS, USER_SS);
    put16(&mut context, CTX_SEG_DS, USER_SS);
    put16(&mut context, CTX_SEG_ES, USER_SS);
    put16(&mut context, CTX_SEG_FS, 0);
    put16(&mut context, CTX_SEG_GS, 0);
    put32(&mut context, CTX_EFLAGS, EFLAGS_RESERVED as u32);
    // The thunk reads the entry out of the first argument register and the
    // argument out of the second, then resumes the context it was given.
    put64(&mut context, CTX_RCX, entry);
    put64(&mut context, CTX_RDX, argument);
    put64(&mut context, CTX_RSP, stack_pointer);
    put64(&mut context, CTX_RIP, entry);
    context
}

fn put16(bytes: &mut [u8], at: usize, value: u16) { bytes[at..at + 2].copy_from_slice(&value.to_le_bytes()); }
fn put32(bytes: &mut [u8], at: usize, value: u32) { bytes[at..at + 4].copy_from_slice(&value.to_le_bytes()); }
fn put64(bytes: &mut [u8], at: usize, value: u64) { bytes[at..at + 8].copy_from_slice(&value.to_le_bytes()); }

#[cfg(test)]
#[path = "nt_context/tests.rs"]
mod tests;
