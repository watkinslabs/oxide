//! Decoding a shipped x86-64 system-service stub.
//!
//! Every system service exported by a PE `ntdll` or `win32u` has the same
//! fixed body: the first argument register is copied to the register the
//! kernel entry reads, the service ordinal is loaded as a 32-bit immediate,
//! and one flag byte at a fixed absolute address decides between the
//! architectural syscall instruction and an indirect user-mode dispatcher.
//!
//! The ordinal is fixed when the module is built, so it is read from the
//! module the guest will run rather than transcribed into a table here: a
//! version bump then cannot renumber the services without the decode moving
//! with it.
//!
//! The `win32u` prologue is byte-identical, which is why the ordinal decode
//! is shared: only the flag test and the branch tail distinguish a full
//! service stub from the eight-byte prefix an ordinal lookup needs.

/// `mov %rcx,%r10` — the first argument register is preserved across the entry.
const MOVE_REQUEST_REGISTER: [u8; 3] = [0x4c, 0x8b, 0xd1];
/// `mov $imm32,%eax` — the service ordinal.
const LOAD_ORDINAL_IMMEDIATE: u8 = 0xb8;
/// Bytes of prologue an ordinal decode needs: the register move and the immediate.
pub const ORDINAL_PREFIX_BYTES: usize = 8;
/// `testb $1,<abs32>` — the flag test, with a 32-bit absolute displacement.
const TEST_FLAG_OPCODE: [u8; 3] = [0xf6, 0x04, 0x25];
const TEST_FLAG_IMMEDIATE: u8 = 0x01;
/// `jne` over the syscall leg, then `syscall`, then `ret`.
const BRANCH_IF_DISPATCHER: [u8; 2] = [0x75, 0x03];
const SYSCALL_INSTRUCTION: [u8; 2] = [0x0f, 0x05];
const RETURN_INSTRUCTION: u8 = 0xc3;
/// Bytes the full service stub occupies up to and including its syscall leg.
pub const SERVICE_STUB_BYTES: usize = 21;

/// A decoded system-service stub.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ServiceStub {
    /// The ordinal the module asks the kernel entry to run.
    pub ordinal: u32,
    /// Absolute address of the flag byte the stub tests.
    pub flag_address: u64,
}

/// Read the service ordinal from a stub prologue.
/// # C: O(1)
pub fn ordinal(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < ORDINAL_PREFIX_BYTES { return None; }
    if bytes[..3] != MOVE_REQUEST_REGISTER || bytes[3] != LOAD_ORDINAL_IMMEDIATE { return None; }
    Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
}

/// Decode a full service stub, including the flag it tests and its syscall leg.
/// Rejects any body that is not the exact shipped shape, so a module whose
/// stubs changed cannot be read as if they had not.
/// # C: O(1)
pub fn decode(bytes: &[u8]) -> Option<ServiceStub> {
    let ordinal = ordinal(bytes)?;
    if bytes.len() < SERVICE_STUB_BYTES { return None; }
    if bytes[8..11] != TEST_FLAG_OPCODE { return None; }
    let flag_address = u32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]) as u64;
    if bytes[15] != TEST_FLAG_IMMEDIATE { return None; }
    if bytes[16..18] != BRANCH_IF_DISPATCHER { return None; }
    if bytes[18..20] != SYSCALL_INSTRUCTION { return None; }
    if bytes[20] != RETURN_INSTRUCTION { return None; }
    Some(ServiceStub { ordinal, flag_address })
}

/// Whether a stub reaches the kernel through the architectural syscall
/// instruction, given the value of the flag byte it tests. Bit 0 selects the
/// indirect user-mode dispatcher; every other bit is reserved and ignored.
/// # C: O(1)
pub fn takes_architectural_entry(flag: u8) -> bool { flag & 1 == 0 }

#[cfg(test)]
#[path = "stub/tests.rs"]
mod tests;
