// Hardware trap -> Windows EXCEPTION_RECORD, for the NT personality.
//
// The reference runtime never sees a CPU trap: a POSIX kernel hands it a
// signal, and the runtime's SIGSEGV/SIGILL/SIGBUS/SIGTRAP/SIGFPE handlers
// rebuild an EXCEPTION_RECORD from the raw machine status the signal frame
// carries (the x86 `#PF` error code and IDT vector, or ESR_EL1) before
// entering the user exception dispatcher. This kernel HAS an NT personality,
// so the record is built where the trap is taken and no signal is invented on
// the way; the decode below is the same decode, one layer down.
//
// Pure arithmetic, no kernel state, both arches always compiled — the mapping
// is `cargo test -p sched` provable rather than only observable at a boot.
//
// Module manifest:
//   `Raised`    — one classified exception plus its record encoder.
//   `x86_64`    — IDT vector + `#PF` error-code decode.
//   `aarch64`   — ESR_EL1 exception-class + WnR decode.

use super::EXCEPTION_RECORD_BYTES;

/// `EXCEPTION_RECORD` field offsets. Part of the user ABI: the record is
/// copied verbatim into the dispatcher frame the runtime reads.
const CODE_OFFSET: usize = 0x00;
const FLAGS_OFFSET: usize = 0x04;
const ADDRESS_OFFSET: usize = 0x10;
const COUNT_OFFSET: usize = 0x18;
const PARAMETERS_OFFSET: usize = 0x20;
/// Records this module builds never carry more than the access/address pair
/// plus one status word.
const MAX_PARAMETERS: usize = 3;

/// NTSTATUS values a hardware trap can raise.
pub const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;
pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xc000_0005;
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xc000_001d;
pub const STATUS_ARRAY_BOUNDS_EXCEEDED: u32 = 0xc000_008c;
pub const STATUS_FLOAT_INVALID_OPERATION: u32 = 0xc000_0090;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xc000_0094;
pub const STATUS_INTEGER_OVERFLOW: u32 = 0xc000_0095;
pub const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xc000_0096;
pub const STATUS_STACK_OVERFLOW: u32 = 0xc000_00fd;

/// `ExceptionInformation[0]` for an access violation: which access was denied.
pub const READ_FAULT: u64 = 0;
pub const WRITE_FAULT: u64 = 1;
pub const EXECUTE_FAULT: u64 = 8;
/// A general-protection fault names no address; the record reports the
/// all-ones sentinel the runtime uses for "selector, not a linear address".
pub const NO_FAULT_ADDRESS: u64 = u64::MAX;

/// One classified hardware exception, before it acquires a CONTEXT.
///
/// `address` is `ExceptionAddress` — the instruction that trapped, already
/// corrected for the traps whose reported PC is past the faulting byte.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Raised {
    pub code: u32,
    pub flags: u32,
    pub address: u64,
    pub parameters: [u64; MAX_PARAMETERS],
    pub count: u32,
}

impl Raised {
    const fn simple(code: u32, address: u64) -> Self {
        Self { code, flags: 0, address, parameters: [0; MAX_PARAMETERS], count: 0 }
    }

    /// Encode this exception as the fixed-layout record the user dispatcher
    /// frame carries. Trailing parameter slots stay zero.
    /// # C: O(1)
    pub fn record(&self) -> [u8; EXCEPTION_RECORD_BYTES] {
        let mut record = [0u8; EXCEPTION_RECORD_BYTES];
        record[CODE_OFFSET..CODE_OFFSET + 4].copy_from_slice(&self.code.to_le_bytes());
        record[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&self.flags.to_le_bytes());
        record[ADDRESS_OFFSET..ADDRESS_OFFSET + 8].copy_from_slice(&self.address.to_le_bytes());
        record[COUNT_OFFSET..COUNT_OFFSET + 4].copy_from_slice(&self.count.to_le_bytes());
        for index in 0..self.count as usize {
            let at = PARAMETERS_OFFSET + index * 8;
            record[at..at + 8].copy_from_slice(&self.parameters[index].to_le_bytes());
        }
        record
    }
}

/// Build the two-parameter access-violation body shared by both
/// architectures: which access was refused, and the address that refused it.
fn access_violation(access: u64, address: u64, pc: u64) -> Raised {
    Raised { code: STATUS_ACCESS_VIOLATION, flags: 0, address: pc,
             parameters: [access, address, 0], count: 2 }
}

pub mod x86_64 {
    use super::*;
    use hal::fault_class::x86_64 as fc;

    /// The `#PF` error-code bits the access parameter is built from: write
    /// (bit 1) becomes bit 0 of the parameter, instruction fetch (bit 4)
    /// becomes bit 3, and a read leaves it zero.
    const ACCESS_SHIFT: u32 = 1;
    const ACCESS_MASK: u64 = 0x09;

    /// `#PF` from user mode that the demand-page resolver refused.
    ///
    /// A refused fault is an access violation; the guard-page and
    /// write-watch resolutions that could answer otherwise are resolved by
    /// the address-space owner before the fault reaches this decode, so no
    /// second copy of that policy exists here.
    /// # C: O(1)
    pub fn page_fault(err: u64, address: u64, pc: u64) -> Raised {
        access_violation((err >> ACCESS_SHIFT) & ACCESS_MASK, address, pc)
    }

    /// Every non-`#PF` synchronous trap taken from user mode.
    ///
    /// `None` for the vectors that cannot reach user mode as an exception the
    /// runtime can describe; the caller then falls back to the POSIX signal,
    /// which is the honest report for a machine check or a double fault.
    /// # C: O(1)
    pub fn trap(vec: u64, pc: u64) -> Option<Raised> {
        let raised = match vec {
            fc::TRAP_DE => Raised::simple(STATUS_INTEGER_DIVIDE_BY_ZERO, pc),
            fc::TRAP_DB => Raised::simple(STATUS_SINGLE_STEP, pc),
            // The trap is taken after `int3`; the record names the byte that
            // raised it, and the dispatch context rewinds to match.
            fc::TRAP_BP => Raised { code: STATUS_BREAKPOINT, flags: 0, address: pc.checked_sub(1)?,
                                    parameters: [0; MAX_PARAMETERS], count: 1 },
            fc::TRAP_OF => Raised::simple(STATUS_INTEGER_OVERFLOW, pc),
            fc::TRAP_BR => Raised::simple(STATUS_ARRAY_BOUNDS_EXCEEDED, pc),
            fc::TRAP_UD => Raised::simple(STATUS_ILLEGAL_INSTRUCTION, pc),
            fc::TRAP_SS => Raised::simple(STATUS_STACK_OVERFLOW, pc),
            // A segment-not-present or protection fault names no linear
            // address. Deciding PRIVILEGED_INSTRUCTION instead needs the
            // faulting opcode decoded, which this layer does not read.
            fc::TRAP_NP | fc::TRAP_GP => access_violation(READ_FAULT, NO_FAULT_ADDRESS, pc),
            fc::TRAP_AC => Raised::simple(STATUS_DATATYPE_MISALIGNMENT, pc),
            // Naming the specific x87/SSE condition needs the status word;
            // the invalid-operation code is the reference's own default when
            // the stack-check bit is clear.
            fc::TRAP_MF | fc::TRAP_XF => Raised::simple(STATUS_FLOAT_INVALID_OPERATION, pc),
            _ => return None,
        };
        Some(raised)
    }
}

pub mod aarch64 {
    use super::*;
    use hal::fault_class::aarch64 as fc;

    /// `ESR_EL1.ISS.WnR` — the aborting access was a write.
    const ISS_WNR: u64 = 1 << 6;

    /// Data or instruction abort from EL0 that the resolver refused.
    /// # C: O(1)
    pub fn abort(esr: u64, address: u64, pc: u64) -> Raised {
        let access = if fc::ec(esr) == fc::EC_IABT_LOW { EXECUTE_FAULT }
                     else if esr & ISS_WNR != 0 { WRITE_FAULT }
                     else { READ_FAULT };
        access_violation(access, address, pc)
    }

    /// Every synchronous EL0 exception, keyed on `ESR_EL1.EC`.
    ///
    /// `None` where no Windows exception describes the condition. A `BRK`
    /// immediate selects between breakpoint, assertion and stack-cookie
    /// failure in the reference by reading the instruction; this layer reads
    /// no user memory and reports the breakpoint.
    /// # C: O(1)
    pub fn sync(esr: u64, address: u64, pc: u64) -> Option<Raised> {
        let raised = match fc::ec(esr) {
            fc::EC_IABT_LOW | fc::EC_DABT_LOW => abort(esr, address, pc),
            fc::EC_UNKNOWN | fc::EC_ILLEGAL_STATE | fc::EC_FP_ACCESS =>
                Raised::simple(STATUS_ILLEGAL_INSTRUCTION, pc),
            fc::EC_PC_ALIGN | fc::EC_SP_ALIGN => Raised::simple(STATUS_DATATYPE_MISALIGNMENT, pc),
            fc::EC_FP_EXC => Raised::simple(STATUS_FLOAT_INVALID_OPERATION, pc),
            fc::EC_BRK => Raised { code: STATUS_BREAKPOINT, flags: 0, address: pc,
                                   parameters: [0; MAX_PARAMETERS], count: 1 },
            fc::EC_SOFTSTEP_LOW => Raised::simple(STATUS_SINGLE_STEP, pc),
            // A hardware breakpoint or watchpoint carries no `BRK` immediate
            // to decode, and the reference reports the unrecognised debug
            // trap as an illegal instruction rather than inventing one.
            fc::EC_BREAKPT_LOW | fc::EC_WATCHPT_LOW => Raised::simple(STATUS_ILLEGAL_INSTRUCTION, pc),
            _ => return None,
        };
        Some(raised)
    }
}

/// Report one classified hardware exception through the Windows personality
/// instead of the POSIX signal, and answer whether that happened.
///
/// A Windows thread that faults must reach its own exception dispatcher, and
/// must reach it FIRST: its `__try`/`__except` probes depend on the exception
/// arriving before any signal disposition is touched. This is the only
/// decision about WHERE an unresolved user fault is reported; the fault
/// funnel asks once and reports the signal when the answer is no.
///
/// `false` for a thread with no NT personality, for a condition no Windows
/// exception describes, and for a thread ALREADY holding an exception — a
/// fault taken while one is being dispatched is not queued behind it, because
/// the dispatcher would then see neither.
/// # C: O(1)
pub fn publish_for_current(raised: Option<Raised>) -> bool {
    let Some(raised) = raised else { return false; };
    let Some(current) = crate::current() else { return false; };
    if !current.is_nt_personality() { return false; }
    current.nt_exception.publish(super::Pending::from_hardware(raised.record())).is_ok()
}

#[cfg(test)]
#[path = "fault/tests.rs"]
mod tests;
