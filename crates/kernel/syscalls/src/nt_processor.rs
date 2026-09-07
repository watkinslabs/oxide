//! Processor identity reported to the calling Windows thread.
//!
//! The service answers with the processor number itself rather than a status,
//! so every value it can produce is a legal answer and there is no error path
//! to encode.

use syscall::nt::NtCall;
#[cfg(target_os = "oxide-kernel")]
use syscall::nt::NtService;

/// Highest processor number this personality reports. The published value is
/// a 32-bit unsigned processor number within the caller's group.
pub const MAX_PROCESSOR_NUMBER: u32 = u32::MAX;

/// Narrow one scheduler CPU identity to the published processor number.
/// # C: O(1)
pub fn processor_number(cpu: u32) -> u32 { cpu.min(MAX_PROCESSOR_NUMBER) }

/// Dispatch the current-processor query. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::NtGetCurrentProcessorNumber { return None; }
    #[cfg(target_arch = "x86_64")]
    let cpu = { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() };
    #[cfg(target_arch = "aarch64")]
    let cpu = { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() };
    Some(processor_number(cpu) as u64)
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn dispatch(_call: NtCall) -> Option<u64> { None }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_processor_is_reported_as_zero() {
        // The published numbering is zero-based within the caller's group, so
        // a single-processor machine must answer zero, never one.
        assert_eq!(processor_number(0), 0);
    }

    #[test]
    fn a_higher_processor_is_reported_verbatim() {
        assert_eq!(processor_number(7), 7);
        assert_eq!(processor_number(MAX_PROCESSOR_NUMBER), MAX_PROCESSOR_NUMBER);
    }
}
