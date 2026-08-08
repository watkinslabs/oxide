// Why a user fault could not be resolved -> which signal userspace is told.
//
// The architecture fault vectors classify the HARDWARE cause (absent page vs
// protection violation vs protection key) and that is all the CPU status
// register can say. It cannot say whether a mapping existed at all: an address
// with no VMA and an address whose file-backed page could not be read out of
// its backing store raise the identical `#PF` / data abort. Only the resolver
// knows which happened, so the resolver's failure reason — not the error code —
// picks the signal:
//
//   * no mapping, or a mapping that forbids the access  -> SIGSEGV, and the
//     hardware's own si_code (SEGV_MAPERR / SEGV_ACCERR / SEGV_PKUERR) is the
//     right one, because in that case the hardware and the resolver agree.
//   * a mapping whose backing could not supply the page -> SIGBUS/BUS_ADRERR.
//     Userspace mmap's a file, touches it, and the read fails: the mapping is
//     valid, the memory behind it is not. Reporting SIGSEGV here tells a crash
//     reporter the program dereferenced garbage, which is a lie.
//   * out of memory -> no signal at all. Userspace resumes and re-takes the
//     fault; whatever the memory-pressure path decided (a fatal signal on the
//     chosen victim) is what ends the process, and if pressure was relieved the
//     retry succeeds.
//   * an explicit retry request -> no signal, re-take the fault.
//
// Ungated on purpose: this is the decision, and it is `cargo test -p vmm`
// provable. The fault entry in `mm-pmm` is target-gated, so a decision written
// there could never be tested at all. ONE mapping serves both architectures —
// each arch supplies its hardware classification and consumes the answer.

use hal::fault_class::FaultSignal;
use hal::siginfo::code;

use crate::Error;

/// SIGBUS, matching the classifier's own private signo table in `hal`.
const SIGBUS: u8 = 7;

/// Why the resolver refused a user fault, in the terms the reference reports
/// back from its fault handler to the architecture entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FaultFailure {
    /// No mapping covers the address, or the mapping forbids this access.
    BadArea,
    /// A mapping covers the address but its backing could not supply the page.
    BusError,
    /// The fill could not obtain memory.
    Oom,
    /// The resolver asks for the faulting instruction to be re-run.
    Retake,
}

/// Classify one resolver error.
///
/// `Fault` is the userfaultfd arm: a monitor that cannot resolve the address
/// (a dead context, a queue that refused the message) leaves a valid mapping
/// with no page behind it — the same shape as a failed fill, and the same
/// signal.
///
/// `NotImplemented` is a backing with no fault operation. Same shape again:
/// the mapping is real, nothing can materialise the page.
/// # C: O(1)
pub fn failure_of(err: Error) -> FaultFailure {
    match err {
        Error::Inval | Error::Perm | Error::Access => FaultFailure::BadArea,
        Error::Io | Error::Fault | Error::NotImplemented => FaultFailure::BusError,
        Error::NoMem => FaultFailure::Oom,
        Error::Again => FaultFailure::Retake,
    }
}

/// The signal a failure reports, given the hardware classification `arch` the
/// fault vector produced for this trap.
///
/// `None` means "queue nothing and resume userspace" — the faulting
/// instruction runs again.
/// # C: O(1)
pub fn signal_for(failure: FaultFailure, arch: FaultSignal) -> Option<FaultSignal> {
    match failure {
        FaultFailure::BadArea  => Some(arch),
        FaultFailure::BusError => Some(FaultSignal { signo: SIGBUS, code: code::BUS_ADRERR }),
        FaultFailure::Oom | FaultFailure::Retake => None,
    }
}

/// Both steps at once, for a fault vector that holds a resolver error and its
/// own hardware classification.
/// # C: O(1)
pub fn signal_of(err: Error, arch: FaultSignal) -> Option<FaultSignal> {
    signal_for(failure_of(err), arch)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SIGSEGV, per the classifier's signo table.
    const SIGSEGV: u8 = 11;

    fn maperr() -> FaultSignal { FaultSignal { signo: SIGSEGV, code: code::SEGV_MAPERR } }
    fn accerr() -> FaultSignal { FaultSignal { signo: SIGSEGV, code: code::SEGV_ACCERR } }
    fn pkuerr() -> FaultSignal { FaultSignal { signo: SIGSEGV, code: code::SEGV_PKUERR } }

    #[test]
    fn failed_file_fill_is_a_bus_error_not_a_segmentation_fault() {
        // The short-read guard in the file fill returns `Io`. A mapping exists
        // and is permitted; the bytes behind it could not be read.
        let s = signal_of(Error::Io, maperr()).expect("a failed fill must raise a signal");
        assert_eq!(s.signo, SIGBUS);
        assert_eq!(s.code, code::BUS_ADRERR);
    }

    #[test]
    fn failed_file_fill_reports_bus_error_whatever_the_hardware_said() {
        // The hardware code is about the PTE, not about the backing store. A
        // failed fill on a protection fault is still a bus error.
        for arch in [maperr(), accerr(), pkuerr()] {
            let s = signal_of(Error::Io, arch).expect("a failed fill must raise a signal");
            assert_eq!((s.signo, s.code), (SIGBUS, code::BUS_ADRERR));
        }
    }

    #[test]
    fn absent_mapping_keeps_the_hardware_classification() {
        // No VMA / forbidden access: hardware and resolver agree, and the
        // si_code the hardware produced is the one userspace must see.
        assert_eq!(signal_of(Error::Inval, maperr()), Some(maperr()));
        assert_eq!(signal_of(Error::Inval, accerr()), Some(accerr()));
        assert_eq!(signal_of(Error::Perm, accerr()), Some(accerr()));
        assert_eq!(signal_of(Error::Access, accerr()), Some(accerr()));
    }

    #[test]
    fn protection_key_denial_survives_the_mapping() {
        // A key-denied access must keep SEGV_PKUERR so `si_pkey` is filled in.
        assert_eq!(signal_of(Error::Inval, pkuerr()), Some(pkuerr()));
    }

    #[test]
    fn unresolvable_userfault_and_missing_backing_op_are_bus_errors() {
        for e in [Error::Fault, Error::NotImplemented] {
            let s = signal_of(e, maperr()).expect("must raise a signal");
            assert_eq!((s.signo, s.code), (SIGBUS, code::BUS_ADRERR));
        }
    }

    #[test]
    fn out_of_memory_raises_no_signal_and_re_takes_the_fault() {
        assert_eq!(failure_of(Error::NoMem), FaultFailure::Oom);
        assert_eq!(signal_of(Error::NoMem, maperr()), None);
    }

    #[test]
    fn explicit_retry_raises_no_signal() {
        assert_eq!(failure_of(Error::Again), FaultFailure::Retake);
        assert_eq!(signal_of(Error::Again, maperr()), None);
    }

    #[test]
    fn every_resolver_error_is_classified_deliberately() {
        // A new `Error` variant must be given a failure class here, not fall
        // into whichever arm happens to be last.
        let all = [Error::NotImplemented, Error::NoMem, Error::Inval, Error::Fault,
                   Error::Perm, Error::Again, Error::Access, Error::Io];
        assert_eq!(all.len(), 8, "Error grew a variant: classify it");
        for e in all { let _ = failure_of(e); }
    }

    #[test]
    fn the_two_fill_failure_reasons_do_not_collapse_together() {
        // The exact regression this module exists to prevent: the file fill
        // returns `NoMem` for an allocation failure and `Io` for an
        // unrecoverable short read, and they are not the same answer.
        assert_ne!(failure_of(Error::Io), failure_of(Error::NoMem));
        assert_ne!(failure_of(Error::Io), failure_of(Error::Inval));
        assert_ne!(signal_of(Error::Io, maperr()), signal_of(Error::Inval, maperr()));
    }
}
