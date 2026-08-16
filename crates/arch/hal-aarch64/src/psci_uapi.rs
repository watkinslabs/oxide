// PSCI ABI numbers and status decoding per ARM DEN 0022 (Power State
// Coordination Interface).
//
// Deliberately UNGATED: every value and every decode here is a pure decision a
// hosted test must be able to fail on. `psci.rs` carries the conduit asm and is
// `target_arch = "aarch64"`-gated, so a `#[cfg(test)]` block there compiles out
// on a hosted x86 run and reports "ok" having built nothing (`docs/53`, and
// CLAUDE.md's phantom-test rule).

/// SMC32 function-ID base. Every PSCI function ID is this plus an index, with
/// the 64-bit calling convention selecting [`PSCI_FN_64BIT`].
pub const PSCI_FN_BASE_32: u32 = 0x8400_0000;

/// Bit that selects the SMC64 calling convention for a PSCI function ID.
pub const PSCI_FN_64BIT: u32 = 0x4000_0000;

/// Build an SMC32 PSCI function ID from its index.
/// # C: O(1)
pub const fn psci_fn32(index: u32) -> u32 { PSCI_FN_BASE_32 + index }

/// Build an SMC64 PSCI function ID from its index.
/// # C: O(1)
pub const fn psci_fn64(index: u32) -> u32 { PSCI_FN_BASE_32 + PSCI_FN_64BIT + index }

/// Function indexes, in the order the interface assigns them.
const IDX_VERSION:        u32 = 0;
const IDX_CPU_OFF:        u32 = 2;
const IDX_CPU_ON:         u32 = 3;
const IDX_AFFINITY_INFO:  u32 = 4;
const IDX_SYSTEM_OFF:     u32 = 8;
const IDX_SYSTEM_RESET:   u32 = 9;
const IDX_PSCI_FEATURES:  u32 = 10;
const IDX_SYSTEM_SUSPEND: u32 = 14;

/// `PSCI_VERSION`. Present from PSCI 0.2 onwards.
pub const PSCI_VERSION: u32 = psci_fn32(IDX_VERSION);
/// `CPU_OFF`.
pub const PSCI_CPU_OFF: u32 = psci_fn32(IDX_CPU_OFF);
/// `CPU_ON` (SMC64).
pub const PSCI_CPU_ON_64: u32 = psci_fn64(IDX_CPU_ON);
/// `AFFINITY_INFO` (SMC64).
pub const PSCI_AFFINITY_INFO_64: u32 = psci_fn64(IDX_AFFINITY_INFO);
/// `SYSTEM_OFF`. The terminal power-down transition (`32§5`).
pub const PSCI_SYSTEM_OFF: u32 = psci_fn32(IDX_SYSTEM_OFF);
/// `SYSTEM_RESET`. The terminal reset transition (`32§5`).
pub const PSCI_SYSTEM_RESET: u32 = psci_fn32(IDX_SYSTEM_RESET);
/// `PSCI_FEATURES`. Added in PSCI 1.0; the discovery call every optional
/// function is gated on.
pub const PSCI_FEATURES: u32 = psci_fn32(IDX_PSCI_FEATURES);
/// `SYSTEM_SUSPEND` (SMC64). Added in PSCI 1.0; the `mem` mechanism of
/// `32a§9`. Arguments: physical resume entry point, context identifier.
pub const PSCI_SYSTEM_SUSPEND_64: u32 = psci_fn64(IDX_SYSTEM_SUSPEND);

/// Status codes returned in x0.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PsciStatus {
    Success           = 0,
    NotSupported      = -1,
    InvalidParameters = -2,
    Denied            = -3,
    AlreadyOn         = -4,
    OnPending         = -5,
    InternalFailure   = -6,
    NotPresent        = -7,
    Disabled          = -8,
    InvalidAddress    = -9,
    Other             = -100,
}

/// Raw value of [`PsciStatus::NotSupported`] — the one code with meaning at the
/// `PSCI_FEATURES` boundary, where anything else means "implemented".
pub const PSCI_RET_NOT_SUPPORTED: i64 = PsciStatus::NotSupported as i64;

/// Decode a status word into the named code.
/// # C: O(1)
pub fn decode_status(raw: i32) -> PsciStatus {
    match raw {
         0 => PsciStatus::Success,
        -1 => PsciStatus::NotSupported,
        -2 => PsciStatus::InvalidParameters,
        -3 => PsciStatus::Denied,
        -4 => PsciStatus::AlreadyOn,
        -5 => PsciStatus::OnPending,
        -6 => PsciStatus::InternalFailure,
        -7 => PsciStatus::NotPresent,
        -8 => PsciStatus::Disabled,
        -9 => PsciStatus::InvalidAddress,
        _  => PsciStatus::Other,
    }
}

/// Shift of the major field in a `PSCI_VERSION` result.
pub const PSCI_VERSION_MAJOR_SHIFT: u32 = 16;
/// Mask of the minor field in a `PSCI_VERSION` result.
pub const PSCI_VERSION_MINOR_MASK: u32 = (1 << PSCI_VERSION_MAJOR_SHIFT) - 1;

/// Encode a `PSCI_VERSION` result. # C: O(1)
pub const fn psci_version(major: u32, minor: u32) -> u32 {
    (major << PSCI_VERSION_MAJOR_SHIFT) | (minor & PSCI_VERSION_MINOR_MASK)
}

/// Major field of a `PSCI_VERSION` result. # C: O(1)
pub const fn version_major(ver: u32) -> u32 { ver >> PSCI_VERSION_MAJOR_SHIFT }

/// Minor field of a `PSCI_VERSION` result. # C: O(1)
pub const fn version_minor(ver: u32) -> u32 { ver & PSCI_VERSION_MINOR_MASK }

/// The version that introduced `PSCI_FEATURES` and `SYSTEM_SUSPEND`. Below it
/// neither call exists, so a discovery attempt is not merely unsupported — the
/// function ID means nothing and the result cannot be trusted.
pub const PSCI_VERSION_1_0: u32 = psci_version(1, 0);

#[cfg(test)]
#[path = "psci_uapi/tests.rs"]
mod tests;
