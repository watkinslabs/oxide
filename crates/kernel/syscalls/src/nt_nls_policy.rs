//! Which out-parameters the locale-mapping services require.
//!
//! Two services hand back the same mapping: the runtime library entry, which
//! caches it, and the initialisation entry beneath it. They differ only in
//! whether the caller must supply somewhere to put the mapped extent, so the
//! rule lives here rather than being written twice.

/// The locale the mapping describes. The runtime reads it back as the
/// system's own locale identifier.
pub const SYSTEM_LCID: u32 = 0x0409;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

/// Whether a caller must supply somewhere to store the mapped extent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SizeArgument { Required, Optional }

/// Admit the three out-parameters, reporting where the extent goes. The
/// mapping address and the locale are always written, so neither may be null;
/// the extent is written only where the caller asked for it.
/// # C: O(1)
pub fn admit_arguments(pointer: u64, lcid: u64, size: u64, extent: SizeArgument)
    -> Result<Option<u64>, u64> {
    if pointer == 0 || lcid == 0 { return Err(STATUS_INVALID_PARAMETER); }
    match (size, extent) {
        (0, SizeArgument::Required) => Err(STATUS_INVALID_PARAMETER),
        (0, SizeArgument::Optional) => Ok(None),
        (size, _) => Ok(Some(size)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mapping_address_and_locale_are_never_optional() {
        for extent in [SizeArgument::Required, SizeArgument::Optional] {
            assert_eq!(admit_arguments(0, 0x1000, 0x1008, extent), Err(STATUS_INVALID_PARAMETER));
            assert_eq!(admit_arguments(0x1000, 0, 0x1008, extent), Err(STATUS_INVALID_PARAMETER));
        }
    }

    #[test]
    fn a_service_that_demands_the_extent_refuses_a_missing_one() {
        assert_eq!(admit_arguments(0x1000, 0x1008, 0, SizeArgument::Required), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn a_service_that_does_not_demand_the_extent_accepts_a_missing_one() {
        // The initialisation entry never dereferences the extent argument, so
        // a caller is entitled to omit it; refusing would fail a legal call.
        assert_eq!(admit_arguments(0x1000, 0x1008, 0, SizeArgument::Optional), Ok(None));
    }

    #[test]
    fn a_supplied_extent_is_written_whichever_service_asked() {
        assert_eq!(admit_arguments(0x1000, 0x1008, 0x1010, SizeArgument::Required), Ok(Some(0x1010)));
        assert_eq!(admit_arguments(0x1000, 0x1008, 0x1010, SizeArgument::Optional), Ok(Some(0x1010)));
    }

    #[test]
    fn the_system_locale_is_the_one_the_runtime_reads_back() {
        assert_eq!(SYSTEM_LCID, 0x0409);
    }
}
