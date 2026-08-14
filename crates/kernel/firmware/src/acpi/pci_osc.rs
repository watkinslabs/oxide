//! PCI root _OSC capability and ownership negotiation.

/// PCI host-bridge _OSC UUID, in AML buffer byte order.
pub(super) const PCI_OSC_UUID: [u8; 16] = [
    0x5b, 0x4d, 0xdb, 0x33, 0xf7, 0x1f, 0x1c, 0x40,
    0x96, 0x57, 0x74, 0x41, 0xc0, 0x3d, 0xd7, 0x66,
];
pub(super) const OSC_QUERY_ENABLE: u32 = 1;
const OSC_REQUEST_ERROR: u32 = 1 << 1;
const OSC_INVALID_UUID: u32 = 1 << 2;
const OSC_INVALID_REVISION: u32 = 1 << 3;
const OSC_CAPABILITY_MASK: u32 = 1 << 4;
const OSC_ERROR_MASK: u32 = OSC_REQUEST_ERROR | OSC_INVALID_UUID | OSC_INVALID_REVISION | OSC_CAPABILITY_MASK;
const OSC_SUPPORT: u32 = (1 << 0) | (1 << 3) | (1 << 4) | (1 << 8);
/// PCI firmware ownership bit for native Advanced Error Reporting.
pub const OSC_PCIE_AER_CONTROL: u32 = 1 << 3;
const OSC_PCIE_CAPABILITY_CONTROL: u32 = 1 << 4;

/// Firmware-granted PCI root ownership retained with its root context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciOscControl { pub support: u32, pub control: u32 }

/// One query-control exchange could not establish PCI root ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OscError { Evaluate, QueryError, InvalidUuid }

/// Negotiate the PCIe capability and native AER ownership bits consumed by
/// the PCI root owner. Hotplug, PME, LTR, and DPC stay unrequested until
/// their owners exist. # C: O(1)
pub(super) fn negotiate<E>(mut eval: impl FnMut([u32; 3]) -> Result<[u32; 3], E>) -> Result<PciOscControl, OscError> {
    let query = [OSC_QUERY_ENABLE, OSC_SUPPORT, OSC_PCIE_CAPABILITY_CONTROL | OSC_PCIE_AER_CONTROL];
    let returned = eval(query).map_err(|_| OscError::Evaluate)?;
    let errors = returned[0] & OSC_ERROR_MASK & !OSC_CAPABILITY_MASK;
    if errors & OSC_INVALID_UUID != 0 { return Err(OscError::InvalidUuid); }
    if errors != 0 { return Err(OscError::QueryError); }
    let support = query[1] & returned[1];
    let control = query[2] & returned[2];
    if control & OSC_PCIE_CAPABILITY_CONTROL == 0 { return Ok(PciOscControl { support, control: 0 }); }
    let returned = eval([0, support, control]).map_err(|_| OscError::Evaluate)?;
    if returned[0] & OSC_INVALID_UUID != 0 { return Err(OscError::InvalidUuid); }
    Ok(PciOscControl { support, control: control & returned[2] })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_prunes_then_control_claims_native_aer() {
        let mut calls = [[0; 3]; 2];
        let mut count = 0;
        let result = negotiate(|input| {
            calls[count] = input; count += 1;
            Ok::<_, ()>(if count == 1 { [OSC_CAPABILITY_MASK, OSC_SUPPORT, OSC_PCIE_CAPABILITY_CONTROL | OSC_PCIE_AER_CONTROL] }
                else { [0, OSC_SUPPORT, OSC_PCIE_CAPABILITY_CONTROL | OSC_PCIE_AER_CONTROL] })
        });
        assert_eq!(result, Ok(PciOscControl { support: OSC_SUPPORT, control: OSC_PCIE_CAPABILITY_CONTROL | OSC_PCIE_AER_CONTROL }));
        assert_eq!(count, 2);
        assert_eq!(calls[0], [OSC_QUERY_ENABLE, OSC_SUPPORT, OSC_PCIE_CAPABILITY_CONTROL | OSC_PCIE_AER_CONTROL]);
        assert_eq!(calls[1], [0, OSC_SUPPORT, OSC_PCIE_CAPABILITY_CONTROL | OSC_PCIE_AER_CONTROL]);
    }

    #[test]
    fn query_failure_never_sends_control() {
        let mut count = 0;
        let result = negotiate(|_| { count += 1; Ok::<_, ()>([OSC_REQUEST_ERROR, 0, 0]) });
        assert_eq!(result, Err(OscError::QueryError));
        assert_eq!(count, 1);
    }

    #[test]
    fn invalid_uuid_rejects_the_exchange() {
        assert_eq!(negotiate(|_| Ok::<_, ()>([OSC_INVALID_UUID, 0, 0])), Err(OscError::InvalidUuid));
    }

    #[test]
    fn ungranted_query_control_never_sends_control() {
        let mut count = 0;
        let result = negotiate(|_| { count += 1; Ok::<_, ()>([0, OSC_SUPPORT, 0]) });
        assert_eq!(result, Ok(PciOscControl { support: OSC_SUPPORT, control: 0 }));
        assert_eq!(count, 1);
    }

    #[test]
    fn control_errors_preserve_only_returned_ownership() {
        let mut count = 0;
        let result = negotiate(|_| {
            count += 1;
            Ok::<_, ()>(if count == 1 { [0, OSC_SUPPORT, OSC_PCIE_CAPABILITY_CONTROL] }
                else { [OSC_REQUEST_ERROR, OSC_SUPPORT, 0] })
        });
        assert_eq!(result, Ok(PciOscControl { support: OSC_SUPPORT, control: 0 }));
    }
}
