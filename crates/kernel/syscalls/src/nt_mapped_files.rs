//! Whether two addresses are views of one mapped file.
//!
//! The question is asked of the mappings, not of the pages: two addresses in
//! one view answer yes without consulting anything, two views of one file
//! answer yes, and a private allocation is not a view at all and is refused
//! as a conflicting address rather than compared.

use syscall::nt::NtCall;
#[cfg(target_os = "oxide-kernel")]
use syscall::nt::NtService;

pub const STATUS_SUCCESS: u64 = 0x0000_0000;
pub const STATUS_INVALID_ADDRESS: u64 = 0xc000_0141;
pub const STATUS_CONFLICTING_ADDRESSES: u64 = 0xc000_0018;
pub const STATUS_NOT_SAME_DEVICE: u64 = 0xc000_00d4;
pub const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

/// What one address contributes to the comparison.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MappedView {
    /// No mapping covers the address.
    None,
    /// A mapping that is not a view of a file, so it cannot be compared.
    Private,
    /// A view of a file, identified by the backing it shares with its peers.
    File(u64),
}

/// Status the pair of classified addresses produces. The order matters: an
/// absent mapping is reported before a private one, and identity of the view
/// is decided before the backing is consulted at all.
/// # C: O(1)
pub fn compare(first: MappedView, second: MappedView, same_view: bool) -> u64 {
    if first == MappedView::None || second == MappedView::None { return STATUS_INVALID_ADDRESS; }
    if first == MappedView::Private || second == MappedView::Private { return STATUS_CONFLICTING_ADDRESSES; }
    if same_view { return STATUS_SUCCESS; }
    match (first, second) {
        (MappedView::File(left), MappedView::File(right)) if left == right => STATUS_SUCCESS,
        _ => STATUS_NOT_SAME_DEVICE,
    }
}

/// Dispatch the mapped-file identity query. # C: O(log N_vma)
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::NtAreMappedFilesTheSame { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let Some(mm) = cur.clone_mm() else { return Some(STATUS_INVALID_PARAMETER); };
    let first = hal::UserVirtAddr::new(call.args.a0).and_then(|address| mm.find_vma(address));
    let second = hal::UserVirtAddr::new(call.args.a1).and_then(|address| mm.find_vma(address));
    let same_view = match (&first, &second) {
        (Some(first), Some(second)) => first.start == second.start && first.end == second.end,
        _ => false,
    };
    let classify = |vma: &Option<vmm::Vma>| match vma {
        None => MappedView::None,
        Some(vma) => match &vma.backing {
            vmm::VmaBacking::File { backing, .. } =>
                MappedView::File(alloc::sync::Arc::as_ptr(backing) as *const u8 as u64),
            vmm::VmaBacking::KernelBytes { data, .. } =>
                MappedView::File(data.as_ptr() as u64),
            _ => MappedView::Private,
        },
    };
    Some(compare(classify(&first), classify(&second), same_view))
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn dispatch(_call: NtCall) -> Option<u64> { None }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unmapped_address_is_reported_before_anything_else_is_examined() {
        assert_eq!(compare(MappedView::None, MappedView::File(1), false), STATUS_INVALID_ADDRESS);
        assert_eq!(compare(MappedView::File(1), MappedView::None, false), STATUS_INVALID_ADDRESS);
        // Even against a private mapping, the absent address is what is named.
        assert_eq!(compare(MappedView::None, MappedView::Private, false), STATUS_INVALID_ADDRESS);
    }

    #[test]
    fn a_private_allocation_conflicts_rather_than_comparing_unequal() {
        assert_eq!(compare(MappedView::Private, MappedView::File(1), false), STATUS_CONFLICTING_ADDRESSES);
        assert_eq!(compare(MappedView::Private, MappedView::Private, false), STATUS_CONFLICTING_ADDRESSES);
        assert_ne!(STATUS_CONFLICTING_ADDRESSES, STATUS_NOT_SAME_DEVICE);
    }

    #[test]
    fn two_addresses_in_one_view_are_the_same_file() {
        assert_eq!(compare(MappedView::File(1), MappedView::File(1), true), STATUS_SUCCESS);
    }

    #[test]
    fn two_views_of_one_file_are_the_same_file() {
        assert_eq!(compare(MappedView::File(9), MappedView::File(9), false), STATUS_SUCCESS);
    }

    #[test]
    fn views_of_different_files_are_reported_as_different_devices() {
        assert_eq!(compare(MappedView::File(9), MappedView::File(10), false), STATUS_NOT_SAME_DEVICE);
    }

    #[test]
    fn a_private_mapping_is_refused_even_when_both_addresses_share_one_mapping() {
        // Identity of the mapping does not rescue an allocation that is not a
        // view: the reference refuses it before the identity test is reached.
        assert_eq!(compare(MappedView::Private, MappedView::Private, true), STATUS_CONFLICTING_ADDRESSES);
    }
}
