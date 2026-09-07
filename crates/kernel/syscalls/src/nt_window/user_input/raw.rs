//! Raw-input device registration for the calling NT process.
use alloc::vec::Vec;
use ipc::win32_window::rawinput::{RawInputError, RawRegistration};
use super::super::owner::{with_state, with_state_mut};

/// # C: O(N_nt_processes + N_registrations)
pub(crate) fn registered_raw_input_for_current() -> Vec<RawRegistration> {
    with_state(|state| state.raw_input_devices().to_vec()).unwrap_or_default()
}

/// # C: O(N_nt_processes + N_batch * N_registrations)
pub(crate) fn register_raw_input_for_current(batch: &[RawRegistration]) -> Result<(), RawInputError> {
    with_state_mut(|state| state.register_raw_input(batch)).unwrap_or(Err(RawInputError::NoMemory))
}
