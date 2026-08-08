//! Path-sensitive verifier state storage.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::super::VerifyError;

pub(super) enum StateSet<T> {
    Empty,
    One(T),
    Many(Vec<T>),
}

impl<T: Copy + Eq> StateSet<T> {
    fn insert(&mut self, value: T) -> Result<bool, VerifyError> {
        match self {
            Self::Empty => {
                *self = Self::One(value);
                Ok(true)
            }
            Self::One(old) if *old == value => Ok(false),
            Self::One(old) => {
                let first = *old;
                let mut values = Vec::new();
                values.try_reserve_exact(2).map_err(|_| VerifyError::NoMemory)?;
                values.push(first);
                values.push(value);
                *self = Self::Many(values);
                Ok(true)
            }
            Self::Many(values) if values.contains(&value) => Ok(false),
            Self::Many(values) => {
                values.try_reserve(1).map_err(|_| VerifyError::NoMemory)?;
                values.push(value);
                Ok(true)
            }
        }
    }
}

/// # C: O(len)
pub(super) fn state_sets<T>(len: usize) -> Result<Vec<StateSet<T>>, VerifyError> {
    let mut states = Vec::new();
    states.try_reserve_exact(len).map_err(|_| VerifyError::NoMemory)?;
    states.resize_with(len, || StateSet::Empty);
    Ok(states)
}

/// # C: O(states at pc)
pub(super) fn enqueue<T: Copy + Eq>(
    states: &mut [StateSet<T>],
    queue: &mut VecDeque<(usize, T)>,
    pc: usize,
    state: T,
) -> Result<(), VerifyError> {
    if !states[pc].insert(state)? { return Ok(()); }
    queue.try_reserve(1).map_err(|_| VerifyError::NoMemory)?;
    queue.push_back((pc, state));
    Ok(())
}
