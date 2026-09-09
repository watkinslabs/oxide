//! Direct AMD64 callback entry: shadow space, return address and copied input.
use super::Input;
const RETURN_BYTES: u64 = 8;
const SHADOW_BYTES: usize = 32;
const FRAME_BYTES: u64 = 48;
const STACK_ALIGNMENT: u64 = 16;

pub(crate) trait Memory { fn write(&mut self, address: u64, bytes: &[u8]) -> bool; }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Prepared { pub stack: u64, pub argument: u64, pub length: u32 }

/// Write only below the saved stack pointer. A failure must precede installing
/// the callback frame; the caller's register image is untouched. # C: O(input bytes)
pub(crate) fn prepare(memory: &mut impl Memory, stack: u64, input: Input<'_>, continuation: u64) -> Option<Prepared> {
    let (length, owned) = match input { Input::User { length, .. } => (length, 0),
        Input::Record(bytes) => (u32::try_from(bytes.len()).ok()?, bytes.len() as u64) };
    let available = stack.checked_sub(FRAME_BYTES)?.checked_sub(owned)?;
    let stack = (available.checked_sub(RETURN_BYTES)? & !(STACK_ALIGNMENT - 1)).checked_add(RETURN_BYTES)?;
    let argument = match input { Input::User { address, .. } => address, Input::Record(_) => stack.checked_add(FRAME_BYTES)? };
    if !memory.write(stack.checked_add(RETURN_BYTES)?, &[0; SHADOW_BYTES]) { return None; }
    if !memory.write(stack, &continuation.to_le_bytes()) { return None; }
    if let Input::Record(bytes) = input { if !bytes.is_empty() && !memory.write(argument, bytes) { return None; } }
    Some(Prepared { stack, argument, length })
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
