//! Pure AAPCS64 payload and handoff plan. Caller owns executable validation,
//! usercopy, canonical LIFO continuation (including LR), and register commit.
use alloc::vec::Vec;

const MAX_PAYLOAD: usize = 4096;
const STACK_ALIGNMENT: u64 = 16;
const RESULT_SPILL_BYTES: u64 = 16;
const POINTER_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Control { pub pc: u64, pub sp: u64, pub lr: u64 }

#[derive(Debug, Eq, PartialEq)]
pub struct Prepared { pub address: u64, pub stack: u64, pub bytes: Vec<u8> }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handoff { pub saved: Control, pub entry: Control, pub arguments: [u64; 4], pub syscall_result: u64 }

/// Payload is at/above entry SP, with room below it for the return-leg spill.
/// No x64 return slot or shadow space. Offsets relocate within owned bytes.
/// # C: O(payload + relocations)
pub fn prepare(sp: u64, bytes: &[u8], relocations: &[(usize, usize)], user_end: u64) -> Option<Prepared> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD || relocations.len() > MAX_PAYLOAD / POINTER_BYTES
        || sp == 0 || sp > user_end || sp & (STACK_ALIGNMENT - 1) != 0 { return None; }
    let address = sp.checked_sub(bytes.len() as u64 + STACK_ALIGNMENT)? & !(STACK_ALIGNMENT - 1);
    if address.checked_sub(RESULT_SPILL_BYTES)? == 0 { return None; }
    let mut owned = Vec::new(); owned.try_reserve_exact(bytes.len()).ok()?;
    owned.extend_from_slice(bytes);
    for &(offset, target) in relocations {
        if target >= bytes.len() { return None; }
        let end = offset.checked_add(POINTER_BYTES)?;
        owned.get_mut(offset..end)?.copy_from_slice(&address.checked_add(target as u64)?.to_le_bytes());
    }
    Some(Prepared { address, stack: address, bytes: owned })
}

/// Build only after validating the ARM executable entries. Main must copy all
/// bytes and push saved PC/SP/LR + lifecycle Completion before applying entry.
/// Return hwnd from dispatch: ARM SVC epilogue seeds x0 from retval. # C: O(1)
pub fn handoff(saved: Control, payload: &Prepared, wndproc: u64, continuation: u64,
    hwnd: u64, message: u64, wparam: u64, user_end: u64) -> Option<Handoff> {
    if hwnd == 0 || [wndproc, continuation].iter().any(|pc| *pc == 0 || *pc >= user_end || *pc & 3 != 0)
        || saved.sp == 0 || saved.sp > user_end || saved.sp & 15 != 0
        || payload.stack != payload.address || payload.stack & 15 != 0
        || payload.stack < RESULT_SPILL_BYTES || payload.bytes.is_empty() || payload.bytes.len() > MAX_PAYLOAD
        || payload.address.checked_add(payload.bytes.len() as u64)? > saved.sp { return None; }
    Some(Handoff { saved, entry: Control { pc: wndproc, sp: payload.stack, lr: continuation },
        arguments: [hwnd, message, wparam, payload.address], syscall_result: hwnd })
}

#[cfg(test)]
#[path = "aarch64/tests.rs"]
mod tests;
