//! Bounded callback-stack payload layout; no persistent callback registry.
use alloc::vec::Vec;
const MAX_PAYLOAD: usize = 4096;
const ALIGNMENT: u64 = 16;
const LINK_AND_SHADOW: u64 = 40;

#[derive(Debug, PartialEq, Eq)]
struct Payload { stack: u64, address: u64, bytes: Vec<u8> }

fn prepare(sp: u64, bytes: &[u8], relocations: &[(usize, usize)]) -> Option<Payload> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD || relocations.len() > MAX_PAYLOAD / 8 { return None; }
    let address = sp.checked_sub(bytes.len() as u64 + ALIGNMENT)? & !(ALIGNMENT - 1);
    let stack = address.checked_sub(LINK_AND_SHADOW)?;
    let mut owned = Vec::new(); owned.try_reserve_exact(bytes.len()).ok()?;
    owned.extend_from_slice(bytes);
    for &(offset, target) in relocations {
        if target >= bytes.len() { return None; }
        let end = offset.checked_add(8)?;
        owned.get_mut(offset..end)?.copy_from_slice(&address.checked_add(target as u64)?.to_le_bytes());
    }
    Some(Payload { stack, address, bytes: owned })
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
#[path = "wndproc_payload/x86.rs"]
mod kernel;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) use kernel::begin;

#[cfg(all(target_os = "oxide-kernel", not(target_arch = "x86_64")))]
pub(crate) fn begin(_: u64, _: u64, _: u64, _: u64, _: &[u8], _: &[(usize, usize)], _: sched::nt_callback::Completion) -> Result<u64, u64> {
    // The current synthetic PE WndProc continuation has an AMD64 instruction ABI.
    // Never branch an ARM user frame into that incompatible continuation.
    Err(0xc000_00bb)
}

#[cfg(test)]
#[path = "wndproc_payload/tests.rs"]
mod tests;
