//! Runtime-to-wake GPE mask transitions.
//!
//! This module owns register state only. Wake policy and `_PRW` device state
//! remain with the canonical ACPI device model.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use super::{Block, Gas, Runtime, read8, runtime, write8};

pub(super) struct WakeMask {
    saved: Vec<AtomicU8>,
    armed: AtomicBool,
}

impl WakeMask {
    pub(super) fn new(blocks: &[Block]) -> Self {
        let count = blocks.iter().map(|block| usize::from(block.registers)).sum();
        Self { saved: (0..count).map(|_| AtomicU8::new(0)).collect(),
            armed: AtomicBool::new(false) }
    }
}

fn wake_bits(block: Block, register: u8, prepared: &impl Fn(u8) -> bool) -> u8 {
    let mut bits = 0;
    for bit_index in 0..8 {
        let gpe = usize::from(block.base) + usize::from(register) * 8 + bit_index;
        let Ok(gpe) = u8::try_from(gpe) else { continue; };
        if prepared(gpe) { bits |= 1 << bit_index; }
    }
    bits
}

fn switch_to_wake(
    runtime: &Runtime,
    mut read: impl FnMut(Gas, u8) -> Option<u8>,
    mut write: impl FnMut(Gas, u8, u8) -> Option<()>,
    prepared: impl Fn(u8) -> bool,
) -> bool {
    let mut saved = 0;
    for block in &runtime.blocks {
        for register in 0..block.registers {
            let Some(enable) = read(block.gas, block.registers + register) else { return false; };
            runtime.wake_mask.saved[saved].store(enable, Ordering::Release);
            saved += 1;
        }
    }
    for block in &runtime.blocks {
        for register in 0..block.registers {
            if write(block.gas, block.registers + register, 0).is_none()
                || write(block.gas, register, u8::MAX).is_none()
                || write(block.gas, block.registers + register,
                    wake_bits(*block, register, &prepared)).is_none() {
                restore(runtime, &mut write);
                return false;
            }
        }
    }
    runtime.wake_mask.armed.store(true, Ordering::Release);
    true
}

fn restore(runtime: &Runtime, write: &mut impl FnMut(Gas, u8, u8) -> Option<()>) -> bool {
    let mut saved = 0;
    let mut complete = true;
    for block in &runtime.blocks {
        for register in 0..block.registers {
            let enable = runtime.wake_mask.saved[saved].load(Ordering::Acquire);
            saved += 1;
            complete &= write(block.gas, block.registers + register, 0).is_some();
            complete &= write(block.gas, block.registers + register, enable).is_some();
        }
    }
    runtime.wake_mask.armed.store(false, Ordering::Release);
    complete
}

/// Disable runtime GPEs, clear stale status, and arm only prepared wake GPEs.
/// # C: O(GPE registers) # Ctx: IRQ-off, single CPU
pub fn arm_wakeup_gpes() -> bool {
    let Some(runtime) = runtime() else { return true; };
    switch_to_wake(runtime, read8,
        |gas, offset, value| write8(gas, offset, value),
        super::super::device_model::fixed_gpe_prepared)
}

/// Restore the exact runtime mask saved at sleep entry. # C: O(GPE registers)
pub fn restore_runtime_gpes() -> bool {
    let Some(runtime) = runtime() else { return true; };
    if !runtime.wake_mask.armed.load(Ordering::Acquire) { return true; }
    restore(runtime, &mut |gas, offset, value| write8(gas, offset, value))
}

#[cfg(test)]
#[path = "gpe_mask/tests.rs"]
mod tests;
