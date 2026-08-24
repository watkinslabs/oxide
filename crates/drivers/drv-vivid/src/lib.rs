#![no_std]
extern crate alloc;

// A virtual video-capture device.
//
// A machine with no camera hardware still presents `/dev/video0`, producing a
// colour-bar test pattern through the same buffer queue, controls and events
// a real camera would. That is what makes the capture path exercisable on a
// virtual machine, and what gives a desktop's camera panel something to show.
//
// Module manifest:
// - `tpg`: the test-pattern generator — pure pixel arithmetic.
// - `tables`: the formats, sizes, intervals, inputs and controls reported.
// - `device`: the transport state and the frame pacing.
// - `tick`: registration and the periodic producer (kernel only).
// - `tests`: hosted tests for the pattern and the pacing.

pub mod tpg;
pub mod tables;
pub mod device;

#[cfg(target_os = "oxide-kernel")]
pub mod tick;

pub use device::Vivid;

/// Tell the frame producer a camera started or stopped. Outside the kernel
/// there is no producer, so the count is not kept.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn note_streaming(started: bool) { tick::note_streaming(started); }

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn note_streaming(_started: bool) {}

/// Publish the requested number of independent virtual cameras and start the
/// shared producer when at least one registration succeeds. This is the
/// Linux Vivid `n_devs` module parameter boundary: each instance owns its own
/// queue, controls, format and frame sequence.
/// # C: O(count)
#[cfg(target_os = "oxide-kernel")]
pub fn init_instances(count: u32) {
    let mut registered = false;
    for index in 0..count {
        registered |= tick::register(index);
    }
    if registered { tick::start(); }
}

/// Publish the default single Vivid instance.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn init() {
    init_instances(1);
}

#[cfg(test)]
mod tests;
