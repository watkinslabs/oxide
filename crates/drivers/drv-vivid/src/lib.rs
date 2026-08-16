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

/// Publish one virtual camera and start producing frames for it.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn init() {
    if tick::register(0) { tick::start(); }
}

#[cfg(test)]
mod tests;
