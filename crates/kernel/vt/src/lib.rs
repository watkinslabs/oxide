// VT data layer (T1 of tty-rebuild-plan; docs/50). Owns the per-VT
// screen buffer (`Vc` = Linux `struct vc_data`) and the ECMA-48/vt102
// emulator (`Emulator` = `vt.c` `do_con_trol`) that mutates it.
//
// Pure logic, host-testable: no rendering, no framebuffer, no I/O. The
// renderer (consw/fbcon) is downstream of `Vc` (T2). The CSI/SGR/ESC
// parser was relocated out of `fbcon::Console` (which conflated emulator
// + renderer) and recast to mutate `Vc` cells instead of blitting pixels.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod palette;
pub mod vc;
pub mod emulator;
pub mod consw;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod consw_tests;

pub use consw::{render, switch, Consw, ScrollDir};
pub use emulator::{CsiState, Emulator};
pub use palette::{rgb, xterm_256, xterm_256_rgb, VGA_PALETTE};
pub use vc::{
    Attr, Cell, Vc, ATTR_BOLD, ATTR_REVERSE, ATTR_UNDERLINE, DEFAULT_BG_RGB, DEFAULT_FG_RGB, N_VT,
    SCROLLBACK_LINES,
};
