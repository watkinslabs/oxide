// TTY full-stack hosted integration net — T9 (tty-rebuild-plan §3-T9 +
// §4 "Hosted integration"). The "no way it's wrong" net: drive the
// FULLY assembled VT stack and serial stack end-to-end and assert every
// observable surface at once.
//
// This crate has NO production content. The library is intentionally
// empty under `#![no_std]`; the entire harness lives under `#[cfg(test)]`
// with `extern crate std`. `make x86`/`make arm` build only kmain/boot/
// bin, so this leaf crate is never compiled into the kernel.
//
// Surfaces asserted per sequence:
//   - VT stack:  read() stream + `Vc` cell grid + consw render ops.
//   - serial:    read() stream + UART TX bytes.
//   - cross:     the SHARED N_TTY ldisc yields the SAME cooked read()
//                stream on the VT and serial stacks for one input seq.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
