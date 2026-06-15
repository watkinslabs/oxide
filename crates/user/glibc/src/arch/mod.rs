// Per-arch sysdeps (docs/59§3): syscall instruction, _start, TLS setup,
// IFUNC variant selection, setjmp/clone asm. G1 ships the syscall shim
// (docs/59§4); the rest fills in at G2/G3/G11.
pub mod syscall;
