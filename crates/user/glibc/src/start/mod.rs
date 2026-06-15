//! start — csu / process entry (docs/59§3, §6 G2). crt1-equivalent
//! `_start` (asm) → `__libc_start_main` → `main` → `exit`. Stack-protector
//! guard + handler. C-ABI exports gated `freestanding`; inner helpers
//! always built so the hosted oracle can test them.
pub mod auxv;
pub mod entry;
pub mod libc_start_main;
pub mod stack_guard;
