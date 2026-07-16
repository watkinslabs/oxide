// /proc/cmdline backed by the kernel's boot-cmdline slot.
//
// `crate::hooks::cmdline` returns the bytes the bootloader passed
// (Limine `cmdline` on x86, FDT `/chosen/bootargs` on aarch64) or an
// arch-default until those parsers land.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

const PROC_CMDLINE_INO: Ino = crate::ids::CMDLINE;

/// Body builder for `/proc/cmdline` — the bootloader-passed cmdline bytes.
/// # C: O(len)
fn body() -> Vec<u8> { crate::hooks::cmdline().to_vec() }

/// `/proc/cmdline` inode (KEYSTONE struct-`Inode`). # C: O(1)
pub fn make_proc_cmdline() -> InodeRef { crate::dyn_file::make_gen_file(PROC_CMDLINE_INO, body) }
