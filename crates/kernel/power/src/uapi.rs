// Linux `include/uapi/linux/reboot.h` verbatim. The header spells the MAGIC2
// family in decimal; the hex here is the same bit pattern (672274793 =
// 0x28121969, 85072278 = 0x05121996, 369367448 = 0x16041998, 537993216 =
// 0x20112000) and the tests pin both spellings against each other.

/// `LINUX_REBOOT_MAGIC1`.
pub const LINUX_REBOOT_MAGIC1: u32 = 0xfee1dead;
/// `LINUX_REBOOT_MAGIC2` — 672274793.
pub const LINUX_REBOOT_MAGIC2: u32 = 0x28121969;
/// `LINUX_REBOOT_MAGIC2A` — 85072278.
pub const LINUX_REBOOT_MAGIC2A: u32 = 0x05121996;
/// `LINUX_REBOOT_MAGIC2B` — 369367448.
pub const LINUX_REBOOT_MAGIC2B: u32 = 0x16041998;
/// `LINUX_REBOOT_MAGIC2C` — 537993216.
pub const LINUX_REBOOT_MAGIC2C: u32 = 0x20112000;

/// `LINUX_REBOOT_CMD_RESTART`.
pub const LINUX_REBOOT_CMD_RESTART: u32 = 0x01234567;
/// `LINUX_REBOOT_CMD_HALT`.
pub const LINUX_REBOOT_CMD_HALT: u32 = 0xCDEF0123;
/// `LINUX_REBOOT_CMD_CAD_ON`.
pub const LINUX_REBOOT_CMD_CAD_ON: u32 = 0x89ABCDEF;
/// `LINUX_REBOOT_CMD_CAD_OFF`.
pub const LINUX_REBOOT_CMD_CAD_OFF: u32 = 0x00000000;
/// `LINUX_REBOOT_CMD_POWER_OFF`.
pub const LINUX_REBOOT_CMD_POWER_OFF: u32 = 0x4321FEDC;
/// `LINUX_REBOOT_CMD_RESTART2` — the `arg` pointer carries a command string.
pub const LINUX_REBOOT_CMD_RESTART2: u32 = 0xA1B2C3D4;
/// `LINUX_REBOOT_CMD_SW_SUSPEND`.
pub const LINUX_REBOOT_CMD_SW_SUSPEND: u32 = 0xD000FCE2;
/// `LINUX_REBOOT_CMD_KEXEC`.
pub const LINUX_REBOOT_CMD_KEXEC: u32 = 0x45584543;

/// `sizeof(buffer)` in `SYSCALL_DEFINE4(reboot)` (`kernel/reboot.c:732`): 256
/// bytes, of which `strncpy_from_user` fills at most 255 before the explicit
/// NUL terminator. A longer user string is TRUNCATED, not rejected.
pub const RESTART2_CMD_BYTES: usize = 256;
