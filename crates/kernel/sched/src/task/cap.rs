// Linux capability numbers per `linux/capability.h`. Bit position in
// `cap_effective` / `cap_permitted` / `cap_bounding` masks. v1
// recognises every defined capability slot 0..40; unknowns return
// false from `Creds::has_cap`. Split from task.rs for the 1000-line
// cap (`08§7`).

pub const CHOWN:            u32 = 0;
pub const DAC_OVERRIDE:     u32 = 1;
pub const DAC_READ_SEARCH:  u32 = 2;
pub const FOWNER:           u32 = 3;
pub const FSETID:           u32 = 4;
pub const KILL:             u32 = 5;
pub const SETGID:           u32 = 6;
pub const SETUID:           u32 = 7;
pub const SETPCAP:          u32 = 8;
pub const LINUX_IMMUTABLE:  u32 = 9;
pub const NET_BIND_SERVICE: u32 = 10;
pub const NET_BROADCAST:    u32 = 11;
pub const NET_ADMIN:        u32 = 12;
pub const NET_RAW:          u32 = 13;
pub const IPC_LOCK:         u32 = 14;
pub const IPC_OWNER:        u32 = 15;
pub const SYS_MODULE:       u32 = 16;
pub const SYS_RAWIO:        u32 = 17;
pub const SYS_CHROOT:       u32 = 18;
pub const SYS_PTRACE:       u32 = 19;
pub const SYS_PACCT:        u32 = 20;
pub const SYS_ADMIN:        u32 = 21;
pub const SYS_BOOT:         u32 = 22;
pub const SYS_NICE:         u32 = 23;
pub const SYS_RESOURCE:     u32 = 24;
pub const SYS_TIME:         u32 = 25;
pub const SYS_TTY_CONFIG:   u32 = 26;
pub const MKNOD:            u32 = 27;
pub const LEASE:            u32 = 28;
pub const AUDIT_WRITE:      u32 = 29;
pub const AUDIT_CONTROL:    u32 = 30;
pub const SETFCAP:          u32 = 31;
pub const MAC_OVERRIDE:     u32 = 32;
pub const MAC_ADMIN:        u32 = 33;
pub const SYSLOG:           u32 = 34;
pub const WAKE_ALARM:       u32 = 35;
pub const BLOCK_SUSPEND:    u32 = 36;
pub const AUDIT_READ:       u32 = 37;
pub const PERFMON:          u32 = 38;
pub const BPF:              u32 = 39;
pub const CHECKPOINT_RESTORE: u32 = 40;
