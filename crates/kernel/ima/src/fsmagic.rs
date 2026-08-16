// Filesystem magic numbers the built-in policies name. A wrong value here is a
// pseudo filesystem that stops being excluded — the measurement log then fills
// with entries for files that were never meant to be measured.

pub const PROC: u64 = 0x9fa0;
pub const SYSFS: u64 = 0x62656572;
pub const DEBUGFS: u64 = 0x64626720;
pub const TMPFS: u64 = 0x01021994;
pub const RAMFS: u64 = 0x858458f6;
pub const DEVPTS: u64 = 0x1cd1;
pub const BINFMTFS: u64 = 0x42494e4d;
pub const SECURITYFS: u64 = 0x73636673;
pub const SELINUXFS: u64 = 0xf97cff8c;
pub const SMACKFS: u64 = 0x43415d53;
pub const CGROUP: u64 = 0x27e0eb;
pub const CGROUP2: u64 = 0x63677270;
pub const NSFS: u64 = 0x6e736673;
pub const EFIVARFS: u64 = 0xde5e81e4;
pub const EXT4: u64 = 0xEF53;
pub const OVERLAYFS: u64 = 0x794c7630;
