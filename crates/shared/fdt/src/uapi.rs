// Userspace ABI for the device tree: the paths and modes tools expect to find
// it under. These are contract, not layout choices — the kexec loader opens
// `OF_SYSFS_RAW` by name on an arm64 host and gives up when it is absent, and
// the older `/proc/device-tree` ABI is a symlink to `OF_SYSFS_BASE`.
//
// They live here, in the shared crate, because both the sysfs exporter that
// creates them and the procfs symlink that points at them must agree; a
// second copy of the string in either place is a way for the two to drift.

/// Raw flattened blob, byte for byte.
pub const OF_SYSFS_RAW: &str = "/sys/firmware/fdt";
/// Kset directory the unflattened tree hangs under.
pub const OF_SYSFS_KSET: &str = "/sys/firmware/devicetree";
/// The device-tree root node's directory — what `/proc/device-tree` resolves to.
pub const OF_SYSFS_BASE: &str = "/sys/firmware/devicetree/base";
/// Name of the entry under `/proc` that points at `OF_SYSFS_BASE`.
pub const OF_PROC_NAME: &str = "device-tree";

/// Directory name the device-tree root node takes under `OF_SYSFS_KSET`.
pub const OF_ROOT_DIR: &str = "base";
/// Prefix marking a property whose value is withheld from non-root readers.
pub const OF_SECURE_PREFIX: &[u8] = b"security-";

/// Mode of the raw blob attribute: the whole firmware description in one file,
/// so root-only.
pub const OF_RAW_MODE: u16 = 0o400;
/// Mode of an ordinary property file.
pub const OF_PROP_MODE: u16 = 0o444;
/// Mode of a `security-` property file, whose body is withheld as well.
pub const OF_SECURE_PROP_MODE: u16 = 0o400;
