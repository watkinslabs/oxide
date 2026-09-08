use syscall::registry_wire;
pub(crate) const MAGIC: &[u8; 8] = b"OXREG\0\x01\0";
pub(crate) const SUBTREE_MAGIC: &[u8; 8] = b"OXHIVE\0\x01";
pub(crate) const MAX_RECORDS: u32 = 1 << 20;
pub(crate) const MAX_BYTES: u32 = 1 << 24;
pub(crate) const MAX_FRAME: usize = registry_wire::MAX_FRAME;

pub const REG_NOTIFY_CHANGE_LAST_SET: u64 = 0x0000_0004;

/// Longest a committed-looking mutation may sit only in the live store before
/// the owner writes it back. A hive set is not a commit; the lazy writer
/// bounds how much an abrupt loss of the owner can discard, so the per-set
/// whole-database write it replaces is not needed for durability.
pub(crate) const LAZY_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
