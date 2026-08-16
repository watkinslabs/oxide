//! The ioctl command numbers, their argument layouts, and the flag words
//! inside them.
//!
//! Every number here is DERIVED from the encoding rule and the argument's own
//! size rather than written down as a literal, because the size is part of the
//! number: a struct that gains a field silently becomes a different command,
//! and a hand-copied constant would keep answering the old one. The tests pin
//! each derived value against the number a caller actually sends.
//!
//! Nothing in this file decides anything. Direction, size, permission and
//! ordering all live beside the code that acts on them.

/// Bits of the command number that carry the ordinal within its type.
pub const IOC_NRBITS: u32 = 8;
/// Bits carrying the owning subsystem's letter.
pub const IOC_TYPEBITS: u32 = 8;
/// Bits carrying the argument's byte size.
pub const IOC_SIZEBITS: u32 = 14;

pub const IOC_NRSHIFT: u32 = 0;
pub const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
pub const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
pub const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

/// No argument travels with the command.
pub const IOC_NONE: u32 = 0;
/// The caller writes the argument; the kernel reads it.
pub const IOC_WRITE: u32 = 1;
/// The kernel writes the argument; the caller reads it.
pub const IOC_READ: u32 = 2;

/// Assemble a command number from its four parts. # C: O(1)
pub const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT) | (ty << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
}

/// A command with no argument. # C: O(1)
pub const fn io(ty: u32, nr: u32) -> u32 { ioc(IOC_NONE, ty, nr, 0) }
/// A command whose argument the kernel writes. # C: O(1)
pub const fn ior(ty: u32, nr: u32, size: u32) -> u32 { ioc(IOC_READ, ty, nr, size) }
/// A command whose argument the caller writes. # C: O(1)
pub const fn iow(ty: u32, nr: u32, size: u32) -> u32 { ioc(IOC_WRITE, ty, nr, size) }
/// A command whose argument travels both ways. # C: O(1)
pub const fn iowr(ty: u32, nr: u32, size: u32) -> u32 {
    ioc(IOC_READ | IOC_WRITE, ty, nr, size)
}

/// The direction bits of a command number. # C: O(1)
pub const fn ioc_dir(cmd: u32) -> u32 { (cmd >> IOC_DIRSHIFT) & 0x3 }
/// The declared argument size of a command number. # C: O(1)
pub const fn ioc_size(cmd: u32) -> u32 { (cmd >> IOC_SIZESHIFT) & ((1 << IOC_SIZEBITS) - 1) }
/// The owning subsystem letter of a command number. # C: O(1)
pub const fn ioc_type(cmd: u32) -> u32 { (cmd >> IOC_TYPESHIFT) & 0xff }
/// The ordinal within the owning subsystem. # C: O(1)
pub const fn ioc_nr(cmd: u32) -> u32 { (cmd >> IOC_NRSHIFT) & 0xff }

/// The letter this filesystem's own commands carry.
pub const MAGIC: u32 = 0xf5;
/// The letter the generic file-attribute and encryption commands carry.
pub const MAGIC_FS: u32 = b'f' as u32;
/// The letter the generic extended-attribute, trim and shutdown commands
/// carry, borrowed from another filesystem so one tool drives both.
pub const MAGIC_XFS: u32 = b'X' as u32;
/// The letter the label commands carry.
pub const MAGIC_LABEL: u32 = 0x94;
/// The letter the inode-version commands carry.
pub const MAGIC_VERSION: u32 = b'v' as u32;

// ---- argument sizes -------------------------------------------------------
// Each is the C structure's size under natural alignment, which is what the
// command number encodes. A mismatch here produces a number no caller sends.

/// `{ u32 sync; u64 start; u64 len; }` — four bytes of padding after `sync`.
pub const GC_RANGE_SIZE: u32 = 24;
/// `{ u64 start; u64 len; }`.
pub const DEFRAGMENT_SIZE: u32 = 16;
/// `{ u32 dst_fd; u64 pos_in; u64 pos_out; u64 len; }` — padded after `dst_fd`.
pub const MOVE_RANGE_SIZE: u32 = 32;
/// `{ u32 dev_num; u32 segments; }`.
pub const FLUSH_DEVICE_SIZE: u32 = 8;
/// `{ u64 start; u64 len; u64 flags; }`.
pub const SECTRIM_RANGE_SIZE: u32 = 24;
/// `{ u8 algorithm; u8 log_cluster_size; }` — byte-aligned, so exactly two.
pub const COMP_OPTION_SIZE: u32 = 2;
/// `{ u64 start; u64 len; u64 minlen; }`.
pub const FSTRIM_RANGE_SIZE: u32 = 24;
/// The generic file-attribute record, thirty-two-bit fields throughout.
pub const FSXATTR_SIZE: u32 = 28;
/// The label buffer both label commands carry.
pub const FSLABEL_MAX: u32 = 256;

pub const U32_SIZE: u32 = 4;
pub const U64_SIZE: u32 = 8;

// ---- this filesystem's own commands --------------------------------------

pub const START_ATOMIC_WRITE: u32 = io(MAGIC, 1);
pub const COMMIT_ATOMIC_WRITE: u32 = io(MAGIC, 2);
pub const START_VOLATILE_WRITE: u32 = io(MAGIC, 3);
pub const RELEASE_VOLATILE_WRITE: u32 = io(MAGIC, 4);
pub const ABORT_ATOMIC_WRITE: u32 = io(MAGIC, 5);
pub const GARBAGE_COLLECT: u32 = iow(MAGIC, 6, U32_SIZE);
pub const WRITE_CHECKPOINT: u32 = io(MAGIC, 7);
pub const DEFRAGMENT: u32 = iowr(MAGIC, 8, DEFRAGMENT_SIZE);
pub const MOVE_RANGE: u32 = iowr(MAGIC, 9, MOVE_RANGE_SIZE);
pub const FLUSH_DEVICE: u32 = iow(MAGIC, 10, FLUSH_DEVICE_SIZE);
pub const GARBAGE_COLLECT_RANGE: u32 = iow(MAGIC, 11, GC_RANGE_SIZE);
pub const GET_FEATURES: u32 = ior(MAGIC, 12, U32_SIZE);
pub const SET_PIN_FILE: u32 = iow(MAGIC, 13, U32_SIZE);
pub const GET_PIN_FILE: u32 = ior(MAGIC, 14, U32_SIZE);
pub const PRECACHE_EXTENTS: u32 = io(MAGIC, 15);
pub const RESIZE_FS: u32 = iow(MAGIC, 16, U64_SIZE);
pub const GET_COMPRESS_BLOCKS: u32 = ior(MAGIC, 17, U64_SIZE);
pub const RELEASE_COMPRESS_BLOCKS: u32 = ior(MAGIC, 18, U64_SIZE);
pub const RESERVE_COMPRESS_BLOCKS: u32 = ior(MAGIC, 19, U64_SIZE);
pub const SEC_TRIM_FILE: u32 = iow(MAGIC, 20, SECTRIM_RANGE_SIZE);
pub const GET_COMPRESS_OPTION: u32 = ior(MAGIC, 21, COMP_OPTION_SIZE);
pub const SET_COMPRESS_OPTION: u32 = iow(MAGIC, 22, COMP_OPTION_SIZE);
pub const DECOMPRESS_FILE: u32 = io(MAGIC, 23);
pub const COMPRESS_FILE: u32 = io(MAGIC, 24);
pub const START_ATOMIC_REPLACE: u32 = io(MAGIC, 25);
pub const GET_DEV_ALIAS_FILE: u32 = ior(MAGIC, 26, U32_SIZE);
pub const IO_PRIO: u32 = iow(MAGIC, 27, U32_SIZE);

/// Shutting the filesystem down, sharing a number with the filesystem the
/// command was borrowed from so one tool drives both.
pub const SHUTDOWN: u32 = ior(MAGIC_XFS, 125, U32_SIZE);

// ---- generic commands this filesystem answers ----------------------------

pub const FS_IOC_GETVERSION: u32 = ior(MAGIC_VERSION, 1, U64_SIZE);
pub const FS_IOC_SETVERSION: u32 = iow(MAGIC_VERSION, 2, U64_SIZE);
pub const FS_IOC_GETFLAGS: u32 = ior(MAGIC_FS, 1, U64_SIZE);
pub const FS_IOC_SETFLAGS: u32 = iow(MAGIC_FS, 2, U64_SIZE);
pub const FS_IOC_FSGETXATTR: u32 = ior(MAGIC_XFS, 31, FSXATTR_SIZE);
pub const FS_IOC_FSSETXATTR: u32 = iow(MAGIC_XFS, 32, FSXATTR_SIZE);
pub const FS_IOC_GETFSLABEL: u32 = ior(MAGIC_LABEL, 49, FSLABEL_MAX);
pub const FS_IOC_SETFSLABEL: u32 = iow(MAGIC_LABEL, 50, FSLABEL_MAX);
pub const FITRIM: u32 = iowr(MAGIC_XFS, 121, FSTRIM_RANGE_SIZE);

// The two oldest encryption commands carry their direction bits INVERTED
// relative to what they do — set reads the caller's buffer while its number
// says read, get writes one while its number says write. The numbers are ABI
// and cannot be corrected, so the direction a caller sends is not usable to
// decide which way the payload travels; `spec` states the real direction.
pub const SET_ENCRYPTION_POLICY: u32 = ior(MAGIC_FS, 19, POLICY_V1_SIZE);
pub const GET_ENCRYPTION_PWSALT: u32 = iow(MAGIC_FS, 20, PWSALT_SIZE);
pub const GET_ENCRYPTION_POLICY: u32 = iow(MAGIC_FS, 21, POLICY_V1_SIZE);
pub const GET_ENCRYPTION_POLICY_EX: u32 = iowr(MAGIC_FS, 22, POLICY_EX_STUB_SIZE);
pub const ADD_ENCRYPTION_KEY: u32 = iowr(MAGIC_FS, 23, ADD_KEY_ARG_SIZE);
pub const REMOVE_ENCRYPTION_KEY: u32 = iowr(MAGIC_FS, 24, REMOVE_KEY_ARG_SIZE);
pub const REMOVE_ENCRYPTION_KEY_ALL_USERS: u32 = iowr(MAGIC_FS, 25, REMOVE_KEY_ARG_SIZE);
pub const GET_ENCRYPTION_KEY_STATUS: u32 = iowr(MAGIC_FS, 26, KEY_STATUS_ARG_SIZE);
pub const GET_ENCRYPTION_NONCE: u32 = ior(MAGIC_FS, 27, FILE_NONCE_SIZE);

pub const ENABLE_VERITY: u32 = iow(MAGIC_FS, 133, VERITY_ENABLE_ARG_SIZE);
pub const MEASURE_VERITY: u32 = iowr(MAGIC_FS, 134, VERITY_DIGEST_HEAD_SIZE);
pub const READ_VERITY_METADATA: u32 = iowr(MAGIC_FS, 135, VERITY_READ_METADATA_SIZE);

// ---- encryption argument layouts -----------------------------------------

/// `{ u8 version; u8 contents_encryption_mode; u8 filenames_encryption_mode;
///    u8 flags; u8 master_key_descriptor[8]; }` — byte-aligned throughout.
pub const POLICY_V1_SIZE: u32 = 12;
/// The same head, then a reserved word and a sixteen-byte key identifier.
pub const POLICY_V2_SIZE: u32 = 24;
/// The salt the password-derivation command exports.
pub const PWSALT_SIZE: u32 = 16;
/// The per-file nonce.
pub const FILE_NONCE_SIZE: u32 = 16;
/// The extended policy query's number encodes only its two-field head plus a
/// one-byte policy union placeholder, not the whole structure.
pub const POLICY_EX_STUB_SIZE: u32 = 9;
/// `{ u64 policy_size; union policy; }` as it travels in memory.
pub const POLICY_EX_ARG_SIZE: u32 = 32;

/// `{ u32 type; u32 __reserved; union { u8 descriptor[8]; u8 identifier[16] }; }`
/// padded out to a fixed forty bytes so both key kinds share one layout.
pub const KEY_SPECIFIER_SIZE: u32 = 40;
/// The specifier, a raw-size word, three reserved words and the key bytes.
pub const ADD_KEY_ARG_SIZE: u32 = 80;
pub const REMOVE_KEY_ARG_SIZE: u32 = 64;
pub const KEY_STATUS_ARG_SIZE: u32 = 128;

/// Offsets inside the add-key argument. The raw key sits PAST the size the
/// command number encodes, so the copy layer fetches it separately.
pub const ADD_KEY_SPECIFIER: usize = 0;
pub const ADD_KEY_RAW_SIZE: usize = 40;
pub const ADD_KEY_KEY_ID: usize = 44;
pub const ADD_KEY_FLAGS: usize = 48;
pub const ADD_KEY_RESERVED: usize = 52;
pub const ADD_KEY_RESERVED_WORDS: usize = 7;
pub const ADD_KEY_RAW: usize = 80;
/// The longest raw key the add-key argument can carry.
pub const MAX_RAW_KEY: usize = 64;
/// The only defined add-key flag: the key is already wrapped by hardware.
pub const ADD_KEY_FLAG_HW_WRAPPED: u32 = 0x0000_0001;

/// Offsets inside the remove-key argument.
pub const REMOVE_KEY_SPECIFIER: usize = 0;
pub const REMOVE_KEY_REMOVAL_STATUS: usize = 40;
pub const REMOVE_KEY_RESERVED: usize = 44;
pub const REMOVE_KEY_RESERVED_WORDS: usize = 5;

/// Offsets inside the key-status argument. Six reserved words separate the
/// specifier the caller supplies from the three the kernel fills in.
pub const KEY_STATUS_SPECIFIER: usize = 0;
pub const KEY_STATUS_RESERVED: usize = 40;
pub const KEY_STATUS_RESERVED_WORDS: usize = 6;
pub const KEY_STATUS_STATUS: usize = 64;
pub const KEY_STATUS_FLAGS: usize = 68;
pub const KEY_STATUS_USER_COUNT: usize = 72;
pub const KEY_STATUS_OUT_RESERVED: usize = 76;
pub const KEY_STATUS_OUT_RESERVED_WORDS: usize = 13;

/// Offsets inside the extended policy query.
pub const POLICY_EX_SIZE_FIELD: usize = 0;
pub const POLICY_EX_POLICY: usize = 8;

/// Offsets inside the key specifier.
pub const SPEC_TYPE: usize = 0;
pub const SPEC_RESERVED: usize = 4;
pub const SPEC_UNION: usize = 8;

/// Key-specifier kinds.
pub const KEY_SPEC_TYPE_DESCRIPTOR: u32 = 1;
pub const KEY_SPEC_TYPE_IDENTIFIER: u32 = 2;

/// Removal outcomes reported back through the remove-key argument.
pub const KEY_REMOVAL_STATUS_FLAG_FILES_BUSY: u32 = 0x01;
pub const KEY_REMOVAL_STATUS_FLAG_OTHER_USERS: u32 = 0x02;

/// Key presence, as the status query reports it.
pub const KEY_STATUS_ABSENT: u32 = 1;
pub const KEY_STATUS_PRESENT: u32 = 2;
pub const KEY_STATUS_INCOMPLETELY_REMOVED: u32 = 3;
/// The status query's only defined flag: the key was added by this user.
pub const KEY_STATUS_FLAG_ADDED_BY_SELF: u32 = 0x01;

// ---- verity argument layouts ---------------------------------------------

/// `{ u32 version; u32 hash_algorithm; u32 block_size; u32 salt_size;
///    u64 salt_ptr; u32 sig_size; u32 __reserved1; u64 sig_ptr;
///    u64 __reserved2[11]; }`.
pub const VERITY_ENABLE_ARG_SIZE: u32 = 128;
pub const VE_VERSION: usize = 0;
pub const VE_HASH_ALGORITHM: usize = 4;
pub const VE_BLOCK_SIZE: usize = 8;
pub const VE_SALT_SIZE: usize = 12;
pub const VE_SALT_PTR: usize = 16;
pub const VE_SIG_SIZE: usize = 24;
pub const VE_RESERVED1: usize = 28;
pub const VE_SIG_PTR: usize = 32;
pub const VE_RESERVED2: usize = 40;
/// The version every caller must set.
pub const VERITY_ENABLE_VERSION: u32 = 1;
/// The longest salt the descriptor can hold.
pub const VERITY_MAX_SALT: usize = 32;
/// The longest built-in signature accepted.
pub const VERITY_MAX_SIGNATURE: usize = 16128;

/// `{ u16 digest_algorithm; u16 digest_size; u8 digest[]; }` — the command
/// number encodes only the fixed head.
pub const VERITY_DIGEST_HEAD_SIZE: u32 = 4;
pub const VD_ALGORITHM: usize = 0;
pub const VD_SIZE: usize = 2;
pub const VD_DIGEST: usize = 4;

/// `{ u64 metadata_type; u64 offset; u64 length; u64 buf_ptr; u64 __reserved; }`.
pub const VERITY_READ_METADATA_SIZE: u32 = 40;
pub const VRM_TYPE: usize = 0;
pub const VRM_OFFSET: usize = 8;
pub const VRM_LENGTH: usize = 16;
pub const VRM_BUF_PTR: usize = 24;
pub const VRM_RESERVED: usize = 32;

/// Metadata kinds the read command can name.
pub const VERITY_METADATA_TYPE_MERKLE_TREE: u64 = 1;
pub const VERITY_METADATA_TYPE_DESCRIPTOR: u64 = 2;
pub const VERITY_METADATA_TYPE_SIGNATURE: u64 = 3;

// ---- shutdown, trim-file and priority flag words -------------------------

pub const GOING_DOWN_FULLSYNC: u32 = 0x0;
pub const GOING_DOWN_METASYNC: u32 = 0x1;
pub const GOING_DOWN_NOSYNC: u32 = 0x2;
pub const GOING_DOWN_METAFLUSH: u32 = 0x3;
pub const GOING_DOWN_NEED_FSCK: u32 = 0x4;
/// One past the last defined shutdown mode.
pub const GOING_DOWN_MAX: u32 = 0x5;

pub const TRIM_FILE_DISCARD: u64 = 0x1;
pub const TRIM_FILE_ZEROOUT: u64 = 0x2;
pub const TRIM_FILE_MASK: u64 = 0x3;

/// The one raised write priority a file can be given.
pub const IOPRIO_WRITE: u32 = 1;
/// One past the last defined priority.
pub const IOPRIO_MAX: u32 = 2;

/// The volume name field holds this many sixteen-bit units on the medium.
pub const MAX_VOLUME_NAME_UNITS: usize = 512;

// The cluster-size bounds and the codec numbers the compress-option commands
// validate against are the format's own, owned by `crate::compress::algo`.
// Restating them here would let the two disagree about which volumes mount.

// ---- generic file-attribute record ---------------------------------------

pub const FSX_XFLAGS: usize = 0;
pub const FSX_EXTSIZE: usize = 4;
pub const FSX_NEXTENTS: usize = 8;
pub const FSX_PROJID: usize = 12;
pub const FSX_COWEXTSIZE: usize = 16;
pub const FSX_PAD: usize = 20;

/// The extended-attribute flags this filesystem can present, in the generic
/// record's own numbering.
pub const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
pub const FS_XFLAG_APPEND: u32 = 0x0000_0010;
pub const FS_XFLAG_NODUMP: u32 = 0x0000_0020;
pub const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
pub const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;

#[cfg(test)]
#[path = "../tests/ioctl/numbers.rs"]
mod tests;
