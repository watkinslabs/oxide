//! Which commands this filesystem answers, and how much of the caller's
//! memory each one moves in which direction.
//!
//! The direction is stated here rather than read off the command number
//! because two of the encryption numbers carry direction bits that contradict
//! what they do, and three of the verity commands name further buffers
//! through pointers INSIDE their payload. A layer that copied by the encoded
//! direction would read the caller's buffer for a query and write it for a
//! set, and would silently ignore every indirect buffer.
//!
//! Answering `None` here means the command is not this filesystem's, which is
//! the only thing that may produce `ENOTTY`. Nothing else in this module
//! invents that errno.

use super::uapi::*;

/// The fixed payload a command moves, and which way. The length is always the
/// size the command number encodes except where the encoded size is only a
/// head; those cases carry the real length.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Payload {
    /// No payload travels; the argument word is unused.
    None,
    /// The layer reads `n` bytes from the caller.
    In(u32),
    /// The layer writes `n` bytes to the caller.
    Out(u32),
    /// The layer reads `n` bytes, then writes the same span back.
    InOut(u32),
}

/// Further caller memory a command names through pointers inside its payload,
/// which the copy layer must follow after the fixed part is in hand.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Indirect {
    /// Everything the command touches is in the fixed payload.
    None,
    /// Read `salt_size` bytes at `salt_ptr` and `sig_size` bytes at `sig_ptr`.
    VerityEnable,
    /// The head declares the caller's digest capacity; the reply is the head
    /// followed by that many digest bytes, written back in place.
    VerityMeasure,
    /// Write up to `length` bytes of the named metadata at `buf_ptr`, and
    /// report the byte count as the command's own result.
    VerityReadMetadata,
    /// A NUL-terminated string of at most [`FSLABEL_MAX`] bytes, which the
    /// layer imports without requiring the whole buffer to be readable.
    LabelString,
    /// An encryption policy, whose length its own first byte decides. The
    /// fixed part is the shorter of the two versions, so it is always
    /// readable; a second version raised the length, and reading the longer
    /// one unconditionally would refuse every caller still sending the
    /// shorter.
    PolicyIn,
    /// The raw key sits past the fixed part, whose `raw_size` field says how
    /// many bytes follow. The command number encodes only the fixed part, so
    /// a layer that copied by the encoded size alone would add a key with no
    /// bytes in it.
    AddKeyRaw,
}

/// How one command's argument travels.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Spec {
    pub payload: Payload,
    pub indirect: Indirect,
}

impl Spec {
    const fn new(payload: Payload, indirect: Indirect) -> Self { Self { payload, indirect } }
}

const fn none() -> Spec { Spec::new(Payload::None, Indirect::None) }
const fn r#in(n: u32) -> Spec { Spec::new(Payload::In(n), Indirect::None) }
const fn out(n: u32) -> Spec { Spec::new(Payload::Out(n), Indirect::None) }
const fn inout(n: u32) -> Spec { Spec::new(Payload::InOut(n), Indirect::None) }

/// How `cmd`'s argument travels, or `None` when the command is not this
/// filesystem's. # C: O(1)
pub fn spec(cmd: u32) -> Option<Spec> {
    Some(match cmd {
        // No argument at all.
        START_ATOMIC_WRITE | START_ATOMIC_REPLACE | COMMIT_ATOMIC_WRITE
        | ABORT_ATOMIC_WRITE | START_VOLATILE_WRITE | RELEASE_VOLATILE_WRITE
        | WRITE_CHECKPOINT | PRECACHE_EXTENTS | DECOMPRESS_FILE | COMPRESS_FILE => none(),

        // A single word the caller supplies.
        GARBAGE_COLLECT | SET_PIN_FILE | IO_PRIO | SHUTDOWN => r#in(U32_SIZE),
        RESIZE_FS => r#in(U64_SIZE),

        // A single word the kernel supplies.
        GET_FEATURES | GET_PIN_FILE | GET_DEV_ALIAS_FILE => out(U32_SIZE),
        GET_COMPRESS_BLOCKS => out(U64_SIZE),
        FS_IOC_GETVERSION => out(U32_SIZE),
        FS_IOC_SETVERSION => r#in(U32_SIZE),
        FS_IOC_GETFLAGS => out(U32_SIZE),
        FS_IOC_SETFLAGS => r#in(U32_SIZE),

        // A word in, a count back out through the same word.
        RELEASE_COMPRESS_BLOCKS | RESERVE_COMPRESS_BLOCKS => out(U64_SIZE),

        // Structures the caller supplies.
        GARBAGE_COLLECT_RANGE => r#in(GC_RANGE_SIZE),
        FLUSH_DEVICE => r#in(FLUSH_DEVICE_SIZE),
        SEC_TRIM_FILE => r#in(SECTRIM_RANGE_SIZE),
        SET_COMPRESS_OPTION => r#in(COMP_OPTION_SIZE),
        FS_IOC_FSSETXATTR => r#in(FSXATTR_SIZE),

        // Structures the kernel supplies.
        GET_COMPRESS_OPTION => out(COMP_OPTION_SIZE),
        FS_IOC_FSGETXATTR => out(FSXATTR_SIZE),
        GET_ENCRYPTION_PWSALT => out(PWSALT_SIZE),
        GET_ENCRYPTION_NONCE => out(FILE_NONCE_SIZE),

        // Structures that travel both ways.
        DEFRAGMENT => inout(DEFRAGMENT_SIZE),
        MOVE_RANGE => inout(MOVE_RANGE_SIZE),
        FITRIM => inout(FSTRIM_RANGE_SIZE),

        // Encryption. The two oldest carry inverted direction bits; the real
        // direction is what is written here.
        SET_ENCRYPTION_POLICY =>
            Spec::new(Payload::In(POLICY_V1_SIZE), Indirect::PolicyIn),
        GET_ENCRYPTION_POLICY => out(POLICY_V1_SIZE),
        GET_ENCRYPTION_POLICY_EX => inout(POLICY_EX_ARG_SIZE),
        ADD_ENCRYPTION_KEY =>
            Spec::new(Payload::InOut(ADD_KEY_ARG_SIZE), Indirect::AddKeyRaw),
        REMOVE_ENCRYPTION_KEY | REMOVE_ENCRYPTION_KEY_ALL_USERS =>
            inout(REMOVE_KEY_ARG_SIZE),
        GET_ENCRYPTION_KEY_STATUS => inout(KEY_STATUS_ARG_SIZE),

        // Verity, each naming further buffers of its own.
        ENABLE_VERITY => Spec::new(Payload::In(VERITY_ENABLE_ARG_SIZE), Indirect::VerityEnable),
        MEASURE_VERITY =>
            Spec::new(Payload::InOut(VERITY_DIGEST_HEAD_SIZE), Indirect::VerityMeasure),
        READ_VERITY_METADATA => Spec::new(Payload::In(VERITY_READ_METADATA_SIZE),
                                          Indirect::VerityReadMetadata),

        // The label, whose set form is a string rather than a fixed buffer.
        FS_IOC_GETFSLABEL => out(FSLABEL_MAX),
        FS_IOC_SETFSLABEL => Spec::new(Payload::In(FSLABEL_MAX), Indirect::LabelString),

        _ => return None,
    })
}

/// Which of the three dispatch stages reaches a command.
///
/// A command has exactly ONE owner. The generic stage runs first and answers
/// the file-attribute set for every filesystem; the typed file-operations
/// stage answers the version, label and trim set; only what neither claims
/// reaches this filesystem's own raw handler. A raw handler that also claimed
/// a command an earlier stage owns would shadow it — the same defect that
/// once made every anonymous descriptor answer a filesystem's errno.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Stage {
    /// The generic stage, reaching the inode's file-attribute operations.
    Generic,
    /// The typed file-operations stage, reaching `unlocked_ioctl`.
    FileIoctl,
    /// This filesystem's own handler, reached with the raw command number.
    Raw,
}

/// Which stage owns `cmd`, or `None` when this filesystem does not answer it.
/// # C: O(1)
pub fn stage(cmd: u32) -> Option<Stage> {
    spec(cmd)?;
    Some(match cmd {
        FS_IOC_GETFLAGS | FS_IOC_SETFLAGS | FS_IOC_FSGETXATTR | FS_IOC_FSSETXATTR =>
            Stage::Generic,
        FS_IOC_GETVERSION | FS_IOC_SETVERSION | FS_IOC_GETFSLABEL | FS_IOC_SETFSLABEL
        | FITRIM => Stage::FileIoctl,
        _ => Stage::Raw,
    })
}

/// Does this filesystem's RAW handler answer `cmd`? False both for a command
/// it does not answer at all and for one an earlier stage owns. # C: O(1)
pub fn owns(cmd: u32) -> bool { stage(cmd) == Some(Stage::Raw) }

/// Does this filesystem answer `cmd` at any stage? # C: O(1)
pub fn answers(cmd: u32) -> bool { spec(cmd).is_some() }

/// The fixed byte count a command's payload occupies, zero when none travels.
/// # C: O(1)
pub fn payload_len(cmd: u32) -> u32 {
    match spec(cmd).map(|s| s.payload) {
        Some(Payload::In(n)) | Some(Payload::Out(n)) | Some(Payload::InOut(n)) => n,
        _ => 0,
    }
}

/// Does the layer have to read the caller's payload before dispatching?
/// # C: O(1)
pub fn reads_payload(cmd: u32) -> bool {
    matches!(spec(cmd).map(|s| s.payload), Some(Payload::In(_)) | Some(Payload::InOut(_)))
}

/// Does the layer have to write a payload back afterwards? # C: O(1)
pub fn writes_payload(cmd: u32) -> bool {
    matches!(spec(cmd).map(|s| s.payload), Some(Payload::Out(_)) | Some(Payload::InOut(_)))
}

/// Is `cmd` one of the argument-free commands whose argument word carries no
/// meaning at all? # C: O(1)
pub fn takes_no_argument(cmd: u32) -> bool {
    matches!(spec(cmd).map(|s| s.payload), Some(Payload::None))
}

/// The commands this filesystem answers, for the checks that must enumerate
/// them rather than sample them. # C: O(1)
pub const ALL: &[u32] = &[
    START_ATOMIC_WRITE, COMMIT_ATOMIC_WRITE, START_VOLATILE_WRITE,
    RELEASE_VOLATILE_WRITE, ABORT_ATOMIC_WRITE, GARBAGE_COLLECT, WRITE_CHECKPOINT,
    DEFRAGMENT, MOVE_RANGE, FLUSH_DEVICE, GARBAGE_COLLECT_RANGE, GET_FEATURES,
    SET_PIN_FILE, GET_PIN_FILE, PRECACHE_EXTENTS, RESIZE_FS, GET_COMPRESS_BLOCKS,
    RELEASE_COMPRESS_BLOCKS, RESERVE_COMPRESS_BLOCKS, SEC_TRIM_FILE,
    GET_COMPRESS_OPTION, SET_COMPRESS_OPTION, DECOMPRESS_FILE, COMPRESS_FILE,
    START_ATOMIC_REPLACE, GET_DEV_ALIAS_FILE, IO_PRIO, SHUTDOWN,
    FS_IOC_GETVERSION, FS_IOC_SETVERSION, FS_IOC_GETFLAGS, FS_IOC_SETFLAGS,
    FS_IOC_FSGETXATTR, FS_IOC_FSSETXATTR, FS_IOC_GETFSLABEL, FS_IOC_SETFSLABEL,
    FITRIM, SET_ENCRYPTION_POLICY, GET_ENCRYPTION_PWSALT, GET_ENCRYPTION_POLICY,
    GET_ENCRYPTION_POLICY_EX, ADD_ENCRYPTION_KEY, REMOVE_ENCRYPTION_KEY,
    REMOVE_ENCRYPTION_KEY_ALL_USERS, GET_ENCRYPTION_KEY_STATUS,
    GET_ENCRYPTION_NONCE, ENABLE_VERITY, MEASURE_VERITY, READ_VERITY_METADATA,
];

#[cfg(test)]
#[path = "../tests/ioctl/spec.rs"]
mod tests;
