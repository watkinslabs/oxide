// Client error taxonomy and the errno mapping both dialects need.
//
// A `.L` server answers `Rlerror` with a numeric errno; a legacy or `.u` server
// answers `Rerror` with a STRING, optionally followed by a numeric code in the
// `.u` dialect. The string table below is what makes a base-9P2000 mount usable
// at all: without it every server-reported failure collapses to one errno and
// `ENOENT` becomes indistinguishable from `EACCES`.

use vfs::VfsError;

/// Largest magnitude a server-supplied errno may have. A reply outside it is a
/// protocol violation, not an error to pass upward — a server could otherwise
/// return a value that a caller reinterprets as a successful large result.
pub const MAX_ERRNO: i32 = 4095;

/// Failure of a 9P operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NpError {
    /// The server reported this POSIX errno (always positive here).
    Server(i32),
    /// A reply was malformed, truncated, or declared a length that disagreed
    /// with the bytes received.
    BadMessage,
    /// A reply arrived whose type was neither the expected `R`-message nor an
    /// error reply.
    UnexpectedReply,
    /// The encoded request would exceed the negotiated `msize`.
    MsgTooLarge,
    /// A path component is longer than the wire length prefix can express.
    NameTooLong,
    /// No tag is free: `u16::MAX - 1` requests are already in flight.
    NoTags,
    /// No fid number is free.
    NoFids,
    /// The transport is gone (server closed, device removed, mount aborted).
    Disconnected,
    /// The version handshake failed: no common dialect, or an `msize` below the
    /// protocol floor.
    BadVersion,
    /// The wait for a reply was ended by a deliverable signal.
    Interrupted,
    /// An allocation failed.
    NoMemory,
}

/// Result of a 9P operation.
pub type NpResult<T> = core::result::Result<T, NpError>;

impl NpError {
    /// Wrap a server-reported errno, rejecting an out-of-range value. A `.L`
    /// server sends a POSITIVE code in `Rlerror`; a value of zero would mean
    /// "error reply with no error", which is a protocol fault rather than a
    /// success. # C: O(1)
    pub fn from_server(code: u32) -> Self {
        let c = code as i32;
        if c <= 0 || c > MAX_ERRNO { return NpError::BadMessage; }
        NpError::Server(c)
    }
}

impl From<NpError> for VfsError {
    /// # C: O(1)
    fn from(e: NpError) -> VfsError {
        match e {
            NpError::Server(c) => VfsError::from_posix_errno(c),
            NpError::BadMessage | NpError::UnexpectedReply => VfsError::Eproto,
            NpError::MsgTooLarge => VfsError::Emsgsize,
            NpError::NameTooLong => VfsError::Enametoolong,
            NpError::NoTags | NpError::NoFids => VfsError::Enomem,
            NpError::Disconnected => VfsError::Eio,
            NpError::BadVersion => VfsError::Eproto,
            NpError::Interrupted => VfsError::Erestartsys,
            NpError::NoMemory => VfsError::Enomem,
        }
    }
}

/// Errno names a legacy or `.u` server may put in an `Rerror` string, paired
/// with the POSIX number they mean. A server is free to send free-form prose
/// instead, which is why an unmatched string falls back to `EIO` rather than
/// being reported as success.
const ERRSTR_TABLE: &[(&str, i32)] = &[
    ("Operation not permitted", 1),
    ("No such file or directory", 2),
    ("No such process", 3),
    ("Interrupted system call", 4),
    ("Input/output error", 5),
    ("No such device or address", 6),
    ("Argument list too long", 7),
    ("Exec format error", 8),
    ("Bad file descriptor", 9),
    ("No child processes", 10),
    ("Resource temporarily unavailable", 11),
    ("Cannot allocate memory", 12),
    ("Permission denied", 13),
    ("Bad address", 14),
    ("Device or resource busy", 16),
    ("File exists", 17),
    ("Invalid cross-device link", 18),
    ("No such device", 19),
    ("Not a directory", 20),
    ("Is a directory", 21),
    ("Invalid argument", 22),
    ("File table overflow", 23),
    ("Too many open files", 24),
    ("File too large", 27),
    ("No space left on device", 28),
    ("Illegal seek", 29),
    ("Read-only file system", 30),
    ("Too many links", 31),
    ("Broken pipe", 32),
    ("Numerical result out of range", 34),
    ("Resource deadlock avoided", 35),
    ("File name too long", 36),
    ("No locks available", 37),
    ("Function not implemented", 38),
    ("Directory not empty", 39),
    ("Too many levels of symbolic links", 40),
    ("No message of desired type", 42),
    ("Value too large for defined data type", 75),
    ("Illegal byte sequence", 84),
    ("Operation not supported", 95),
    ("Connection reset by peer", 104),
    ("Transport endpoint is not connected", 107),
    ("Stale file handle", 116),
    ("Remote I/O error", 121),
    ("Disk quota exceeded", 122),
    ("Operation canceled", 125),
    ("No medium found", 123),
    ("Unknown error", 5),
];

/// Translate an `Rerror` string to an errno. An unrecognised string is `EIO` —
/// a real failure with an unknown cause, never a success. # C: O(table)
pub fn errstr_to_errno(s: &str) -> i32 {
    for (name, code) in ERRSTR_TABLE {
        if *name == s { return *code; }
    }
    5
}

/// Decide the errno for a legacy or `.u` `Rerror`. The `.u` dialect appends a
/// numeric code; a code BELOW 512 is authoritative and used directly, because a
/// server that bothered to send one knows better than the string table. A code
/// at or above 512 is a Plan 9 error number in a different namespace and must
/// NOT be handed to POSIX code as an errno — the string is consulted instead.
/// # C: O(table)
pub fn rerror_errno(ename: &str, ecode: Option<u32>) -> NpError {
    if let Some(code) = ecode {
        if code < 512 && code != 0 { return NpError::from_server(code); }
    }
    NpError::Server(errstr_to_errno(ename))
}
