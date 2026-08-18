//! SCMI failures reported by a transport or rejected by a protocol client.

/// SCMI operation failure.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Unsupported,
    Invalid,
    Access,
    NotFound,
    Range,
    Busy,
    Communication,
    Io,
    RemoteIo,
    Protocol,
    NoMemory,
    Malformed,
}

/// SCMI operation result.
pub type Result<T> = core::result::Result<T, Error>;
