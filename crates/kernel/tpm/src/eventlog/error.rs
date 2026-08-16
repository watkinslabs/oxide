// Event-log parse failures. A log is firmware-supplied and arbitrary bytes
// may follow the last valid record, so "this is not a record" is a normal
// outcome and never a panic.

/// Why a log record could not be parsed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LogError {
    /// A field ran past the end of the log.
    Truncated { need: usize, have: usize },
    /// The first record is not a specification-identification event.
    BadSignature,
    /// The first record's fixed fields are not what the format requires.
    BadHeader(&'static str),
    /// A record names a digest algorithm the log's own table does not size,
    /// which makes the rest of the record unwalkable.
    UnknownAlg(u16),
    /// A record's digest count disagrees with the log's algorithm table.
    DigestCount { expected: usize, got: usize },
    /// A digest is not the length its algorithm declares.
    DigestLen { alg_id: u16, expected: usize, got: usize },
    /// The algorithm table is empty, so no record can be sized.
    NoAlgorithms,
    /// The record is the log terminator, not an event.
    EndOfLog,
}
