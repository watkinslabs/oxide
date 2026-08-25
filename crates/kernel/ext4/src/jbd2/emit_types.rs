extern crate alloc;

use alloc::vec::Vec;

/// One staged metadata write awaiting commit.
#[derive(Clone, Debug)]
pub struct StagedBlock {
    /// Target fs LBA the data should ultimately land at.
    pub target_lba: u64,
    /// Block contents (length = journal block size).
    pub data:       Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EmitError {
    Empty,
    BlockSize,
    BlockNumber,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TransactionError<E> {
    Emit(EmitError),
    Write(E),
}

