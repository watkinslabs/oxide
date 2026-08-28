// JBD2 emission manifest: types, descriptor encoding, transaction streaming,
// journal cursor, and focused tests. Recovery remains in `replay.rs`.

#[path = "emit_types.rs"]
mod types;
#[path = "emit_descriptor.rs"]
mod descriptor;
#[path = "emit_transaction.rs"]
mod transaction;
#[path = "emit_cursor.rs"]
mod cursor;

pub use types::{EmitError, StagedBlock, TransactionError};
pub use descriptor::{
    build_descriptor_block, build_descriptor_block_for, descriptor_capacity,
    descriptor_capacity_for, escape_journal_payload,
};
pub use transaction::{
    build_commit_block, build_commit_block_for, emit_transaction, emit_transaction_for,
    emit_transaction_split,
    transaction_block_count, transaction_block_count_for,
};
pub use cursor::LogCursor;

#[cfg(test)]
#[path = "emit_tests.rs"]
mod tests;
