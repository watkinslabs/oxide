// Module manifest — TCG event log.
//
//   error.rs   — the one error type the log parsers return
//   types.rs   — event-type numbers and fixed record geometry
//   spec_id.rs — the log's first record, which declares the digest sizes
//   tpm2.rs    — crypto-agile records: parse and walk
//   tpm1.rs    — fixed-format records: parse and walk
//   builder.rs — append records in either format
//
// Log records are little-endian, unlike the command protocol.

mod cursor;
mod error;
mod types;
mod spec_id;
mod tpm2;
mod tpm1;
mod builder;

pub use error::LogError;
pub use types::{event_type_name, EV_ACTION, EV_COMPACT_HASH, EV_EVENT_TAG, EV_IPL, EV_IPL_PARTITION_DATA, EV_NONHOST_CODE, EV_NONHOST_CONFIG, EV_NONHOST_INFO, EV_NO_ACTION, EV_POST_CODE, EV_PREBOOT, EV_SEPARATOR, EV_UNUSED, TCG_EVENT1_HEADER_LEN, TCG_EVENT1_DIGEST_LEN, TCG_EVENT2_PREFIX_LEN};
pub use spec_id::{AlgSize, SpecId, SPEC_ID_SIGNATURE};
pub use tpm2::{Event2, Tpm2Log};
pub use tpm1::{Event1, Tpm1Log};
pub use builder::{Tpm1LogBuilder, Tpm2LogBuilder};
