//! Atomic KMS object owner.
//!
//! - `blobs`: copied user property blobs and their lifetime.
//! - `props`: DRM object-property definitions and current values.
//! - `commit`: parse, validate, and apply atomic state transitions.

mod blobs;
mod commit;
mod props;

pub use blobs::{create_blob, destroy_blob, get_blob, mode_blob};
pub use commit::commit;
pub use props::{get_obj_properties, get_property};
