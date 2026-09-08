//! Module manifest: builder publishes process/thread arenas; layout owns offsets;
//! processor_features owns the published feature-vector numbering and maps
//! architectural identification onto it for every architecture, not just the
//! host one, so both mappings stay testable from either;
//! user_shared_data owns the fixed read-only NT shared page;
//! publish updates catalog-owned regions; runtime provides bounded environment views.
mod layout;
pub mod processor_features;
mod user_shared_data;
mod builder;
mod publish;
pub mod runtime;
pub use builder::*;
pub use user_shared_data::{USER_SHARED_DATA_BASE, USER_SHARED_DATA_BYTES, SYSTEM_CALL_OFF as USER_SHARED_DATA_SYSTEM_CALL_OFF,
    SYSTEM_CALL_ADDRESS as USER_SHARED_DATA_SYSTEM_CALL_ADDRESS};
pub use layout::{X64_SHADOW_SPACE, X64_RETURN_SLOT, THREAD_TEB_BYTES, NT_DEBUG_INFO_OFFSET};
#[cfg(target_os = "oxide-kernel")]
pub use publish::{publish_module, publish_modules};
