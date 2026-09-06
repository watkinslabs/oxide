//! Module manifest: builder publishes process/thread arenas; layout owns offsets;
//! publish updates catalog-owned regions; runtime provides bounded environment views.
mod layout;
mod builder;
mod publish;
pub mod runtime;
pub use builder::*;
pub use layout::{X64_SHADOW_SPACE, X64_RETURN_SLOT, THREAD_TEB_BYTES, NT_DEBUG_INFO_OFFSET};
#[cfg(target_os = "oxide-kernel")]
pub use publish::{publish_module, publish_modules};
