//! Linux-shaped LSM hook dispatch.
//!
//! Module manifest:
//! - hooks: provider registries and VFS/task dispatch entry points.
//! - task_dispatch: allocation-free ordered task authorization chain.

mod hooks;
mod task_dispatch;

pub use hooks::*;
