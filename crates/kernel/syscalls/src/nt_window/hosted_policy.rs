// Module manifest: nt_window's target-independent policy children, mirrored so `cargo test`
// compiles them and their contracts are runnable; kernel builds reach the same files through
// nt_window.rs. Only ungated decision modules belong here — live glue stays gated (docs/53).
#![allow(unused_imports)] // Kernel-only consumers of the mirrored manifests re-exports are gated out here.
#[path = "create_lifecycle.rs"]
pub(crate) mod create_lifecycle;
#[path = "desktop/geometry.rs"]
pub(crate) mod desktop_geometry;
#[path = "erase_background.rs"]
pub(crate) mod erase_background;
#[path = "paint_prepare.rs"]
pub(crate) mod paint_prepare;
/// `paint_callbacks::work` names erase preparation through this parent.
pub(crate) use crate::nt_redraw_contract as redraw;
#[path = "paint_callbacks.rs"]
pub(crate) mod paint_callbacks;
#[path = "position/hosted_policy.rs"]
pub(crate) mod position;
