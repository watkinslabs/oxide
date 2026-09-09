//! Real compositor position admission; no live task cancellation in this fixture.
#[path="../../src/nt_window/position/work.rs"]
mod work;
#[path="../../src/nt_window/position/compositor.rs"]
mod compositor;
pub(crate) use work::RemotePosition;
pub(crate) use compositor::queue_compositor;
pub(crate) fn cancel_position_window<T>(_: &T, _: u64) {}
