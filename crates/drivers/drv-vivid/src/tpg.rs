// Test-pattern generator manifest: pixel primitives, packed-format line
// renderers, and whole-frame/planar layout renderers live in focused modules.
mod pixel;
mod formats;
mod frame;

pub use pixel::{bar_at, chroma_u, chroma_v, luma, Motion, RenderMap, Rgb, BARS};
pub use formats::{render_line, render_line_at};
pub use frame::{frame_bytes, plane_sizes, render_frame, render_frame_motion,
    render_frame_motion_window};
