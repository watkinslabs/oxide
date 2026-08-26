// Resolved-path text for `openat`'s diagnostics, and nothing else.
//
// Every consumer of the rendered path in the open path sits behind
// `debug-cgroup`, `debug-atexit` or `debug-eacces`. Rendering it
// unconditionally cost every `openat` two full dentry-to-root walks, two mount
// table lookups, a mount-point string clone and the concatenation — for a
// value a production kernel throws away. The reference does not build a path
// string on open at all: `d_path` runs for `/proc`, audit records and error
// reports, never for `do_filp_open`.
#![cfg(target_os = "oxide-kernel")]

extern crate alloc;

#[cfg(any(feature = "debug-cgroup", feature = "debug-atexit", feature = "debug-eacces"))]
mod armed {
    extern crate alloc;
    use alloc::string::String;
    use alloc::sync::Arc;

    pub(crate) type PathDisplay = String;

    /// Render the resolved path for the open diagnostics. # C: O(depth + path len)
    pub(crate) fn render(mnt_id: u64, d: &Arc<vfs::Dentry>) -> PathDisplay {
        vfs::mount::render_path_for_mount(mnt_id, d)
    }

    /// Adopt text the caller already built. # C: O(1)
    pub(crate) fn from_string(text: String) -> PathDisplay { text }
}

#[cfg(not(any(feature = "debug-cgroup", feature = "debug-atexit", feature = "debug-eacces")))]
mod armed {
    use alloc::sync::Arc;

    /// Placeholder for the diagnostic path text no consumer is compiled to read.
    #[derive(Clone)]
    pub(crate) struct PathDisplay;

    /// Render nothing: no consumer of the text is compiled in. # C: O(1)
    pub(crate) fn render(_mnt_id: u64, _d: &Arc<vfs::Dentry>) -> PathDisplay { PathDisplay }

    /// Discard text no consumer is compiled to read. # C: O(1)
    pub(crate) fn from_string(_text: alloc::string::String) -> PathDisplay { PathDisplay }
}

pub(crate) use armed::{from_string, render};
