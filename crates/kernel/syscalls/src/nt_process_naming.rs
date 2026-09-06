//! The name a native process reports to ordinary Linux process tools.
//!
//! Kept out of the target-gated creation path so its rule is reachable by a
//! hosted test: a file gated on the kernel target compiles out of `cargo test`
//! entirely, and a test that never compiles reports nothing.

/// The image's own basename, under either separator, because an NT request
/// carries a Windows path while the same value may also be a host path.
/// A path that ends in a separator has no basename to take, so it is returned
/// whole rather than reduced to an empty name no task manager could show.
/// # C: O(path.len())
pub(crate) fn comm_of(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().filter(|name| !name.is_empty()).unwrap_or(path)
}

#[cfg(test)]
#[path = "tests/nt_process_naming.rs"]
mod tests;
