// Module manifest: the slim reader/writer lock and condition-variable wakes.
// state: the compact lock word and its transitions, ungated.
// dispatch: user boundary, kernel-only.
pub(crate) mod state;
#[cfg(target_os = "oxide-kernel")]
mod dispatch;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use dispatch::{acquire, dispatch, release};
#[cfg(test)]
#[path = "nt_srw/tests.rs"]
mod tests;
