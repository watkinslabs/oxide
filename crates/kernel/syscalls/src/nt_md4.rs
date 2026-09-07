// Module manifest: MD4 digest services for the Windows RTL boundary.
// digest: the accumulator and the exported context record layout.
// dispatch: user boundary, kernel-only.
pub(crate) mod digest;
#[cfg(target_os = "oxide-kernel")]
mod dispatch;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use dispatch::dispatch;
#[cfg(test)]
#[path = "nt_md4/tests.rs"]
mod tests;
