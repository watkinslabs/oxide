// Module manifest: the counted-string comparisons, copy and case fold the NT
// RTL publishes over its two string descriptors.
// rules: descriptor layout and the ordering, copy and fold decisions, ungated.
// dispatch: user boundary, kernel-only.
pub(crate) mod rules;
#[cfg(target_os = "oxide-kernel")]
mod dispatch;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use dispatch::dispatch;
#[cfg(test)]
#[path = "nt_counted_string/tests.rs"]
mod tests;
