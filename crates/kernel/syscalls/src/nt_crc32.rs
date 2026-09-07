// Module manifest: the CRC-32 accumulation the NT RTL publishes.
// checksum: the reflected table-driven accumulator, ungated.
// dispatch: user boundary, kernel-only.
pub(crate) mod checksum;
#[cfg(target_os = "oxide-kernel")]
mod dispatch;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use dispatch::dispatch;
#[cfg(test)]
#[path = "nt_crc32/tests.rs"]
mod tests;
