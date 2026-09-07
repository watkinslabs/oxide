// Module manifest: IP address string services for the Windows RTL boundary.
// digits: hex table and the wide unsigned-long conversion the parsers use.
// ipv4: dotted-quad scan, parse and format, plus the shared text emitters.
// ipv6: colon-group parse with zero-run elision and the extended forms.
// format6: IPv6 rendering, including the embedded dotted quad.
// dispatch: user boundary, kernel-only.
mod digits;
pub(crate) mod ipv4;
pub(crate) mod ipv6;
pub(crate) mod format6;
#[cfg(target_os = "oxide-kernel")]
mod dispatch;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use dispatch::dispatch;
#[cfg(test)]
#[path = "nt_ip_string/tests/ipv4.rs"]
mod ipv4_tests;
#[cfg(test)]
#[path = "nt_ip_string/tests/ipv6.rs"]
mod ipv6_tests;
#[cfg(test)]
#[path = "nt_ip_string/tests/format.rs"]
mod format_tests;
