// The `crashkernel=` command-line grammar.
//
// Ungated, and every decision it makes is one a boot cannot report on: a
// machine that reserves the wrong amount, or reserves nothing because a suffix
// was misread, boots exactly like one that got it right and only differs the
// day it panics.

/// Bytes and optional fixed base a `crashkernel=` value asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CrashKernelReq {
    /// Bytes to reserve.
    pub size: u64,
    /// Fixed physical base, when the value named one.
    pub base: Option<u64>,
}
