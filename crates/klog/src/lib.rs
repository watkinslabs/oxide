// Minimal kernel logger skeleton per docs/04 (FROZEN).
// Format strings interned in `.klog_strings` (per `04` format-interning OQ
// resolution = defmt-style linker section). Userspace decoder resolves
// strings by virtual address. UART backend is HAL-pluggable; the wiring
// lands once HAL is frozen and `kernel/_start` exists.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Level {
    Error = 0,
    Warn  = 1,
    Info  = 2,
    Debug = 3,
    Trace = 4,
}

/// UART-shaped sink. HAL or test code provides an impl.
///
/// # C: O(1) per byte
pub trait Uart {
    /// # C: O(1)
    fn write_byte(&mut self, b: u8);

    /// # C: O(n) n=bytes.len()
    fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }
}

#[doc(hidden)]
pub struct InternedFormat {
    pub level: Level,
    pub bytes: &'static [u8],
}

/// # C: O(1)
#[doc(hidden)]
#[inline(always)]
pub fn __klog_emit(_entry: &'static InternedFormat) {
    // Sink wiring lands with HAL freeze. For now the emit point exists
    // so call-site expansion typechecks.
}

/// Emit an interned format string at the given level. `$msg` must be
/// a `&'static str` literal per `07§5` (compile-time interning).
///
/// Expansion places the format string into `.klog_strings` (a custom
/// linker section per `07§6`), then calls into `__klog_emit` with a
/// pointer into that section. The userspace decoder reads
/// `.klog_strings` from the kernel image and resolves the address.
#[macro_export]
macro_rules! klog {
    ($lvl:ident, $msg:literal $(,)?) => {{
        #[link_section = ".klog_strings"]
        static __KLOG_STR: $crate::InternedFormat = $crate::InternedFormat {
            level: $crate::Level::$lvl,
            bytes: $msg.as_bytes(),
        };
        $crate::__klog_emit(&__KLOG_STR);
    }};
}

/// Convenience wrappers per `04` log surface.
#[macro_export]
macro_rules! kerror { ($msg:literal $(,)?) => { $crate::klog!(Error, $msg) }; }
#[macro_export]
macro_rules! kwarn  { ($msg:literal $(,)?) => { $crate::klog!(Warn,  $msg) }; }
#[macro_export]
macro_rules! kinfo  { ($msg:literal $(,)?) => { $crate::klog!(Info,  $msg) }; }
#[macro_export]
macro_rules! kdebug { ($msg:literal $(,)?) => { $crate::klog!(Debug, $msg) }; }
#[macro_export]
macro_rules! ktrace { ($msg:literal $(,)?) => { $crate::klog!(Trace, $msg) }; }

#[cfg(test)]
mod tests {
    use super::*;

    struct VecUart(pub alloc::vec::Vec<u8>);
    extern crate alloc;

    impl Uart for VecUart {
        fn write_byte(&mut self, b: u8) { self.0.push(b); }
    }

    #[test]
    fn levels_are_distinct() {
        assert_ne!(Level::Error as u8, Level::Trace as u8);
    }

    #[test]
    fn macro_expands_and_links() {
        kerror!("error path");
        kinfo!("hello");
        kdebug!("dbg");
    }

    #[test]
    fn uart_default_write_bytes_iterates() {
        let mut u = VecUart(alloc::vec::Vec::new());
        u.write_bytes(b"abc");
        assert_eq!(u.0, b"abc");
    }
}
