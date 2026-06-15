//! time — glibc-ABI (docs/59§3, §6 G10). `tm` is the always-built
//! oracle-tested calendar; `clock` is the freestanding syscall layer.
//! strftime + TZ-aware localtime land in G10b/G16.
pub mod tm;
pub mod strftime;
#[cfg(feature = "freestanding")]
pub mod clock;
