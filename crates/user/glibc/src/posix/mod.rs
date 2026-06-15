//! posix — glibc-ABI surface, one fn/file (docs/59§3). Implemented at G8 (docs/59§6).
//! write/read land early (G2), mmap/brk at G3, for the entry + malloc paths.
pub mod io;
pub mod mman;
#[cfg(feature = "freestanding")]
pub mod ids;
#[cfg(feature = "freestanding")]
pub mod process;
#[cfg(feature = "freestanding")]
pub mod fd;
#[cfg(feature = "freestanding")]
pub mod fs;
pub mod stat;
pub mod fnmatch;
