//! posix — glibc-ABI surface, one fn/file (docs/59§3). Implemented at G8 (docs/59§6).
//! write/read land early (G2) for the process-entry path.
pub mod io;
