//! stdio — glibc-ABI (docs/59§3, §6 G6). `fmt` is the always-built,
//! oracle-tested printf format engine; `file` carries the FILE ABI layout;
//! `printf`/`put` are the freestanding C exports. G6a = write-side +
//! snprintf, unbuffered; read-side (fopen/fread/fgets/scanf), buffering,
//! and exact float formatting are G6 follow-ups.
pub mod fmt;
pub mod scan;
pub mod file;
#[cfg(feature = "freestanding")]
pub mod printf;
#[cfg(feature = "freestanding")]
pub mod read;
#[cfg(feature = "freestanding")]
pub mod scanf;
#[cfg(feature = "freestanding")]
pub mod put;
#[cfg(feature = "freestanding")]
pub mod memstream;
#[cfg(feature = "freestanding")]
pub mod cookie;
#[cfg(feature = "freestanding")]
pub mod unlocked;
