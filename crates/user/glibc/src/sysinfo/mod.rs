//! sysinfo — system-information surface (docs/59§6 G8): uname, sysconf,
//! confstr, pathconf/fpathconf, getpagesize, getloadavg, get_nprocs*,
//! get_phys_pages/get_avphys_pages, sysinfo(2). One fn/file family; all
//! gated `freestanding` (syscall + /proc backed). _SC_/_CS_/_PC_ codes and
//! struct layouts (utsname/sysinfo) match host headers exactly.
#[cfg(feature = "freestanding")]
pub mod info;
#[cfg(feature = "freestanding")]
pub mod conf;
#[cfg(feature = "freestanding")]
pub mod rlim;
