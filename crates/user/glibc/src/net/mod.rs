//! net — glibc-ABI surface (docs/59§3, §6 G13). inet (byte order + pton/ntop)
//! first; socket wrappers + getaddrinfo follow.
pub mod inet;
pub mod socket;
