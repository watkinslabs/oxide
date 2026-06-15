//! net — glibc-ABI surface (docs/59§3, §6 G13). inet (byte order + pton/ntop)
//! first; socket wrappers + getaddrinfo follow.
pub mod addrinfo;
pub mod inet;
pub mod netdb;
pub mod netdb_host;
pub mod netdb_net;
pub mod netdb_proto;
pub mod netdb_serv;
pub mod netgr;
pub mod socket;
