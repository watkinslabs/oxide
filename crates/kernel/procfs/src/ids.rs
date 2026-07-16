//! Synthetic procfs inode identities, grouped by exported namespace.
pub(crate) const NET_DEV: u64 = 0xFEED_0001;
pub(crate) const NET_TCP: u64 = 0xFEED_0002;
pub(crate) const NET_UDP: u64 = 0xFEED_0003;
pub(crate) const MODULES: u64 = 0xFEED_0004;
pub(crate) const NET_ROUTE: u64 = 0xFEED_0005;
pub(crate) const NET_ARP: u64 = 0xFEED_0006;
pub(crate) const NET_UNIX: u64 = 0xFEED_0007;
pub(crate) const NET_IF_INET6: u64 = 0xFEED_0008;
pub(crate) const NET_SNMP: u64 = 0xFEED_0009;
pub(crate) const NET_TCP6: u64 = 0xFEED_000A;
pub(crate) const NET_UDP6: u64 = 0xFEED_000B;
pub(crate) const NET_RAW: u64 = 0xFEED_000C;
pub(crate) const NET_RAW6: u64 = 0xFEED_000D;
pub(crate) const NS_GENERATED: u64 = 0xFEED_1000;
