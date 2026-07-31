// Transmit preparation for ICMP datagram endpoints. The caller supplies the
// echo type, code, sequence, and body; the kernel supplies the identifier and
// the checksum. A caller-chosen identifier is discarded, which is what makes
// the reply demultiplexing key trustworthy.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::netdev::NetError;

use super::sock::{autobind_v4, autobind_v6};
use super::validate::{self, PingFamily};

/// Prepare one IPv4 echo probe: acquire the identifier, screen the message,
/// stamp the identifier, and seal the message checksum. # C: O(len)
pub fn prepare_v4(endpoint: &Arc<crate::raw4::Raw4Endpoint>, message: &[u8], oob: bool)
    -> Result<Vec<u8>, NetError>
{
    let ident = autobind_v4(endpoint)?;
    validate::admit_send(PingFamily::V4, message, oob)?;
    let mut out = validate::stamp_identifier(message, ident);
    let checksum = crate::ipv4::ip_checksum(&out);
    out[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(out)
}

/// Prepare one IPv6 echo probe. The transmit path seals the message checksum
/// from the pseudo-header, so this leaves the field cleared. # C: O(len)
pub fn prepare_v6(endpoint: &Arc<crate::raw6::Raw6Endpoint>, message: &[u8], oob: bool)
    -> Result<Vec<u8>, NetError>
{
    let ident = autobind_v6(endpoint)?;
    validate::admit_send(PingFamily::V6, message, oob)?;
    Ok(validate::stamp_identifier(message, ident))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ping::validate::identifier;

    fn endpoint_v4() -> Arc<crate::raw4::Raw4Endpoint> {
        let namespace = crate::net_ns::test_support::allocate_namespace();
        crate::net_ns::materialize_state(&namespace);
        crate::raw4::Raw4Endpoint::new_ping(crate::SocketOwner::root(namespace, 0),
            Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::mcast_filter::SocketMcast::new()),
            Arc::new(crate::SocketError::new()),
            Arc::new(core::sync::atomic::AtomicI32::new(0)),
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)))
    }

    #[test]
    fn the_caller_identifier_never_reaches_the_wire() {
        let endpoint = endpoint_v4();
        let message = alloc::vec![8u8, 0, 0, 0, 0xff, 0xff, 0x00, 0x2a, b'p', b'a', b'y'];
        let sealed = prepare_v4(&endpoint, &message, false).unwrap();
        let assigned = endpoint.ping.as_ref().unwrap().ident();
        assert_ne!(assigned, 0);
        assert_ne!(assigned, 0xffff, "the allocator must not echo the caller value back");
        assert_eq!(identifier(&sealed), assigned);
        assert_eq!(&sealed[6..8], &[0x00, 0x2a], "sequence is the caller's");
        assert_eq!(&sealed[8..], b"pay");
        // The sealed message checksums to zero, so a receiver validates it.
        assert_eq!(crate::ipv4::ip_checksum(&sealed), 0);
    }

    #[test]
    fn the_identifier_is_stable_across_probes() {
        let endpoint = endpoint_v4();
        let message = alloc::vec![8u8, 0, 0, 0, 0, 0, 0, 1];
        let first = prepare_v4(&endpoint, &message, false).unwrap();
        let second = prepare_v4(&endpoint, &message, false).unwrap();
        assert_eq!(identifier(&first), identifier(&second));
    }

    #[test]
    fn a_forbidden_type_is_refused_after_the_identifier_is_acquired() {
        let endpoint = endpoint_v4();
        let message = alloc::vec![3u8, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(prepare_v4(&endpoint, &message, false), Err(NetError::Einval));
        assert!(endpoint.ping.as_ref().unwrap().is_bound(),
            "the transmit path acquires the identifier before it screens the message");
    }
}
