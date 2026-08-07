use super::*;

const INGRESS_REASM_DOMAIN: u32 = 0;
const LOCAL_OUT_REASM_DOMAIN: u32 = 1;

/// Copy an ingress datagram into packet-owned storage without turning memory
/// pressure into an allocator abort. # C: O(packet)
fn copy_packet(bytes: &[u8]) -> NetResult<Vec<u8>> {
    copy_packet_with(bytes, |packet, len| {
        packet.try_reserve_exact(len).map_err(|_| NetError::Enobufs)
    })
}

fn copy_packet_with(bytes: &[u8], reserve: impl FnOnce(&mut Vec<u8>, usize) -> NetResult<()>)
    -> NetResult<Vec<u8>>
{
    let mut packet = Vec::new();
    reserve(&mut packet, bytes.len())?;
    packet.extend_from_slice(bytes);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_copy_preserves_an_allocation_failure() {
        assert_eq!(copy_packet_with(b"packet", |_, _| Err(NetError::Enobufs)),
            Err(NetError::Enobufs));
    }
}

impl NetStack {
    /// Gather IPv4 fragments before a netfilter hook sees the packet. `None`
    /// retains the packet in the canonical fragment queue until complete.
    /// # C: O(fragments + packet)
    fn ipv4_nf_defrag(&self, net_ns: u64, domain: u32, iface: Option<NetIfaceId>,
        l3: &[u8]) -> NetResult<Option<(Vec<u8>, u32)>> {
        let hdr = Ipv4Hdr::parse(l3).map_err(|_| NetError::Einval)?;
        let total = hdr.total_len as usize;
        if total > l3.len() { return Err(NetError::Einval); }
        let l3 = &l3[..total];
        let mf = hdr.flags_frag & crate::ipv4::IPV4_FLAG_MORE_FRAGMENTS != 0;
        let off8 = (hdr.flags_frag & crate::ipv4::IPV4_FRAGMENT_OFFSET_MASK) as usize;
        if !mf && off8 == 0 { return Ok(Some((copy_packet(l3)?, 0))); }
        let prefix = (off8 == 0).then_some(&l3[..hdr.ihl_bytes()]);
        let key = crate::ipv4_reasm::ReasmKey {
            net_ns, domain, iface, src: hdr.src, dst: hdr.dst, proto: hdr.proto, id: hdr.id,
        };
        let payload = &l3[hdr.ihl_bytes()..];
        let fragsize = (hdr.ihl_bytes() + payload.len()) as u32;
        let Some((header, payload, largest)) = self.ipv4_reasm.try_push_with_prefix(
            key, net_now_ns(), off8 * 8, prefix, payload, mf, fragsize,
        )? else { return Ok(None); };
        let packet = crate::cgroup_bpf::reassembled_ipv4(&header, &payload)
            .ok_or(NetError::Einval)?;
        Ok(Some((packet, largest)))
    }

    /// Defragment one received IPv4 datagram before PRE_ROUTING. # C: O(fragments + packet)
    pub(super) fn ipv4_nf_defrag_ingress(&self, net_ns: u64, iface: NetIfaceId,
        l3: &[u8]) -> NetResult<Option<(Vec<u8>, u32)>> {
        self.ipv4_nf_defrag(net_ns, INGRESS_REASM_DOMAIN, Some(iface), l3)
    }

    /// Defragment raw socket output before LOCAL_OUT unless IP_NODEFRAG keeps
    /// the socket's supplied fragments intact. # C: O(fragments + packet)
    pub(crate) fn ipv4_nf_defrag_local_out(&self, net_ns: u64, l3: &[u8],
        nodefrag: bool) -> NetResult<Option<Vec<u8>>> {
        if nodefrag { return Ok(Some(l3.to_vec())); }
        self.ipv4_nf_defrag(net_ns, LOCAL_OUT_REASM_DOMAIN, None, l3)
            .map(|packet| packet.map(|(packet, _)| packet))
    }
}
