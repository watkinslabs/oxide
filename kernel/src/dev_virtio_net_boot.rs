// Boot-time one-shot probes that exercise the modern virtio-net
// transport end to end through SLIRP: ARP request to the gateway,
// ICMP echo, DHCP DISCOVER. Split out of `dev_virtio_net_modern`
// to keep that file under the 1000-line cap (08§7).
//
// All probes share the same shape: build a frame, call
// `dev_virtio_net_modern::tx_frame`, spin while polling
// `dev_virtio_net_modern::rx_poll` for the matching reply. They
// run once each at boot from `pci_boot::enumerate_and_log` after
// the modern transport is registered.

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

use core::sync::atomic::Ordering;

use crate::dev_virtio_net_modern::{
    arp_cache, mac, rx_poll, tx_frame, TxOutcome,
};

const ETHERTYPE_ARP:    u16 = 0x0806;
const IPV4_ETHERTYPE:   u16 = 0x0800;
const IPV4_PROTO_ICMP:  u8  = 1;
const ARP_OP_REQUEST:   u16 = 1;
const ARP_OP_REPLY:     u16 = 2;
const VIRTIO_NET_HDR_LEN: usize = 12;

// -------- ARP --------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct ArpProbeResult {
    pub tx_attempted: bool,
    pub tx_confirmed: bool,
    pub rx_frames:    usize,
    pub reply_seen:   bool,
    pub gateway_mac:  [u8; 6],
    pub gateway_ip:   [u8; 4],
}

fn build_arp_request(
    src_mac: [u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4], out: &mut [u8; 42],
) {
    for i in 0..6 { out[i] = 0xFF; }
    out[6..12].copy_from_slice(&src_mac);
    out[12] = (ETHERTYPE_ARP >> 8) as u8;
    out[13] = (ETHERTYPE_ARP & 0xFF) as u8;
    out[14] = 0x00; out[15] = 0x01;     // htype=1
    out[16] = 0x08; out[17] = 0x00;     // ptype=IPv4
    out[18] = 6; out[19] = 4;
    out[20] = (ARP_OP_REQUEST >> 8) as u8;
    out[21] = (ARP_OP_REQUEST & 0xFF) as u8;
    out[22..28].copy_from_slice(&src_mac);
    out[28..32].copy_from_slice(&src_ip);
    for i in 32..38 { out[i] = 0; }
    out[38..42].copy_from_slice(&dst_ip);
}

/// Send an ARP request to `target_ip` via `src_ip`, poll for reply.
/// On success: parses sender_mac + sender_ip, inserts into arp_cache.
/// # C: O(rx_drain)
pub fn boot_arp_probe(src_ip: [u8; 4], target_ip: [u8; 4]) -> ArpProbeResult {
    let mut out = ArpProbeResult {
        tx_attempted: false, tx_confirmed: false, rx_frames: 0,
        reply_seen: false, gateway_mac: [0; 6], gateway_ip: [0; 4],
    };
    let m = match mac() { Some(m) => m, None => return out };
    let mut frame = [0u8; 42];
    build_arp_request(m, src_ip, target_ip, &mut frame);

    debug_boot! {
        klog::write_raw(b"[INFO]  arp-tx src=");
        for (i, b) in m.iter().enumerate() {
            klog::write_hex_u64(*b as u64);
            if i < 5 { klog::write_raw(b":"); }
        }
        klog::write_raw(b" target_ip=");
        for (i, b) in target_ip.iter().enumerate() {
            klog::write_dec_u64(*b as u64);
            if i < 3 { klog::write_raw(b"."); }
        }
        klog::write_raw(b"\n");
    }

    out.tx_attempted = true;
    match tx_frame(&frame) {
        Ok(TxOutcome::Confirmed) => out.tx_confirmed = true,
        Ok(TxOutcome::Timeout)   => out.tx_confirmed = false,
        Err(_)                   => { out.tx_attempted = false; return out; }
    }

    let mut reply_seen = false;
    let mut gw_mac = [0u8; 6];
    let mut gw_ip  = [0u8; 4];
    let mut frames_total = 0usize;
    let mut drained_total = 0usize;
    for _ in 0..50usize {
        for _ in 0..1_000_000usize { core::hint::spin_loop(); }
        let drained = rx_poll(|f: &[u8]| {
            frames_total += 1;
            if f.len() < 14 + 28 { return; }
            let et = ((f[12] as u16) << 8) | (f[13] as u16);
            if et != ETHERTYPE_ARP { return; }
            if let Ok(arp) = net::arp::ArpPkt::parse(&f[14..14 + 28]) {
                if arp.opcode == ARP_OP_REPLY {
                    reply_seen = true;
                    gw_mac = arp.sender_mac.0;
                    gw_ip  = arp.sender_ip.octets();
                    arp_cache().insert(arp.sender_ip, arp.sender_mac);
                }
            }
        });
        drained_total += drained;
        if reply_seen { break; }
    }
    out.rx_frames   = drained_total.max(frames_total);
    out.reply_seen  = reply_seen;
    out.gateway_mac = gw_mac;
    out.gateway_ip  = gw_ip;
    out
}

// -------- ICMP -------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct IcmpProbeResult {
    pub tx_attempted: bool,
    pub tx_confirmed: bool,
    pub rx_frames:    usize,
    pub reply_seen:   bool,
    pub round_trips:  usize,
}

/// Build + send an ICMP Echo Request to `gw_ip` via `gw_mac`,
/// poll for matching Echo Reply.
/// # C: O(rx_drain)
pub fn boot_icmp_echo_probe(
    src_ip: [u8; 4], gw_ip: [u8; 4], gw_mac: [u8; 6],
) -> IcmpProbeResult {
    let mut out = IcmpProbeResult {
        tx_attempted: false, tx_confirmed: false,
        rx_frames: 0, reply_seen: false, round_trips: 0,
    };
    let our_mac = match mac() { Some(m) => m, None => return out };

    let payload: [u8; 8] = *b"oxide-pi";
    let echo_id:  u16 = 0xC0DE;
    let echo_seq: u16 = 0x0001;
    let mut icmp_buf = [0u8; 16];
    let mut echo = net::icmp::IcmpEcho {
        typ: net::icmp::ICMP_TYPE_ECHO_REQUEST,
        code: 0, checksum: 0, id: echo_id, seq: echo_seq,
    };
    echo.build_into(&payload, &mut icmp_buf);

    let ip_hdr = net::ipv4::Ipv4Hdr::build(
        net::Ipv4Addr::new(src_ip[0], src_ip[1], src_ip[2], src_ip[3]),
        net::Ipv4Addr::new(gw_ip[0],  gw_ip[1],  gw_ip[2],  gw_ip[3]),
        net::IpProto::Icmp,
        icmp_buf.len() as u16,
        0xCAFE,
    );
    let mut frame = [0u8; 14 + 20 + 16];
    net::ethernet::EthHdr::write_to(
        net::MacAddr(gw_mac), net::MacAddr(our_mac),
        net::eth_p::IPV4, &mut frame[..14],
    );
    ip_hdr.write_to(&mut frame[14..14 + 20]);
    frame[14 + 20..].copy_from_slice(&icmp_buf);

    out.tx_attempted = true;
    match tx_frame(&frame) {
        Ok(TxOutcome::Confirmed) => out.tx_confirmed = true,
        Ok(TxOutcome::Timeout)   => out.tx_confirmed = false,
        Err(_)                   => { out.tx_attempted = false; return out; }
    }

    let mut reply_seen = false;
    let mut frames_total = 0usize;
    let mut drained_total = 0usize;
    let mut spin_used = 0usize;
    let _ = Ordering::Relaxed; // silence unused warning if spin_used unused
    for _ in 0..50usize {
        for _ in 0..1_000_000usize {
            core::hint::spin_loop();
            spin_used = spin_used.wrapping_add(1);
        }
        let drained = rx_poll(|f: &[u8]| {
            frames_total += 1;
            if f.len() < 14 + 20 + 8 { return; }
            let et = ((f[12] as u16) << 8) | (f[13] as u16);
            if et != IPV4_ETHERTYPE { return; }
            let ip_hdr = match net::ipv4::Ipv4Hdr::parse(&f[14..14 + 20]) {
                Ok(h) => h, Err(_) => return,
            };
            if ip_hdr.proto != IPV4_PROTO_ICMP { return; }
            let total = ip_hdr.total_len as usize;
            if 14 + total > f.len() { return; }
            let icmp_body = &f[14 + 20..14 + total];
            if let Ok(reply) = net::icmp::IcmpEcho::parse(icmp_body) {
                if reply.typ == net::icmp::ICMP_TYPE_ECHO_REPLY
                    && reply.id == echo_id
                    && reply.seq == echo_seq
                {
                    reply_seen = true;
                }
            }
        });
        drained_total += drained;
        if reply_seen { break; }
    }
    out.rx_frames   = drained_total.max(frames_total);
    out.reply_seen  = reply_seen;
    out.round_trips = if reply_seen { spin_used } else { 0 };
    out
}

// -------- DHCP DISCOVER ---------------------------------------------

const DHCP_OP_BOOTREQUEST: u8 = 1;
const DHCP_OP_BOOTREPLY:   u8 = 2;
const DHCP_HW_ETHER:       u8 = 1;
const DHCP_MAGIC: [u8; 4]    = [0x63, 0x82, 0x53, 0x63];
const DHCP_OPT_MSGTYPE:    u8 = 53;
const DHCP_OPT_END:        u8 = 0xFF;
const DHCP_MSG_DISCOVER:   u8 = 1;
const DHCP_MSG_OFFER:      u8 = 2;
const DHCP_MSG_ACK:        u8 = 5;
const DHCP_FIXED_LEN:    usize = 240;

#[derive(Copy, Clone, Debug)]
pub struct DhcpDiscoverResult {
    pub tx_attempted: bool,
    pub tx_confirmed: bool,
    pub rx_frames:    usize,
    pub offer_seen:   bool,
    pub offered_ip:   [u8; 4],
    pub server_ip:    [u8; 4],
}

/// Send a DHCPDISCOVER, poll for OFFER. v1 single-shot.
/// # C: O(rx_drain)
pub fn boot_dhcp_discover() -> DhcpDiscoverResult {
    let mut out = DhcpDiscoverResult {
        tx_attempted: false, tx_confirmed: false, rx_frames: 0,
        offer_seen: false, offered_ip: [0; 4], server_ip: [0; 4],
    };
    let our_mac = match mac() { Some(m) => m, None => return out };

    let xid: u32 = 0xDECA_F0DE;
    let opts_len = 4 + 3 + 1;
    let dhcp_len = DHCP_FIXED_LEN + opts_len;
    let mut dhcp = alloc::vec![0u8; dhcp_len];
    dhcp[0] = DHCP_OP_BOOTREQUEST;
    dhcp[1] = DHCP_HW_ETHER;
    dhcp[2] = 6;
    dhcp[4..8].copy_from_slice(&xid.to_be_bytes());
    dhcp[10] = 0x80;
    dhcp[28..34].copy_from_slice(&our_mac);
    dhcp[240..244].copy_from_slice(&DHCP_MAGIC);
    dhcp[244] = DHCP_OPT_MSGTYPE;
    dhcp[245] = 1;
    dhcp[246] = DHCP_MSG_DISCOVER;
    dhcp[247] = DHCP_OPT_END;

    let udp_len = 8 + dhcp_len as u16;
    let mut udp = alloc::vec![0u8; udp_len as usize];
    udp[0..2].copy_from_slice(&68u16.to_be_bytes());
    udp[2..4].copy_from_slice(&67u16.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes());
    udp[8..].copy_from_slice(&dhcp);

    let ip_hdr = net::ipv4::Ipv4Hdr::build(
        net::Ipv4Addr::new(0, 0, 0, 0),
        net::Ipv4Addr::new(255, 255, 255, 255),
        net::IpProto::Udp, udp_len, 0xDECA,
    );

    let frame_len = 14 + 20 + udp_len as usize;
    let mut frame = alloc::vec![0u8; frame_len];
    net::ethernet::EthHdr::write_to(
        net::MacAddr([0xFF; 6]), net::MacAddr(our_mac),
        net::eth_p::IPV4, &mut frame[..14],
    );
    ip_hdr.write_to(&mut frame[14..14 + 20]);
    frame[14 + 20..].copy_from_slice(&udp);

    out.tx_attempted = true;
    match tx_frame(&frame) {
        Ok(TxOutcome::Confirmed) => out.tx_confirmed = true,
        Ok(TxOutcome::Timeout)   => out.tx_confirmed = false,
        Err(_)                   => { out.tx_attempted = false; return out; }
    }

    let mut offer_seen = false;
    let mut offered_ip: [u8; 4] = [0; 4];
    let mut server_ip:  [u8; 4] = [0; 4];
    let mut frames_total = 0usize;
    let mut drained_total = 0usize;
    for _ in 0..50usize {
        for _ in 0..1_000_000usize { core::hint::spin_loop(); }
        let drained = rx_poll(|f: &[u8]| {
            frames_total += 1;
            if f.len() < 14 + 20 + 8 + DHCP_FIXED_LEN { return; }
            let et = ((f[12] as u16) << 8) | (f[13] as u16);
            if et != IPV4_ETHERTYPE { return; }
            let ip_hdr = match net::ipv4::Ipv4Hdr::parse(&f[14..14 + 20]) {
                Ok(h) => h, Err(_) => return,
            };
            if ip_hdr.proto != net::IpProto::Udp as u8 { return; }
            let udp_off = 14 + 20;
            let src_port = ((f[udp_off] as u16) << 8) | (f[udp_off + 1] as u16);
            let dst_port = ((f[udp_off + 2] as u16) << 8) | (f[udp_off + 3] as u16);
            if src_port != 67 || dst_port != 68 { return; }
            let dhcp_off = udp_off + 8;
            if f.len() < dhcp_off + DHCP_FIXED_LEN + 4 { return; }
            if f[dhcp_off] != DHCP_OP_BOOTREPLY { return; }
            let xid_rx = u32::from_be_bytes([
                f[dhcp_off + 4], f[dhcp_off + 5],
                f[dhcp_off + 6], f[dhcp_off + 7],
            ]);
            if xid_rx != xid { return; }
            if f[dhcp_off + 236..dhcp_off + 240] != DHCP_MAGIC { return; }
            let mut o = dhcp_off + 240;
            let mut msg = 0u8;
            while o + 1 < f.len() && f[o] != DHCP_OPT_END {
                if f[o] == 0 { o += 1; continue; }
                let len = f[o + 1] as usize;
                if o + 2 + len > f.len() { break; }
                if f[o] == DHCP_OPT_MSGTYPE && len >= 1 {
                    msg = f[o + 2];
                }
                o += 2 + len;
            }
            // QEMU libslirp collapses DHCPOFFER+DHCPACK into a
            // single ACK on DISCOVER; accept either as our offer.
            if msg == DHCP_MSG_OFFER || msg == DHCP_MSG_ACK {
                offer_seen = true;
                offered_ip.copy_from_slice(&f[dhcp_off + 16..dhcp_off + 20]);
                server_ip .copy_from_slice(&f[dhcp_off + 20..dhcp_off + 24]);
            }
        });
        drained_total += drained;
        if offer_seen { break; }
    }
    out.rx_frames   = drained_total.max(frames_total);
    out.offer_seen  = offer_seen;
    out.offered_ip  = offered_ip;
    out.server_ip   = server_ip;
    let _ = VIRTIO_NET_HDR_LEN;
    out
}
