//! `/proc/net/nf_conntrack` rendering. The format is load-bearing: `conntrack
//! -L` and every monitoring tool parse it positionally, so field order and
//! spacing are part of the ABI.

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use crate::entry::{Conn, ProtoState};
use crate::proto::tcp_state::TCP_STATE_NAMES;
use crate::tuple::{InetAddr, Tuple};
use crate::uapi::*;

fn proto_name(protonum: u8) -> &'static str {
    match protonum {
        IPPROTO_ICMP   => "icmp",
        IPPROTO_TCP    => "tcp",
        IPPROTO_UDP    => "udp",
        IPPROTO_GRE    => "gre",
        IPPROTO_ICMPV6 => "icmpv6",
        IPPROTO_SCTP   => "sctp",
        IPPROTO_UDPLITE => "udplite",
        _ => "unknown",
    }
}

fn l3_name(l3num: u8) -> &'static str {
    if l3num == NFPROTO_IPV6 { "ipv6" } else { "ipv4" }
}

/// Address in the textual form the proc file uses for its family. # C: O(1)
pub fn render_addr(a: &InetAddr, l3num: u8) -> String {
    if l3num == NFPROTO_IPV6 {
        let mut s = String::new();
        for i in 0..8 {
            if i > 0 { s.push(':'); }
            let g = u16::from_be_bytes([a.0[i * 2], a.0[i * 2 + 1]]);
            s.push_str(&format!("{g:x}"));
        }
        s
    } else {
        format!("{}.{}.{}.{}", a.0[0], a.0[1], a.0[2], a.0[3])
    }
}

/// One direction's `src=/dst=/sport=/dport=` group. ICMP replaces the port
/// pair with `type=/code=/id=`. # C: O(1)
pub fn render_tuple(t: &Tuple) -> String {
    let mut s = format!("src={} dst={}",
        render_addr(&t.src.addr, t.l3num), render_addr(&t.dst.addr, t.l3num));
    if t.is_icmp() {
        s.push_str(&format!(" type={} code={} id={}",
            t.dst.proto.icmp_type, t.dst.proto.icmp_code, t.src.proto.port));
    } else if matches!(t.protonum, IPPROTO_TCP | IPPROTO_UDP | IPPROTO_UDPLITE | IPPROTO_SCTP) {
        s.push_str(&format!(" sport={} dport={}", t.src.proto.port, t.dst.proto.port));
    }
    s
}

/// One entry's line, without the trailing newline. # C: O(1)
pub fn render_entry(c: &Arc<Conn>, now: u64, acct: bool) -> String {
    let t = &c.orig;
    let mut s = format!("{:<8} {} {:<3} {}",
        l3_name(t.l3num), l3num_number(t.l3num), t.protonum, proto_name(t.protonum));
    s.push_str(&format!(" {}", c.expires_in(now)));
    if let ProtoState::Tcp(track) = *c.proto.lock() {
        let name = TCP_STATE_NAMES.get(track.state as usize).copied().unwrap_or("NONE");
        s.push_str(&format!(" {name}"));
    }
    s.push(' ');
    s.push_str(&render_tuple(&c.orig));
    if acct {
        let (p, b) = c.counters[IP_CT_DIR_ORIGINAL as usize].read();
        s.push_str(&format!(" packets={p} bytes={b}"));
    }
    let status = c.status();
    // A flow that has never been answered is reported unreplied; tooling keys
    // on this token to distinguish a half-open attempt from a conversation.
    if status & IPS_SEEN_REPLY == 0 { s.push_str(" [UNREPLIED]"); }
    s.push(' ');
    s.push_str(&render_tuple(&c.reply));
    if acct {
        let (p, b) = c.counters[IP_CT_DIR_REPLY as usize].read();
        s.push_str(&format!(" packets={p} bytes={b}"));
    }
    if status & IPS_ASSURED != 0 { s.push_str(" [ASSURED]"); }
    if let Some(h) = c.helper.lock().as_ref() { s.push_str(&format!(" helper={h}")); }
    s.push_str(&format!(" mark={}", c.mark.load(core::sync::atomic::Ordering::Relaxed)));
    s.push_str(&format!(" use=1"));
    s
}

fn l3num_number(l3num: u8) -> u8 { if l3num == NFPROTO_IPV6 { 10 } else { 2 } }

/// Whole file body. # C: O(N)
pub fn render(entries: &[Arc<Conn>], now: u64, acct: bool) -> String {
    let mut out = String::new();
    for c in entries {
        out.push_str(&render_entry(c, now, acct));
        out.push('\n');
    }
    out
}

/// `/proc/net/nf_conntrack_expect` body. # C: O(N)
pub fn render_expectations(exps: &[crate::expect::Expectation], now: u64) -> String {
    let mut out = String::new();
    for e in exps {
        out.push_str(&format!("{} {} {} {} {}\n",
            e.timeout.saturating_sub(now),
            l3_name(e.tuple.l3num),
            e.tuple.protonum,
            proto_name(e.tuple.protonum),
            render_tuple(&e.tuple)));
    }
    out
}
