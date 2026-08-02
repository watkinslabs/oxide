// Network-protocol overhead a TCP connection carries ahead of its own header:
// the sticky IPv4 option area the socket installed. The reference keeps this
// as one per-connection length that every MSS computation subtracts, so the
// segments a connection emits still fit the path MTU once the option area is
// prepended.
//
// No target gate: the whole rule must run under hosted `cargo test`, unlike
// the option level that admits the areas (`sock_opts::sol_ip`).

/// Floor an MSS may not fall below once overhead is subtracted, in bytes.
/// Segments smaller than this carry too little data to make progress.
pub const TCP_MIN_SND_MSS: u16 = 48;

/// The IPv4 option area a compiled sticky option set prepends, in bytes.
/// # C: O(1)
pub fn ext_hdr_len(opts: Option<&crate::ipv4_options::Compiled>) -> u16 {
    opts.map_or(0, |c| c.len().min(u16::MAX as usize) as u16)
}

/// Subtract one connection's network-protocol overhead from an MSS derived
/// from path MTU, holding the result at the minimum send MSS. The floor
/// applies after the subtraction, so an option area wider than the path can
/// carry still leaves a segment able to make progress rather than an MSS of
/// zero. A zero input is the connection's "no path MTU known" sentinel, not a
/// tiny MSS, and stays zero. # C: O(1)
pub fn mss_minus_ext_hdr(mss: u16, ext_hdr_len: u16) -> u16 {
    if mss == 0 { return 0; }
    subtract_ext_hdr(mss, ext_hdr_len)
}

/// The same subtraction for an MSS that is already known to come from a real
/// path MTU, where zero is a legitimate arithmetic result rather than the
/// "unknown" sentinel. The floor runs after the subtraction, never before, so
/// the option area is charged in full. # C: O(1)
pub fn subtract_ext_hdr(mss: u16, ext_hdr_len: u16) -> u16 {
    mss.saturating_sub(ext_hdr_len).max(TCP_MIN_SND_MSS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled(bytes: &[u8]) -> crate::ipv4_options::Compiled {
        crate::ipv4_options::build_in(bytes, true, 0).unwrap()
    }

    #[test]
    fn no_option_area_costs_a_connection_nothing() {
        assert_eq!(ext_hdr_len(None), 0);
        assert_eq!(mss_minus_ext_hdr(1_460, 0), 1_460);
    }

    #[test]
    fn a_record_route_area_shrinks_the_mss_by_its_own_length() {
        // Record-route: kind 7, length 39, pointer 4, then 36 zero bytes. The
        // compiled area is padded to a four-byte multiple, so the cost is the
        // padded length, not the option's own.
        let mut area = alloc::vec![crate::ipv4_options::uapi::IPOPT_RR, 39, 4];
        area.extend_from_slice(&[0u8; 36]);
        let c = compiled(&area);
        let len = ext_hdr_len(Some(&c));
        assert_eq!(len as usize, c.len());
        assert_eq!(len % 4, 0);
        assert_eq!(mss_minus_ext_hdr(1_460, len), 1_460 - len);
    }

    #[test]
    fn the_minimum_send_mss_survives_an_option_area_wider_than_the_path() {
        assert_eq!(mss_minus_ext_hdr(60, 40), TCP_MIN_SND_MSS);
        assert_eq!(mss_minus_ext_hdr(20, 40), TCP_MIN_SND_MSS);
    }

    #[test]
    fn an_unknown_path_mtu_stays_unknown_rather_than_becoming_the_floor() {
        assert_eq!(mss_minus_ext_hdr(0, u16::MAX), 0);
        assert_eq!(mss_minus_ext_hdr(0, 0), 0);
    }
}
