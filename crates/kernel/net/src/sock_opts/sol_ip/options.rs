// IPv4 header option area: the compile pass `setsockopt(IP_OPTIONS)` runs over
// caller bytes, and the inverse pass `getsockopt(IP_OPTIONS)` runs before
// handing the area back. No target gate — the whole decision is hosted-testable.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::uapi::*;

/// Everything the compile pass learns about one option area. Offsets are
/// relative to the START of the option area, so `None` and offset zero stay
/// distinguishable. # C: O(1)
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Compiled {
    pub data: Vec<u8>,
    /// Source-route option offset, plus its first hop lifted out of the list.
    pub srr: Option<usize>,
    pub is_strictroute: bool,
    pub faddr: [u8; 4],
    pub rr: Option<usize>,
    pub rr_needaddr: bool,
    pub ts: Option<usize>,
    pub ts_needtime: bool,
    pub ts_needaddr: bool,
    pub router_alert: Option<usize>,
    pub cipso: Option<usize>,
}

impl Compiled {
    /// Option-area length, always a multiple of four. # C: O(1)
    pub fn len(&self) -> usize { self.data.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.data.is_empty() }
}

/// Route classification the timestamp option's prespecified-address form asks
/// for. Supplying `false` for every address keeps the option in the "still
/// needs a stamp" state the compile pass would otherwise skip. # C: O(1)
pub trait AddrClass { fn is_unicast(&self, addr: [u8; 4]) -> bool; }

/// The classification a socket that cannot consult a routing table uses.
pub struct NoUnicast;
impl AddrClass for NoUnicast { fn is_unicast(&self, _addr: [u8; 4]) -> bool { false } }

/// `ip_options_get`: pad the caller's area to a four-byte multiple, compile it,
/// then gate a source route on `CAP_NET_RAW`. An over-long area is refused
/// before anything is parsed. # C: O(optlen)
pub fn build(bytes: &[u8], net_raw: bool) -> Result<Compiled, Errno> {
    build_with(bytes, net_raw, &NoUnicast)
}

/// [`build`] against a caller-supplied address classification. # C: O(optlen)
pub fn build_with(bytes: &[u8], net_raw: bool, class: &dyn AddrClass)
    -> Result<Compiled, Errno>
{
    if bytes.len() > MAX_IPOPTLEN { return Err(Errno::Einval); }
    let mut data = Vec::from(bytes);
    while data.len() & 3 != 0 { data.push(IPOPT_END); }
    if data.is_empty() { return Ok(Compiled::default()); }
    let mut out = compile(data, net_raw, class)?;
    // A source route is a privileged construction, refused only AFTER the area
    // parses: a malformed area carrying one still answers the parse error.
    if out.srr.is_some() && !net_raw { return Err(Errno::Eperm); }
    out.data.truncate(out.data.len());
    Ok(out)
}

/// `__ip_options_compile` with no packet in hand. Every structural rejection
/// is one errno — the parameter-problem pointer a router would emit has no
/// socket-visible form. # C: O(optlen)
fn compile(mut data: Vec<u8>, net_raw: bool, class: &dyn AddrClass)
    -> Result<Compiled, Errno>
{
    let mut c = Compiled::default();
    let total = data.len();
    let mut at = 0usize;
    while at < total {
        let left = total - at;
        match data[at] {
            IPOPT_END => { for b in data[at..].iter_mut() { *b = IPOPT_END; } break; }
            IPOPT_NOOP => { at += 1; continue; }
            _ => {}
        }
        if left < 2 { return Err(Errno::Einval); }
        let optlen = data[at + 1] as usize;
        if optlen < 2 || optlen > left { return Err(Errno::Einval); }
        match data[at] {
            IPOPT_SSRR | IPOPT_LSRR => {
                if optlen < 3 { return Err(Errno::Einval); }
                if data[at + 2] < 4 { return Err(Errno::Einval); }
                if c.srr.is_some() { return Err(Errno::Einval); }
                // Without a packet the pointer must still name the first hop,
                // which is then lifted out of the list and carried separately.
                if data[at + 2] != 4 || optlen < 7 || (optlen - 3) & 3 != 0 {
                    return Err(Errno::Einval);
                }
                c.faddr.copy_from_slice(&data[at + 3..at + 7]);
                if optlen > 7 { data.copy_within(at + 7..at + optlen, at + 3); }
                c.is_strictroute = data[at] == IPOPT_SSRR;
                c.srr = Some(at);
            }
            IPOPT_RR => {
                if c.rr.is_some() { return Err(Errno::Einval); }
                if optlen < 3 { return Err(Errno::Einval); }
                if data[at + 2] < 4 { return Err(Errno::Einval); }
                let ptr = data[at + 2] as usize;
                if ptr <= optlen {
                    if ptr + 3 > optlen { return Err(Errno::Einval); }
                    data[at + 2] += 4;
                    c.rr_needaddr = true;
                }
                c.rr = Some(at);
            }
            IPOPT_TIMESTAMP => {
                if c.ts.is_some() { return Err(Errno::Einval); }
                if optlen < 4 { return Err(Errno::Einval); }
                if data[at + 2] < 5 { return Err(Errno::Einval); }
                let ptr = data[at + 2] as usize;
                if ptr <= optlen {
                    if ptr + 3 > optlen { return Err(Errno::Einval); }
                    match data[at + 3] & 0xf {
                        IPOPT_TS_TSONLY => { c.ts_needtime = true; data[at + 2] += 4; }
                        IPOPT_TS_TSANDADDR => {
                            if ptr + 7 > optlen { return Err(Errno::Einval); }
                            c.ts_needaddr = true;
                            c.ts_needtime = true;
                            data[at + 2] += 8;
                        }
                        IPOPT_TS_PRESPEC => {
                            if ptr + 7 > optlen { return Err(Errno::Einval); }
                            let mut addr = [0u8; 4];
                            addr.copy_from_slice(&data[at + ptr - 1..at + ptr + 3]);
                            // A prespecified unicast hop is already this
                            // router's stamp slot, so the area is left alone.
                            if !class.is_unicast(addr) {
                                c.ts_needtime = true;
                                data[at + 2] += 8;
                            }
                        }
                        // Any other flag nibble is a privileged construction.
                        _ => { if !net_raw { return Err(Errno::Einval); } }
                    }
                } else if data[at + 3] & 0xf != IPOPT_TS_PRESPEC {
                    if data[at + 3] >> 4 == 15 { return Err(Errno::Einval); }
                }
                c.ts = Some(at);
            }
            IPOPT_RA => {
                if optlen < 4 { return Err(Errno::Einval); }
                if data[at + 2] == 0 && data[at + 3] == 0 { c.router_alert = Some(at); }
            }
            IPOPT_CIPSO => {
                if !net_raw || c.cipso.is_some() { return Err(Errno::Einval); }
                c.cipso = Some(at);
                if cipso_validate(&data[at..at + optlen]) != 0 { return Err(Errno::Einval); }
            }
            // Security, stream identifier and every unassigned kind are
            // privileged constructions.
            _ => { if !net_raw { return Err(Errno::Einval); } }
        }
        at += optlen;
    }
    c.data = data;
    Ok(c)
}

/// Structural screen for a commercial-security option: a header, a non-zero
/// domain of interpretation, then a well-formed tag chain. Returns the offset
/// of the first malformed byte, zero when the option is sound. # C: O(optlen)
fn cipso_validate(opt: &[u8]) -> usize {
    let opt_len = opt[1] as usize;
    if opt_len < 8 { return 1; }
    if u32::from_be_bytes([opt[2], opt[3], opt[4], opt[5]]) == 0 { return 2; }
    let mut at = 6usize;
    while at < opt_len {
        if at + 1 == opt_len { return at; }
        let tag_len = opt[at + 1] as usize;
        if tag_len == 0 || tag_len > opt_len - at { return at + 1; }
        at += tag_len;
    }
    0
}

/// `ip_options_undo`: return the area to the shape the caller supplied, so a
/// `getsockopt` round-trip reproduces the `setsockopt` bytes. # C: O(optlen)
pub fn undo(c: &Compiled) -> Vec<u8> {
    let mut data = c.data.clone();
    if let Some(at) = c.srr {
        let optlen = data[at + 1] as usize;
        data.copy_within(at + 3..at + optlen - 4, at + 7);
        data[at + 3..at + 7].copy_from_slice(&c.faddr);
    }
    if c.rr_needaddr {
        if let Some(at) = c.rr { retract(&mut data, at); }
    }
    if let Some(at) = c.ts {
        if c.ts_needtime {
            retract(&mut data, at);
            if data[at + 3] & 0xf == IPOPT_TS_PRESPEC { data[at + 2] -= 4; }
        }
        if c.ts_needaddr { retract(&mut data, at); }
    }
    data
}

/// Step one option's fill pointer back over a four-byte slot and clear it.
/// # C: O(1)
fn retract(data: &mut [u8], at: usize) {
    data[at + 2] -= 4;
    let slot = at + data[at + 2] as usize - 1;
    data[slot..slot + 4].fill(0);
}
