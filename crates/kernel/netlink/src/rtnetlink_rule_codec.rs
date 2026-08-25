use super::*;

pub mod fra {
    pub const FRA_FWMARK:   u16 = 10;
    pub const FRA_PRIORITY: u16 = 6;
    pub const FRA_TABLE:    u16 = 15;
    pub const FRA_FWMASK:   u16 = 16;
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FibRuleHdr {
    pub family:  u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos:     u8,
    pub table:   u8,
    pub res1:    u8,
    pub res2:    u8,
    pub action:  u8,
    pub flags:   u32,
}

impl FibRuleHdr {
    pub const SIZE: usize = 12;

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.family;
        buf[1] = self.dst_len;
        buf[2] = self.src_len;
        buf[3] = self.tos;
        buf[4] = self.table;
        buf[5] = self.res1;
        buf[6] = self.res2;
        buf[7] = self.action;
        buf[8..12].copy_from_slice(&self.flags.to_ne_bytes());
    }
}

/// Build one RTM_NEWRULE reply.
/// # C: O(N attrs)
pub(crate) fn build_newrule_reply(seq: u32, pid: u32, row: RuleRow, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(32);
    let frh = FibRuleHdr {
        family: row.family,
        dst_len: row.dst_len,
        src_len: row.src_len,
        tos: row.tos,
        table: if row.table <= u8::MAX as u32 { row.table as u8 } else { 0 },
        action: row.action,
        flags: row.flags,
        ..FibRuleHdr::default()
    };
    let mut frh_buf = [0u8; FibRuleHdr::SIZE];
    frh.write_to(&mut frh_buf);
    body.extend_from_slice(&frh_buf);
    put_nlattr_u32(&mut body, fra::FRA_PRIORITY, row.priority);
    put_nlattr_u32(&mut body, fra::FRA_TABLE, row.table);
    if row.fwmask != 0 {
        put_nlattr_u32(&mut body, fra::FRA_FWMARK, row.fwmark);
        put_nlattr_u32(&mut body, fra::FRA_FWMASK, row.fwmask);
    }

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: RTM_NEWRULE,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum ParseRuleError { Malformed, UnsupportedFamily }

fn parse_rule_attrs(attrs: &[u8]) -> Result<(Option<u32>, Option<u32>, Option<u32>, Option<u32>), ParseRuleError> {
    let mut priority = None;
    let mut table = None;
    let mut fwmark = None;
    let mut fwmask = None;
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { return Err(ParseRuleError::Malformed); }
        let next = off.checked_add(nlmsg_align(nla_len)).ok_or(ParseRuleError::Malformed)?;
        if next > attrs.len() { return Err(ParseRuleError::Malformed); }
        let payload = &attrs[off + 4..off + nla_len];
        if matches!(nla_type, fra::FRA_PRIORITY | fra::FRA_TABLE | fra::FRA_FWMARK | fra::FRA_FWMASK) {
            if payload.len() != 4 { return Err(ParseRuleError::Malformed); }
            let value = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
            match nla_type {
                fra::FRA_PRIORITY => priority = Some(value),
                fra::FRA_TABLE => table = Some(value),
                fra::FRA_FWMARK => fwmark = Some(value),
                fra::FRA_FWMASK => fwmask = Some(value),
                _ => {}
            }
        }
        off = next;
    }
    if off != attrs.len() { return Err(ParseRuleError::Malformed); }
    Ok((priority, table, fwmark, fwmask))
}

pub(super) fn parse_rule(net_ns: u64, full_msg: &[u8])
    -> Result<(RuleRow, Option<u32>), ParseRuleError>
{
    let off = Nlmsghdr::SIZE;
    if full_msg.len() < off + FibRuleHdr::SIZE { return Err(ParseRuleError::Malformed); }
    let family = match full_msg[off] {
        AF_INET | AF_INET6 => full_msg[off],
        _ => return Err(ParseRuleError::UnsupportedFamily),
    };
    let attrs = &full_msg[off + FibRuleHdr::SIZE..];
    let (priority, attr_table, fwmark, fwmask) = parse_rule_attrs(attrs)?;
    let table = attr_table.unwrap_or(full_msg[off + 4] as u32);
    Ok((RuleRow {
        ns: net_ns,
        family,
        dst_len: full_msg[off + 1],
        src_len: full_msg[off + 2],
        tos: full_msg[off + 3],
        table,
        action: full_msg[off + 7],
        flags: u32::from_ne_bytes(full_msg[off + 8..off + 12].try_into().unwrap()),
        fwmark: fwmark.unwrap_or(0),
        fwmask: fwmask.unwrap_or_else(|| if fwmark.is_some() { u32::MAX } else { 0 }),
        priority: priority.unwrap_or(0),
    }, priority))
}
