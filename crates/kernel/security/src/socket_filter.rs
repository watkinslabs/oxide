//! Classic socket-filter verifier and interpreter (socket-filter UAPI).

extern crate alloc;

use alloc::vec::Vec;

const BPF_MAXINSNS: usize = 4096;
const BPF_MEMWORDS: usize = 16;
const INSN_SIZE: usize = 8;
const SKF_AD_OFF: u32 = 0xffff_f000;
const SKF_AD_PROTOCOL: u32 = 0;
const SKF_AD_PKTTYPE: u32 = 4;
const SKF_AD_IFINDEX: u32 = 8;
const SKF_AD_NLATTR: u32 = 12;
const SKF_AD_NLATTR_NEST: u32 = 16;
const SKF_AD_MARK: u32 = 20;
const SKF_AD_QUEUE: u32 = 24;
const SKF_AD_HATYPE: u32 = 28;
const SKF_AD_RXHASH: u32 = 32;
const SKF_AD_CPU: u32 = 36;
const SKF_AD_ALU_XOR_X: u32 = 40;
const SKF_AD_VLAN_TAG: u32 = 44;
const SKF_AD_VLAN_TAG_PRESENT: u32 = 48;
const SKF_AD_PAY_OFFSET: u32 = 52;
const SKF_AD_RANDOM: u32 = 56;
const SKF_AD_VLAN_TPID: u32 = 60;
const NLA_HDR_LEN: usize = 4;
const NLA_ALIGN_MASK: usize = 3;
const NLA_TYPE_MASK: u16 = 0x3fff;

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;
const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;
const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_MSH: u16 = 0xa0;
const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;
const BPF_A: u16 = 0x10;
const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_XOR: u16 = 0xa0;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VerifyError { Size, Opcode, Memory, Jump, DivideByZero, MissingReturn }

#[derive(Copy, Clone)]
struct Insn { code: u16, jt: u8, jf: u8, k: u32 }

/// Packet metadata visible to Linux classic socket-filter ancillary loads.
pub struct Context<'a> {
    pub packet: &'a [u8],
    pub protocol: u16,
    pub ifindex: Option<u32>,
    pub pay_offset: u32,
    pub hatype: u16,
    pub cpu: u32,
    pub random: u32,
}

impl<'a> Context<'a> {
    /// Build context for callers without skb metadata. # C: O(1)
    pub fn packet(packet: &'a [u8]) -> Self {
        Self {
            packet, protocol: 0, ifindex: None, pay_offset: 0, hatype: 0, cpu: 0, random: 0,
        }
    }
}

fn decode(bytes: &[u8]) -> Insn {
    Insn {
        code: u16::from_ne_bytes([bytes[0], bytes[1]]),
        jt: bytes[2], jf: bytes[3],
        k: u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    }
}

fn decode_all(insns: &[u8]) -> Result<Vec<Insn>, VerifyError> {
    if insns.is_empty() || insns.len() % INSN_SIZE != 0
        || insns.len() / INSN_SIZE > BPF_MAXINSNS
    { return Err(VerifyError::Size); }
    Ok(insns.chunks_exact(INSN_SIZE).map(decode).collect())
}

/// Verify one classic socket filter and reject every unsupported opcode. # C: O(insns)
pub fn verify(insns: &[u8]) -> Result<(), VerifyError> {
    let program = decode_all(insns)?;
    for (pc, insn) in program.iter().copied().enumerate() {
        let class = insn.code & 0x07;
        let mode = insn.code & 0xe0;
        let size = insn.code & 0x18;
        let src = insn.code & BPF_X;
        let op = insn.code & 0xf0;
        let valid = match class {
            BPF_LD => (matches!(mode, BPF_IMM | BPF_MEM | BPF_LEN) && size == BPF_W
                    || matches!(mode, BPF_ABS | BPF_IND) && matches!(size, BPF_W | BPF_H | BPF_B))
                && insn.code == BPF_LD | mode | size,
            BPF_LDX => (matches!(mode, BPF_IMM | BPF_MEM | BPF_LEN) && size == BPF_W
                    || mode == BPF_MSH && size == BPF_B)
                && insn.code == BPF_LDX | mode | size,
            BPF_ST | BPF_STX => insn.code == class,
            BPF_ALU => if op == BPF_NEG { insn.code == BPF_ALU | BPF_NEG }
                else { matches!(op, BPF_ADD | BPF_SUB | BPF_MUL | BPF_DIV | BPF_OR
                    | BPF_AND | BPF_LSH | BPF_RSH | BPF_MOD | BPF_XOR)
                    && insn.code == BPF_ALU | op | src },
            BPF_JMP => if op == BPF_JA { insn.code == BPF_JMP | BPF_JA }
                else { matches!(op, BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET)
                    && insn.code == BPF_JMP | op | src },
            BPF_RET => insn.code == BPF_RET | BPF_K || insn.code == BPF_RET | BPF_A,
            BPF_MISC => insn.code == BPF_MISC | BPF_TAX || insn.code == BPF_MISC | BPF_TXA,
            _ => false,
        };
        if !valid { return Err(VerifyError::Opcode); }
        if matches!(class, BPF_LD | BPF_LDX) && matches!(mode, BPF_ABS | BPF_IND | BPF_MSH)
            && insn.k >= SKF_AD_OFF
        {
            let ancillary = class == BPF_LD && mode == BPF_ABS
                && matches!(insn.k - SKF_AD_OFF,
                    SKF_AD_PROTOCOL | SKF_AD_PKTTYPE | SKF_AD_IFINDEX | SKF_AD_NLATTR
                    | SKF_AD_NLATTR_NEST | SKF_AD_MARK | SKF_AD_QUEUE | SKF_AD_HATYPE
                    | SKF_AD_RXHASH | SKF_AD_CPU | SKF_AD_ALU_XOR_X | SKF_AD_VLAN_TAG
                    | SKF_AD_VLAN_TAG_PRESENT | SKF_AD_PAY_OFFSET | SKF_AD_RANDOM
                    | SKF_AD_VLAN_TPID);
            if !ancillary { return Err(VerifyError::Opcode); }
        }
        if matches!(class, BPF_LD | BPF_LDX) && mode == BPF_MEM
            || matches!(class, BPF_ST | BPF_STX)
        {
            if insn.k as usize >= BPF_MEMWORDS { return Err(VerifyError::Memory); }
        }
        if class == BPF_ALU && src == BPF_K && matches!(op, BPF_DIV | BPF_MOD) && insn.k == 0 {
            return Err(VerifyError::DivideByZero);
        }
        if class == BPF_ALU && src == BPF_K && matches!(op, BPF_LSH | BPF_RSH) && insn.k >= 32 {
            return Err(VerifyError::Opcode);
        }
        if class == BPF_JMP {
            let remain = program.len() - pc - 1;
            if op == BPF_JA {
                if insn.k as usize >= remain { return Err(VerifyError::Jump); }
            } else if insn.jt as usize >= remain || insn.jf as usize >= remain {
                return Err(VerifyError::Jump);
            }
        }
    }
    if program.last().map(|i| i.code & 0x07) != Some(BPF_RET) {
        return Err(VerifyError::MissingReturn);
    }
    verify_initialized_memory(&program)?;
    Ok(())
}

fn merge_mask(slot: &mut Option<u16>, next: u16) {
    *slot = Some(match *slot { Some(current) => current & next, None => next });
}

fn verify_initialized_memory(program: &[Insn]) -> Result<(), VerifyError> {
    let mut incoming = alloc::vec![None; program.len()];
    incoming[0] = Some(0u16);
    for (pc, insn) in program.iter().copied().enumerate() {
        let Some(mut mask) = incoming[pc] else { continue };
        let class = insn.code & 0x07;
        let mode = insn.code & 0xe0;
        let op = insn.code & 0xf0;
        if matches!(class, BPF_LD | BPF_LDX) && mode == BPF_MEM
            && mask & (1u16 << insn.k) == 0
        {
            return Err(VerifyError::Memory);
        }
        if matches!(class, BPF_ST | BPF_STX) { mask |= 1u16 << insn.k; }
        if class == BPF_RET { continue; }
        if class == BPF_JMP && op == BPF_JA {
            merge_mask(&mut incoming[pc + 1 + insn.k as usize], mask);
        } else if class == BPF_JMP {
            merge_mask(&mut incoming[pc + 1 + insn.jt as usize], mask);
            merge_mask(&mut incoming[pc + 1 + insn.jf as usize], mask);
        } else {
            merge_mask(&mut incoming[pc + 1], mask);
        }
    }
    Ok(())
}

fn load(packet: &[u8], off: usize, size: u16) -> Option<u32> {
    match size {
        BPF_W => Some(u32::from_be_bytes(packet.get(off..off + 4)?.try_into().ok()?)),
        BPF_H => Some(u16::from_be_bytes(packet.get(off..off + 2)?.try_into().ok()?) as u32),
        BPF_B => Some(*packet.get(off)? as u32),
        _ => None,
    }
}

fn nla_at(packet: &[u8], off: usize) -> Option<(usize, u16)> {
    let header = packet.get(off..off.checked_add(NLA_HDR_LEN)?)?;
    let len = u16::from_ne_bytes([header[0], header[1]]) as usize;
    if len < NLA_HDR_LEN || len > packet.len() - off { return None; }
    Some((len, u16::from_ne_bytes([header[2], header[3]])))
}

fn nla_find(packet: &[u8], start: usize, end: usize, kind: u32) -> u32 {
    if kind > u16::MAX as u32 || start > end || end > packet.len() { return 0; }
    let mut off = start;
    while off.checked_add(NLA_HDR_LEN).is_some_and(|next| next <= end) {
        let Some((len, typ)) = nla_at(&packet[..end], off) else { return 0; };
        if typ & NLA_TYPE_MASK == kind as u16 { return off as u32; }
        let Some(step) = len.checked_add(NLA_ALIGN_MASK).map(|v| v & !NLA_ALIGN_MASK)
            else { return 0; };
        let Some(next) = off.checked_add(step) else { return 0; };
        if next > end { return 0; }
        off = next;
    }
    0
}

fn ancillary(ctx: &Context<'_>, kind: u32, a: u32, x: u32) -> Option<u32> {
    match kind {
        SKF_AD_PROTOCOL => Some(ctx.protocol as u32),
        SKF_AD_IFINDEX => ctx.ifindex,
        SKF_AD_HATYPE => Some(ctx.hatype as u32),
        SKF_AD_NLATTR => Some(nla_find(ctx.packet, a as usize, ctx.packet.len(), x)),
        SKF_AD_NLATTR_NEST => {
            let off = a as usize;
            let (len, _) = nla_at(ctx.packet, off)?;
            Some(nla_find(ctx.packet, off + NLA_HDR_LEN, off + len, x))
        }
        SKF_AD_PAY_OFFSET => Some(ctx.pay_offset),
        SKF_AD_CPU => Some(ctx.cpu),
        SKF_AD_RANDOM => Some(ctx.random),
        SKF_AD_PKTTYPE | SKF_AD_MARK | SKF_AD_QUEUE | SKF_AD_RXHASH
        | SKF_AD_VLAN_TAG | SKF_AD_VLAN_TAG_PRESENT | SKF_AD_VLAN_TPID => Some(0),
        _ => None,
    }
}

/// Run verified classic BPF over packet bytes and return its u32 verdict. # C: O(insns)
pub fn run(insns: &[u8], packet: &[u8]) -> u32 {
    run_with_context(insns, Context::packet(packet))
}

/// Run verified classic BPF with Linux skb ancillary metadata. # C: O(insns + packet)
pub fn run_with_context(insns: &[u8], ctx: Context<'_>) -> u32 {
    let Ok(program) = decode_all(insns) else { return 0; };
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; BPF_MEMWORDS];
    let mut pc = 0usize;
    while let Some(insn) = program.get(pc).copied() {
        let class = insn.code & 0x07;
        let mode = insn.code & 0xe0;
        let size = insn.code & 0x18;
        let src = insn.code & BPF_X;
        let op = insn.code & 0xf0;
        match class {
            BPF_LD => {
                if mode == BPF_ABS && insn.k >= SKF_AD_OFF {
                    let kind = insn.k - SKF_AD_OFF;
                    if kind == SKF_AD_ALU_XOR_X { a ^= x; }
                    else { a = match ancillary(&ctx, kind, a, x) { Some(v) => v, None => return 0 }; }
                    pc += 1;
                    continue;
                }
                a = match mode {
                    BPF_IMM => insn.k,
                    BPF_ABS => match load(ctx.packet, insn.k as usize, size) { Some(v) => v, None => return 0 },
                    BPF_IND => match (x as usize).checked_add(insn.k as usize)
                        .and_then(|off| load(ctx.packet, off, size))
                    { Some(v) => v, None => return 0 },
                    BPF_MEM => mem.get(insn.k as usize).copied().unwrap_or(0),
                    BPF_LEN => ctx.packet.len() as u32,
                    _ => return 0,
                };
                pc += 1;
            }
            BPF_LDX => {
                x = match mode {
                    BPF_IMM => insn.k,
                    BPF_MEM => mem.get(insn.k as usize).copied().unwrap_or(0),
                    BPF_LEN => ctx.packet.len() as u32,
                    BPF_MSH => match load(ctx.packet, insn.k as usize, BPF_B) {
                        Some(v) => (v & 0x0f) << 2, None => return 0,
                    },
                    _ => return 0,
                };
                pc += 1;
            }
            BPF_ST => { mem[insn.k as usize] = a; pc += 1; }
            BPF_STX => { mem[insn.k as usize] = x; pc += 1; }
            BPF_ALU => {
                let v = if src == BPF_X { x } else { insn.k };
                a = match op {
                    BPF_ADD => a.wrapping_add(v), BPF_SUB => a.wrapping_sub(v),
                    BPF_MUL => a.wrapping_mul(v), BPF_DIV => if v == 0 { return 0 } else { a / v },
                    BPF_OR => a | v, BPF_AND => a & v, BPF_LSH => a.checked_shl(v).unwrap_or(0),
                    BPF_RSH => a.checked_shr(v).unwrap_or(0), BPF_NEG => a.wrapping_neg(),
                    BPF_MOD => if v == 0 { return 0 } else { a % v }, BPF_XOR => a ^ v,
                    _ => return 0,
                };
                pc += 1;
            }
            BPF_JMP => {
                if op == BPF_JA { pc += 1 + insn.k as usize; continue; }
                let v = if src == BPF_X { x } else { insn.k };
                let take = match op {
                    BPF_JEQ => a == v, BPF_JGT => a > v, BPF_JGE => a >= v,
                    BPF_JSET => a & v != 0, _ => return 0,
                };
                pc += 1 + if take { insn.jt as usize } else { insn.jf as usize };
            }
            BPF_RET => return if insn.code == BPF_RET | BPF_A { a } else { insn.k },
            BPF_MISC => { if op == BPF_TAX { x = a; } else { a = x; } pc += 1; }
            _ => return 0,
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> [u8; 8] {
        let c = code.to_ne_bytes(); let k = k.to_ne_bytes();
        [c[0], c[1], jt, jf, k[0], k[1], k[2], k[3]]
    }

    #[test]
    fn packet_load_and_positive_verdict_work() {
        let mut p = Vec::new();
        p.extend_from_slice(&insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 8));
        p.extend_from_slice(&insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x61));
        p.extend_from_slice(&insn(BPF_RET | BPF_K, 0, 0, 11));
        p.extend_from_slice(&insn(BPF_RET | BPF_K, 0, 0, 0));
        assert_eq!(verify(&p), Ok(()));
        assert_eq!(run(&p, b"12345678abc"), 11);
        assert_eq!(run(&p, b"12345678xbc"), 0);
    }

    #[test]
    fn unsupported_and_invalid_programs_fail_at_load() {
        assert_eq!(verify(&insn(0xffff, 0, 0, 0)), Err(VerifyError::Opcode));
        let mut p = Vec::new();
        p.extend_from_slice(&insn(BPF_ALU | BPF_DIV | BPF_K, 0, 0, 0));
        p.extend_from_slice(&insn(BPF_RET | BPF_K, 0, 0, 1));
        assert_eq!(verify(&p), Err(VerifyError::DivideByZero));

        let mut uninitialized = Vec::new();
        uninitialized.extend_from_slice(&insn(BPF_LD | BPF_MEM, 0, 0, 0));
        uninitialized.extend_from_slice(&insn(BPF_RET | BPF_A, 0, 0, 0));
        assert_eq!(verify(&uninitialized), Err(VerifyError::Memory));

        let mut ancillary = Vec::new();
        ancillary.extend_from_slice(&insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF));
        ancillary.extend_from_slice(&insn(BPF_RET | BPF_A, 0, 0, 0));
        assert_eq!(verify(&ancillary), Ok(()));

        let mut unknown = Vec::new();
        unknown.extend_from_slice(&insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF + 64));
        unknown.extend_from_slice(&insn(BPF_RET | BPF_A, 0, 0, 0));
        assert_eq!(verify(&unknown), Err(VerifyError::Opcode));
    }

    #[test]
    fn return_accumulator_uses_classic_bpf_a_encoding() {
        let mut p = Vec::new();
        p.extend_from_slice(&insn(BPF_LD | BPF_IMM, 0, 0, 17));
        p.extend_from_slice(&insn(BPF_RET | BPF_A, 0, 0, 0));
        assert_eq!(verify(&p), Ok(()));
        assert_eq!(run(&p, &[]), 17);
        assert_eq!(verify(&insn(BPF_RET | BPF_X, 0, 0, 0)), Err(VerifyError::Opcode));
    }

    #[test]
    fn ancillary_protocol_xor_and_nlattr_follow_linux_semantics() {
        let mut protocol = Vec::new();
        protocol.extend_from_slice(&insn(
            BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_PROTOCOL,
        ));
        protocol.extend_from_slice(&insn(BPF_RET | BPF_A, 0, 0, 0));
        assert_eq!(run_with_context(&protocol, Context {
            packet: &[], protocol: 0x86dd, ifindex: Some(7), pay_offset: 8,
            hatype: 1, cpu: 2, random: 0x1234,
        }), 0x86dd);

        let mut xor = Vec::new();
        xor.extend_from_slice(&insn(BPF_LD | BPF_IMM, 0, 0, 4));
        xor.extend_from_slice(&insn(BPF_LDX | BPF_IMM, 0, 0, 3));
        xor.extend_from_slice(&insn(
            BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_ALU_XOR_X,
        ));
        xor.extend_from_slice(&insn(BPF_RET | BPF_A, 0, 0, 0));
        assert_eq!(run(&xor, &[]), 7);

        let mut nlattr = Vec::new();
        nlattr.extend_from_slice(&insn(BPF_LD | BPF_IMM, 0, 0, 0));
        nlattr.extend_from_slice(&insn(BPF_LDX | BPF_IMM, 0, 0, 3));
        nlattr.extend_from_slice(&insn(
            BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_NLATTR,
        ));
        nlattr.extend_from_slice(&insn(BPF_RET | BPF_A, 0, 0, 0));
        assert_eq!(run(&nlattr, &[4, 0, 1, 0, 4, 0, 3, 0]), 4);
    }
}
