// `earlycon` / `earlyprintk` boot-parameter decoding.
//
// The decision this module makes is: given a command line, which UART does
// the boot console drive, how is it addressed, and at what baud. It owns no
// hardware and no globals — the arch boot crate takes the returned spec and
// programs the port. Keeping the decision here is what makes the whole
// grammar hosted-testable; the arch side is then a shim with nothing to get
// wrong except the register writes.
//
// Accepted forms (a boot console is requested by any one of them):
//   earlycon
//   earlycon=<name>
//   earlycon=<name>,<options>
//   earlycon=<name>,0x<addr>[,<options>]
//   earlycon=<name>,io|mmio|mmio16|mmio32|mmio32be|mmio32native,<addr>[,<options>]
//   console=<name>,...            (same grammar, when <name> is a UART driver)
//   earlyprintk=serial[,ttyS<n>|0x<port>][,<baud>][,keep]
//   earlyprintk=ttyS<n>[,<baud>]
//   earlyprintk=mmio32,0x<addr>[,<baud>]
// `<options>` is `<baud>` optionally followed by `,<uartclk>`.

use crate::token::{bare_flag, find, parse_uint, split_comma, tokens, split_token, value};

/// How the UART's registers are reached.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoType {
    /// x86 port-mapped I/O (`io,`).
    Port,
    /// Memory-mapped, one byte per register (`mmio,`).
    Mem,
    /// Memory-mapped, registers 2 bytes apart (`mmio16,`).
    Mem16,
    /// Memory-mapped, registers 4 bytes apart, little-endian (`mmio32,`).
    Mem32,
    /// Memory-mapped, registers 4 bytes apart, big-endian (`mmio32be,`).
    Mem32Be,
}

impl IoType {
    /// Register stride in bytes for this access type.
    /// # C: O(1)
    pub fn stride(self) -> u32 {
        match self { IoType::Port | IoType::Mem => 1, IoType::Mem16 => 2, IoType::Mem32 | IoType::Mem32Be => 4 }
    }
}

/// Which UART programming model the named driver uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Driver {
    /// 8250/16550-compatible register file.
    Uart8250,
    /// PrimeCell PL011 register file.
    Pl011,
}

/// A fully resolved boot-console request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EarlyconSpec {
    pub driver: Driver,
    pub iotype: IoType,
    pub addr: u64,
    pub baud: u32,
}

/// Platform fallback used when the parameter names a driver but no address,
/// or when a bare `earlycon` asks for "the platform's boot UART". The arch
/// boot crate supplies its own; keeping it a parameter is what lets the
/// grammar be tested for both arches from one hosted test binary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArchDefaults {
    pub driver: Driver,
    pub iotype: IoType,
    pub addr: u64,
}

/// Baud assumed when a parameter names no rate.
pub const DEFAULT_BAUD: u32 = 115_200;

/// Second 8250 port-I/O base, reachable as `earlyprintk=ttyS1`.
const COM2_PORT: u64 = 0x2f8;

/// Map an `earlycon=` driver name to its programming model. Names are the
/// ones the parameter grammar accepts; an unknown name is not a UART and
/// must not silently become one.
/// # C: O(1)
pub fn driver_for_name(name: &[u8]) -> Option<Driver> {
    match name {
        b"uart" | b"uart8250" | b"ns16550" | b"ns16550a" | b"8250" => Some(Driver::Uart8250),
        b"pl011" => Some(Driver::Pl011),
        _ => None,
    }
}

/// Decode the `io|mmio…` keyword that may lead the options field.
/// Returns the io type and the remaining bytes after the keyword's comma.
fn iotype_prefix(rest: &[u8]) -> Option<(IoType, &[u8])> {
    const TABLE: [(&[u8], IoType); 6] = [
        (b"mmio32native,", IoType::Mem32),
        (b"mmio32be,", IoType::Mem32Be),
        (b"mmio32,", IoType::Mem32),
        (b"mmio16,", IoType::Mem16),
        (b"mmio,", IoType::Mem),
        (b"io,", IoType::Port),
    ];
    for (tag, io) in TABLE {
        if rest.len() >= tag.len() && &rest[..tag.len()] == tag { return Some((io, &rest[tag.len()..])); }
    }
    None
}

/// Parse the value of an `earlycon=`/`console=` token into a spec.
/// `None` when the name is not a UART driver this kernel can program — the
/// caller must then leave the boot console unregistered rather than guess.
/// # C: O(len)
pub fn parse_earlycon(val: &[u8], def: ArchDefaults) -> Option<EarlyconSpec> {
    let (name, rest) = split_comma(val);
    let driver = driver_for_name(name)?;
    // A named driver with no address inherits the platform address only when
    // it is the platform's own driver; a different driver at an unknown
    // address has nowhere to write.
    let fallback_addr = if driver == def.driver { def.addr } else { 0 };
    let fallback_io = if driver == def.driver { def.iotype } else { IoType::Mem };
    let mut spec = EarlyconSpec { driver, iotype: fallback_io, addr: fallback_addr, baud: DEFAULT_BAUD };
    let Some(rest) = rest else { return Some(spec) };

    let opts = if let Some((io, after)) = iotype_prefix(rest) {
        spec.iotype = io;
        let (v, n) = parse_uint(after);
        if n == 0 { return None; }
        spec.addr = v;
        after.get(n..).map(|t| t.strip_prefix(b",").unwrap_or(t)).filter(|t| !t.is_empty() && n < after.len())
    } else if rest.len() > 2 && rest[0] == b'0' && (rest[1] | 0x20) == b'x' {
        spec.iotype = IoType::Mem;
        let (v, n) = parse_uint(rest);
        if n == 0 { return None; }
        spec.addr = v;
        rest.get(n..).map(|t| t.strip_prefix(b",").unwrap_or(t)).filter(|t| !t.is_empty() && n < rest.len())
    } else {
        Some(rest)
    };

    if let Some(opts) = opts {
        let (baud_field, _clk) = split_comma(opts);
        let (v, n) = parse_uint(baud_field);
        if n != 0 && v != 0 { spec.baud = v as u32; }
    }
    Some(spec)
}

/// Parse the value of an `earlyprintk=` token. The x86 spelling predates
/// `earlycon` and names the port by tty index or raw address rather than by
/// io-type keyword.
/// # C: O(len)
pub fn parse_earlyprintk(val: &[u8], def: ArchDefaults) -> Option<EarlyconSpec> {
    let mut spec = EarlyconSpec { driver: def.driver, iotype: def.iotype, addr: def.addr, baud: DEFAULT_BAUD };
    let mut rest: &[u8] = val;
    if let Some(after) = strip(rest, b"mmio32") {
        spec.driver = Driver::Uart8250;
        spec.iotype = IoType::Mem32;
        rest = after.strip_prefix(b",").unwrap_or(after);
        let (v, n) = parse_uint(rest);
        if n == 0 { return None; }
        spec.addr = v;
        rest = &rest[n..];
    } else {
        if let Some(after) = strip(rest, b"serial") { rest = after.strip_prefix(b",").unwrap_or(after); }
        else if find(rest, b"ttyS").is_none() && !rest.starts_with(b"0x") && !rest.is_empty() && rest != b"keep" {
            // Neither `serial`, a ttyS index, nor an address: not a serial
            // request (vga/dbgp/xen spellings name hardware we do not drive).
            return None;
        }
        if let Some(after) = strip(rest, b"ttyS") {
            spec.driver = Driver::Uart8250;
            spec.iotype = IoType::Port;
            let (idx, n) = parse_uint(after);
            spec.addr = if n != 0 && idx == 1 { COM2_PORT } else { def.addr };
            rest = &after[n..];
        } else if rest.starts_with(b"0x") {
            spec.driver = Driver::Uart8250;
            spec.iotype = IoType::Port;
            let (v, n) = parse_uint(rest);
            if n == 0 { return None; }
            spec.addr = v;
            rest = &rest[n..];
        }
    }
    let rest = rest.strip_prefix(b",").unwrap_or(rest);
    let (baud_field, _) = split_comma(rest);
    if baud_field != b"keep" {
        let (v, n) = parse_uint(baud_field);
        if n != 0 && v != 0 { spec.baud = v as u32; }
    }
    Some(spec)
}

fn strip<'a>(s: &'a [u8], tag: &[u8]) -> Option<&'a [u8]> {
    if s.len() >= tag.len() && &s[..tag.len()] == tag { Some(&s[tag.len()..]) } else { None }
}

/// Resolve the whole command line to a boot-console request, in the order
/// the parameters take precedence: an explicit `earlycon=` first, then a
/// bare `earlycon`, then `earlyprintk=`, then a `console=` whose device name
/// is a UART driver rather than a tty class.
/// # C: O(line length)
pub fn earlycon_request(line: &[u8], def: ArchDefaults) -> Option<EarlyconSpec> {
    if let Some(v) = value(line, b"earlycon") { if let Some(s) = parse_earlycon(v, def) { return Some(s); } }
    if bare_flag(line, b"earlycon") {
        return Some(EarlyconSpec { driver: def.driver, iotype: def.iotype, addr: def.addr, baud: DEFAULT_BAUD });
    }
    if let Some(v) = value(line, b"earlyprintk") { if let Some(s) = parse_earlyprintk(v, def) { return Some(s); } }
    if bare_flag(line, b"earlyprintk") {
        return Some(EarlyconSpec { driver: def.driver, iotype: def.iotype, addr: def.addr, baud: DEFAULT_BAUD });
    }
    for token in tokens(line) {
        let (key, val) = split_token(token);
        if key != b"console" { continue; }
        let Some(val) = val else { continue };
        if driver_for_name(split_comma(val).0).is_some() { if let Some(s) = parse_earlycon(val, def) { return Some(s); } }
    }
    None
}

/// Does the command line ask for the boot console to survive registration of
/// the real console? `keep_bootcon`, or the `keep` suffix on `earlyprintk=`.
/// Without it the boot console is dropped once a real console takes over, so
/// anything logged in the handover window reaches no wire at all.
/// # C: O(line length)
pub fn keep_bootcon(line: &[u8]) -> bool {
    if bare_flag(line, b"keep_bootcon") { return true; }
    match value(line, b"earlyprintk") { Some(v) => find(v, b"keep").is_some(), None => false }
}
