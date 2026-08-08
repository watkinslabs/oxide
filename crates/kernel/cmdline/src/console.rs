// `console=` grammar: which device classes get printk fan-out, which device
// backs `/dev/console`, and the line settings a serial entry asks for.
//
// Grammar: `console=<device>[,<baud><parity><bits><flow>]`, e.g.
// `console=ttyS0,115200n8r`. Repeated entries all register; the LAST one
// backs `/dev/console`.

use crate::token::{split_comma, split_token, tokens};

/// Kind of console device named by a `console=` token.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsoleKind {
    /// A serial UART line (`ttyS<n>` 8250, `ttyAMA<n>` PL011).
    Serial,
    /// Video VT `n` — `tty0` = current foreground VT, `tty<n>` = VT n.
    Vt(u8),
}

/// Parity requested by a serial console's options field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Parity { None, Odd, Even }

/// Line settings a `console=<serial>,<options>` entry asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConsoleOptions {
    pub baud: u32,
    pub parity: Parity,
    pub bits: u8,
    /// RTS/CTS hardware flow control (`r` suffix).
    pub flow: bool,
}

impl ConsoleOptions {
    /// The settings assumed when a `console=` entry names no options.
    /// # C: O(1)
    pub const fn default_8n1() -> Self { ConsoleOptions { baud: 115_200, parity: Parity::None, bits: 8, flow: false } }
}

/// Decode `<baud><parity><bits><flow>` (`115200n8r`). Absent fields keep the
/// 8N1 defaults, so `console=ttyS0,9600` is a baud change and nothing else.
/// # C: O(len)
pub fn parse_options(opts: &[u8]) -> ConsoleOptions {
    let mut out = ConsoleOptions::default_8n1();
    let (v, n) = crate::token::parse_uint(opts);
    if n != 0 && v != 0 { out.baud = v as u32; }
    let mut rest = &opts[n..];
    if let Some(&c) = rest.first() {
        match c | 0x20 {
            b'n' => { out.parity = Parity::None; rest = &rest[1..]; }
            b'o' => { out.parity = Parity::Odd; rest = &rest[1..]; }
            b'e' => { out.parity = Parity::Even; rest = &rest[1..]; }
            _ => {}
        }
    }
    if let Some(&c) = rest.first() {
        if c.is_ascii_digit() { out.bits = c - b'0'; rest = &rest[1..]; }
    }
    if let Some(&c) = rest.first() { if c | 0x20 == b'r' { out.flow = true; } }
    out
}

/// Map a `console=` device name to its [`ConsoleKind`]. `ttyS*`/`ttyAMA*` are
/// serial; `tty0` is the foreground VT and `tty<n>` is VT n. A name this
/// kernel drives no console for yields `None` rather than a guess.
/// # C: O(len)
pub fn classify(name: &[u8]) -> Option<ConsoleKind> {
    if name.starts_with(b"ttyS") || name.starts_with(b"ttyAMA") || name.starts_with(b"ttyUSB") {
        return Some(ConsoleKind::Serial);
    }
    if let Some(rest) = name.strip_prefix(b"tty") {
        if !rest.is_empty() && rest.iter().all(|c| c.is_ascii_digit()) {
            let mut n: u32 = 0;
            for &c in rest { n = n.saturating_mul(10).saturating_add((c - b'0') as u32); }
            return Some(ConsoleKind::Vt(n.min(255) as u8));
        }
    }
    None
}

/// Iterate every `console=` entry as `(kind, options)`, in command-line order.
/// # C: O(line length)
pub fn entries(line: &[u8]) -> impl Iterator<Item = (ConsoleKind, ConsoleOptions)> + '_ {
    tokens(line).filter_map(|t| {
        let (key, val) = split_token(t);
        if key != b"console" { return None; }
        let val = val?;
        let (name, opts) = split_comma(val);
        let kind = classify(name)?;
        Some((kind, opts.map(parse_options).unwrap_or_else(ConsoleOptions::default_8n1)))
    })
}

/// The preferred console: the device named by the LAST `console=` entry,
/// which backs `/dev/console`. Falls back to the foreground video VT when no
/// parseable entry is present.
/// # C: O(cmdline length)
pub fn preferred_console() -> ConsoleKind { preferred_console_in(crate::get()) }

/// Global-free form of [`preferred_console`]. # C: O(line length)
pub fn preferred_console_in(line: &[u8]) -> ConsoleKind {
    entries(line).map(|(k, _)| k).last().unwrap_or(ConsoleKind::Vt(0))
}

/// Line settings of the last serial `console=` entry, or `None` when the line
/// names no serial console. # C: O(line length)
pub fn serial_options_in(line: &[u8]) -> Option<ConsoleOptions> {
    entries(line).filter(|(k, _)| *k == ConsoleKind::Serial).map(|(_, o)| o).last()
}

/// Does the cmdline request a printk console of each class? A `struct
/// console` is registered per `console=` entry; a class NOT named gets no
/// printk (its `/dev` tty still works). `(serial, vt)`. With NO parseable
/// entry both are true, matching the arch default's serial+VT pair.
/// # C: O(cmdline length)
pub fn console_classes() -> (bool, bool) { console_classes_in(crate::get()) }

/// Global-free form of [`console_classes`]. # C: O(line length)
pub fn console_classes_in(line: &[u8]) -> (bool, bool) {
    let mut serial = false;
    let mut vt = false;
    let mut any = false;
    for (kind, _) in entries(line) {
        match kind {
            ConsoleKind::Serial => { serial = true; any = true; }
            ConsoleKind::Vt(_) => { vt = true; any = true; }
        }
    }
    if !any { (true, true) } else { (serial, vt) }
}
