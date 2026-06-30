// tracefs event-filter predicate engine (Linux `kernel/trace/trace_events_
// filter.c`). Parses the trace-event filter grammar
//   expr := or ; or := and ("||" and)* ; and := unary ("&&" unary)*
//   unary := "!" unary | primary ; primary := "(" expr ")" | predicate
//   predicate := field OP value
// OPs: `== != < <= > >=` (integer fields) and `~` glob-match (string fields);
// `==`/`!=` also match string fields exactly. Field names are validated against
// the event's `format` field table (name/size/signed/is_string parsed from the
// `events/<sub>/<ev>/format` body) — an unknown field, a type/op mismatch, or a
// malformed expression is a parse error (the filer write then returns EINVAL
// and keeps the prior filter, mirroring Linux).
//
// `evaluate(&Ast, &EventRecord)` is consumed at record-emit time (`ring`): an
// enabled event carrying a compiled filter only records matching samples. The
// hot path stays lockless when no filter is set (`FilterSlot::has_filter`); a
// set filter is read under a `try_lock` that fails OPEN (records the sample)
// rather than block the context-switch path.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as TraceClass};

// ---- format field table ----------------------------------------------------

/// One declared `format` field: its name + whether it is a string (char array
/// or pointer) vs an integer. `size`/`signed` are retained for completeness.
/// # C: O(1)
#[derive(Clone, Debug)]
pub struct Field {
    pub name:      String,
    pub size:      usize,
    pub signed:    bool,
    pub is_string: bool,
}

/// Pull the integer after `key:` (e.g. `size:16`) from one `\t`-split token.
fn kv_num(tok: &str, key: &str) -> Option<usize> {
    tok.strip_prefix(key).and_then(|v| v.trim_end_matches(';').trim().parse().ok())
}

/// Parse a `format` body into its field table. Each field line is
/// `\tfield:TYPE NAME[;\toffset:..;\tsize:..;\tsigned:..]`. # C: O(format)
pub fn parse_fields(format: &[u8]) -> Vec<Field> {
    let text = core::str::from_utf8(format).unwrap_or("");
    let mut out = Vec::new();
    for line in text.lines() {
        let toks: Vec<&str> = line.split('\t').filter(|t| !t.is_empty()).collect();
        let mut decl: Option<&str> = None;
        let mut size = 0usize;
        let mut signed = false;
        for t in &toks {
            if let Some(d) = t.strip_prefix("field:") { decl = Some(d.trim_end_matches(';')); }
            else if let Some(n) = kv_num(t, "size:") { size = n; }
            else if let Some(n) = kv_num(t, "signed:") { signed = n != 0; }
        }
        let decl = match decl { Some(d) => d, None => continue };
        // decl = "TYPE ... NAME" possibly "NAME[16]". Name = last space-token,
        // with any trailing array `[..]` stripped.
        let last = decl.rsplit(' ').next().unwrap_or(decl);
        let is_array = last.contains('[');
        let name = last.split('[').next().unwrap_or(last).trim().to_string();
        if name.is_empty() { continue; }
        let type_part = &decl[..decl.len() - last.len()];
        let is_string = decl.contains("char") && (is_array || type_part.contains('*') || last.contains('*'));
        out.push(Field { name, size, signed, is_string });
    }
    out
}

// ---- AST -------------------------------------------------------------------

/// Integer comparison operator. # C: O(1)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntOp { Eq, Ne, Lt, Le, Gt, Ge }
impl IntOp { fn test(self, a: i64, b: i64) -> bool {
    match self { IntOp::Eq => a == b, IntOp::Ne => a != b, IntOp::Lt => a < b,
                 IntOp::Le => a <= b, IntOp::Gt => a > b, IntOp::Ge => a >= b } } }

/// String comparison operator. `Glob` is `~` (`*`/`?` wildcards). # C: O(1)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrOp { Eq, Ne, Glob }

/// Compiled filter expression. # C: O(nodes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ast {
    And(alloc::boxed::Box<Ast>, alloc::boxed::Box<Ast>),
    Or(alloc::boxed::Box<Ast>, alloc::boxed::Box<Ast>),
    Not(alloc::boxed::Box<Ast>),
    Int { field: String, op: IntOp, val: i64 },
    Str { field: String, op: StrOp, val: String },
}

/// Filter parse failure (→ EINVAL at the filter file). # C: O(1)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Empty, UnknownField, BadOp, BadValue, TypeMismatch, Syntax, Trailing,
}

// ---- tokenizer -------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),   // field name OR bareword string value (may hold `*?./`)
    Num(i64),
    Str(String),     // quoted "..."
    Op(String),      // == != <= >= < > ~
    And, Or, Not, LParen, RParen,
}

fn is_ident_ch(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'*' | b'?' | b'.' | b'/')
}

fn tokenize(src: &[u8]) -> Result<Vec<Tok>, ParseError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => { i += 1; }
            b'(' => { out.push(Tok::LParen); i += 1; }
            b')' => { out.push(Tok::RParen); i += 1; }
            b'~' => { out.push(Tok::Op("~".into())); i += 1; }
            b'&' => { if src.get(i + 1) == Some(&b'&') { out.push(Tok::And); i += 2; } else { return Err(ParseError::Syntax); } }
            b'|' => { if src.get(i + 1) == Some(&b'|') { out.push(Tok::Or); i += 2; } else { return Err(ParseError::Syntax); } }
            b'=' => { if src.get(i + 1) == Some(&b'=') { out.push(Tok::Op("==".into())); i += 2; } else { return Err(ParseError::Syntax); } }
            b'!' => { if src.get(i + 1) == Some(&b'=') { out.push(Tok::Op("!=".into())); i += 2; } else { out.push(Tok::Not); i += 1; } }
            b'<' => { if src.get(i + 1) == Some(&b'=') { out.push(Tok::Op("<=".into())); i += 2; } else { out.push(Tok::Op("<".into())); i += 1; } }
            b'>' => { if src.get(i + 1) == Some(&b'=') { out.push(Tok::Op(">=".into())); i += 2; } else { out.push(Tok::Op(">".into())); i += 1; } }
            b'"' => {
                let mut s = Vec::new();
                i += 1;
                while i < src.len() && src[i] != b'"' { s.push(src[i]); i += 1; }
                if i >= src.len() { return Err(ParseError::Syntax); }
                i += 1; // closing quote
                out.push(Tok::Str(String::from_utf8(s).map_err(|_| ParseError::BadValue)?));
            }
            b'-' if src.get(i + 1).map_or(false, |d| d.is_ascii_digit()) => {
                let start = i; i += 1;
                while i < src.len() && (src[i].is_ascii_alphanumeric() || src[i] == b'x') { i += 1; }
                out.push(parse_num(&src[start..i])?);
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < src.len() && (src[i].is_ascii_alphanumeric() || src[i] == b'x') { i += 1; }
                out.push(parse_num(&src[start..i])?);
            }
            c if is_ident_ch(c) => {
                let start = i;
                while i < src.len() && is_ident_ch(src[i]) { i += 1; }
                out.push(Tok::Ident(String::from_utf8_lossy(&src[start..i]).into_owned()));
            }
            _ => return Err(ParseError::Syntax),
        }
    }
    Ok(out)
}

fn parse_num(b: &[u8]) -> Result<Tok, ParseError> {
    let s = core::str::from_utf8(b).map_err(|_| ParseError::BadValue)?;
    let (neg, body) = s.strip_prefix('-').map_or((false, s), |r| (true, r));
    let v = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).map_err(|_| ParseError::BadValue)?
    } else {
        body.parse::<i64>().map_err(|_| ParseError::BadValue)?
    };
    Ok(Tok::Num(if neg { -v } else { v }))
}

// ---- recursive-descent parser ----------------------------------------------

struct Parser<'a> { toks: Vec<Tok>, pos: usize, fields: &'a [Field] }

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok> { self.toks.get(self.pos) }
    fn next(&mut self) -> Option<Tok> { let t = self.toks.get(self.pos).cloned(); if t.is_some() { self.pos += 1; } t }

    fn parse(&mut self) -> Result<Ast, ParseError> {
        if self.toks.is_empty() { return Err(ParseError::Empty); }
        let a = self.or()?;
        if self.pos != self.toks.len() { return Err(ParseError::Trailing); }
        Ok(a)
    }

    fn or(&mut self) -> Result<Ast, ParseError> {
        let mut a = self.and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.pos += 1;
            let b = self.and()?;
            a = Ast::Or(alloc::boxed::Box::new(a), alloc::boxed::Box::new(b));
        }
        Ok(a)
    }

    fn and(&mut self) -> Result<Ast, ParseError> {
        let mut a = self.unary()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.pos += 1;
            let b = self.unary()?;
            a = Ast::And(alloc::boxed::Box::new(a), alloc::boxed::Box::new(b));
        }
        Ok(a)
    }

    fn unary(&mut self) -> Result<Ast, ParseError> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.pos += 1;
            return Ok(Ast::Not(alloc::boxed::Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Ast, ParseError> {
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.pos += 1;
            let a = self.or()?;
            if !matches!(self.next(), Some(Tok::RParen)) { return Err(ParseError::Syntax); }
            return Ok(a);
        }
        self.predicate()
    }

    fn predicate(&mut self) -> Result<Ast, ParseError> {
        let field = match self.next() { Some(Tok::Ident(s)) => s, _ => return Err(ParseError::Syntax) };
        let op = match self.next() { Some(Tok::Op(o)) => o, _ => return Err(ParseError::BadOp) };
        let fd = self.fields.iter().find(|f| f.name == field).ok_or(ParseError::UnknownField)?;
        if fd.is_string {
            let val = match self.next() {
                Some(Tok::Str(s)) => s,
                Some(Tok::Ident(s)) => s,
                Some(Tok::Num(n)) => { let mut s = String::new(); s.push_str(&alloc::format!("{n}")); s }
                _ => return Err(ParseError::BadValue),
            };
            let sop = match op.as_str() {
                "~" => StrOp::Glob, "==" => StrOp::Eq, "!=" => StrOp::Ne,
                _ => return Err(ParseError::TypeMismatch),
            };
            Ok(Ast::Str { field, op: sop, val })
        } else {
            let val = match self.next() { Some(Tok::Num(n)) => n, _ => return Err(ParseError::BadValue) };
            let iop = match op.as_str() {
                "==" => IntOp::Eq, "!=" => IntOp::Ne, "<" => IntOp::Lt,
                "<=" => IntOp::Le, ">" => IntOp::Gt, ">=" => IntOp::Ge,
                _ => return Err(ParseError::TypeMismatch),
            };
            Ok(Ast::Int { field, op: iop, val })
        }
    }
}

/// Compile a filter expression against an event's `format` field table.
/// Invalid → `ParseError`. # C: O(expr)
pub fn compile(expr: &[u8], fields: &[Field]) -> Result<Ast, ParseError> {
    let toks = tokenize(expr)?;
    if toks.is_empty() { return Err(ParseError::Empty); }
    Parser { toks, pos: 0, fields }.parse()
}

// ---- evaluation ------------------------------------------------------------

/// A field value supplied by the emit site. # C: O(1)
#[derive(Clone, Copy, Debug)]
pub enum FieldVal<'a> { Int(i64), Str(&'a str) }

/// The record an event filter evaluates against: a stack slice of
/// `(field-name, value)` the tracepoint provides at emit time (alloc-free).
/// # C: O(1)
pub struct EventRecord<'a> { fields: &'a [(&'a str, FieldVal<'a>)] }
impl<'a> EventRecord<'a> {
    /// # C: O(1)
    pub fn new(fields: &'a [(&'a str, FieldVal<'a>)]) -> Self { Self { fields } }
    fn int(&self, name: &str) -> Option<i64> {
        self.fields.iter().find(|(n, _)| *n == name).and_then(|(_, v)| match v { FieldVal::Int(i) => Some(*i), _ => None })
    }
    fn str(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(n, _)| *n == name).and_then(|(_, v)| match v { FieldVal::Str(s) => Some(*s), _ => None })
    }
}

/// `*`/`?` glob match (Linux filter `~`). # C: O(pat·str)
fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while si < s.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == s[si]) { pi += 1; si += 1; }
        else if pi < pat.len() && pat[pi] == b'*' { star = pi; mark = si; pi += 1; }
        else if star != usize::MAX { pi = star + 1; mark += 1; si = mark; }
        else { return false; }
    }
    while pi < pat.len() && pat[pi] == b'*' { pi += 1; }
    pi == pat.len()
}

/// Evaluate a compiled filter against a record. A field absent from the record
/// makes its leaf comparison false. # C: O(nodes)
pub fn evaluate(ast: &Ast, rec: &EventRecord) -> bool {
    match ast {
        Ast::And(a, b) => evaluate(a, rec) && evaluate(b, rec),
        Ast::Or(a, b)  => evaluate(a, rec) || evaluate(b, rec),
        Ast::Not(a)    => !evaluate(a, rec),
        Ast::Int { field, op, val } => rec.int(field).map_or(false, |v| op.test(v, *val)),
        Ast::Str { field, op, val } => rec.str(field).map_or(false, |s| match op {
            StrOp::Eq   => s.as_bytes() == val.as_bytes(),
            StrOp::Ne   => s.as_bytes() != val.as_bytes(),
            StrOp::Glob => glob_match(val.as_bytes(), s.as_bytes()),
        }),
    }
}

// ---- per-event filter slot -------------------------------------------------

struct FilterState { raw: Vec<u8>, ast: Option<Ast> }

/// The mutable filter behind one `events/<sub>/<ev>/filter` file, also read by
/// the event's emit site in `ring`. `has_filter` is the lockless fast-path gate
/// (no filter → emit pays one atomic load); a set filter is read under a
/// fail-open `try_lock` so the context-switch path never blocks. # C: O(1)
pub struct FilterSlot {
    /// The event's `format` body — re-parsed on each filter write to validate.
    pub format:  &'static [u8],
    has_filter:  AtomicBool,
    state:       Spinlock<FilterState, TraceClass>,
}

impl FilterSlot {
    /// # C: O(1)
    pub const fn new(format: &'static [u8]) -> Self {
        Self { format, has_filter: AtomicBool::new(false),
               state: Spinlock::new(FilterState { raw: Vec::new(), ast: None }) }
    }

    /// True if a compiled filter is installed (the emit fast-path gate). # C: O(1)
    #[inline]
    pub fn has_filter(&self) -> bool { self.has_filter.load(Ordering::Acquire) }

    /// Apply a filter write. `"0"`/empty clears (Linux). A valid expression is
    /// stored + compiled; an INVALID one is rejected and the prior filter is
    /// kept. # C: O(expr)
    pub fn set(&self, raw: &[u8]) -> Result<(), ParseError> {
        let trimmed: &[u8] = {
            let s = raw.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(raw.len());
            let e = raw.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(s, |p| p + 1);
            &raw[s..e]
        };
        if trimmed.is_empty() || trimmed == b"0" {
            let mut g = self.state.lock();
            g.raw.clear(); g.ast = None;
            self.has_filter.store(false, Ordering::Release);
            return Ok(());
        }
        let fields = parse_fields(self.format);
        let ast = compile(trimmed, &fields)?; // Err → prior filter kept (below not reached)
        let mut g = self.state.lock();
        g.raw.clear(); g.raw.extend_from_slice(trimmed); g.raw.push(b'\n');
        g.ast = Some(ast);
        self.has_filter.store(true, Ordering::Release);
        Ok(())
    }

    /// Serve `filter` read bytes (`"none\n"` when unset). # C: O(n)
    pub fn read_into(&self, off: u64, buf: &mut [u8]) -> usize {
        let g = self.state.lock();
        let body: &[u8] = if g.raw.is_empty() { b"none\n" } else { &g.raw };
        let off = off as usize;
        if off >= body.len() { return 0; }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        n
    }

    /// Emit-time predicate: `true` = record the sample. No filter → `true`
    /// (fast path). A set filter is evaluated under a fail-open `try_lock` so a
    /// concurrent writer never blocks the (IRQs-off) context-switch path. # C: O(nodes)
    #[inline]
    pub fn passes(&self, rec: &EventRecord) -> bool {
        if !self.has_filter() { return true; }
        match self.state.try_lock() {
            Some(g) => match &g.ast { Some(a) => evaluate(a, rec), None => true },
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHED: &[u8] = b"name: sched_switch\nID: 1\nformat:\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
\tfield:char prev_comm[16];\toffset:8;\tsize:16;\tsigned:0;\n\
\tfield:pid_t prev_pid;\toffset:24;\tsize:4;\tsigned:1;\n\
\tfield:char next_comm[16];\toffset:28;\tsize:16;\tsigned:0;\n\
\tfield:pid_t next_pid;\toffset:44;\tsize:4;\tsigned:1;\n";

    fn fields() -> Vec<Field> { parse_fields(SCHED) }

    #[test]
    fn parses_field_table_types() {
        let f = fields();
        let pid = f.iter().find(|x| x.name == "prev_pid").unwrap();
        assert!(!pid.is_string);
        let comm = f.iter().find(|x| x.name == "prev_comm").unwrap();
        assert!(comm.is_string);
        assert_eq!(comm.size, 16);
        let cp = f.iter().find(|x| x.name == "common_pid").unwrap();
        assert!(!cp.is_string);
    }

    fn rec<'a>(items: &'a [(&'a str, FieldVal<'a>)]) -> EventRecord<'a> { EventRecord::new(items) }

    #[test]
    fn int_truth_table() {
        let f = fields();
        let a = compile(b"prev_pid == 42", &f).unwrap();
        assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(42))])));
        assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(7))])));
        let a = compile(b"prev_pid > 10", &f).unwrap();
        assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(11))])));
        assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(10))])));
        let a = compile(b"prev_pid <= 10 && prev_pid >= 5", &f).unwrap();
        assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(5))])));
        assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(10))])));
        assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(11))])));
        let a = compile(b"prev_pid != 0x10", &f).unwrap();
        assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(16))])));
        assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(15))])));
    }

    #[test]
    fn bool_logic_and_precedence() {
        let f = fields();
        // && binds tighter than ||
        let a = compile(b"prev_pid == 1 || prev_pid == 2 && next_pid == 3", &f).unwrap();
        assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(1)), ("next_pid", FieldVal::Int(99))])));
        assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(2)), ("next_pid", FieldVal::Int(3))])));
        assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(2)), ("next_pid", FieldVal::Int(4))])));
        // parens override
        let a = compile(b"(prev_pid == 1 || prev_pid == 2) && next_pid == 3", &f).unwrap();
        assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(1)), ("next_pid", FieldVal::Int(4))])));
        assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(1)), ("next_pid", FieldVal::Int(3))])));
        // not
        let a = compile(b"!(prev_pid == 1)", &f).unwrap();
        assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(1))])));
        assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(2))])));
    }

    #[test]
    fn string_glob_and_eq() {
        let f = fields();
        let a = compile(b"prev_comm ~ \"sh*\"", &f).unwrap();
        assert!(evaluate(&a, &rec(&[("prev_comm", FieldVal::Str("shutdown"))])));
        assert!(!evaluate(&a, &rec(&[("prev_comm", FieldVal::Str("bash"))])));
        let a = compile(b"prev_comm ~ \"*sh\"", &f).unwrap();
        assert!(evaluate(&a, &rec(&[("prev_comm", FieldVal::Str("bash"))])));
        let a = compile(b"next_comm == bash", &f).unwrap();
        assert!(evaluate(&a, &rec(&[("next_comm", FieldVal::Str("bash"))])));
        assert!(!evaluate(&a, &rec(&[("next_comm", FieldVal::Str("dash"))])));
        let a = compile(b"next_comm ~ \"k?orker*\"", &f).unwrap();
        assert!(evaluate(&a, &rec(&[("next_comm", FieldVal::Str("kworker/0"))])));
    }

    #[test]
    fn absent_field_is_false() {
        let f = fields();
        let a = compile(b"prev_pid == 1", &f).unwrap();
        assert!(!evaluate(&a, &rec(&[("next_pid", FieldVal::Int(1))])));
    }

    #[test]
    fn invalid_expressions_rejected() {
        let f = fields();
        assert_eq!(compile(b"nope == 1", &f), Err(ParseError::UnknownField));
        assert_eq!(compile(b"prev_pid =! 1", &f).is_err(), true);
        assert_eq!(compile(b"prev_pid ~ 1", &f), Err(ParseError::TypeMismatch)); // ~ on int
        assert_eq!(compile(b"prev_comm < 1", &f), Err(ParseError::TypeMismatch)); // < on string
        assert_eq!(compile(b"prev_pid == abc", &f), Err(ParseError::BadValue));
        assert_eq!(compile(b"prev_pid ==", &f), Err(ParseError::BadValue));
        assert_eq!(compile(b"prev_pid 1", &f), Err(ParseError::BadOp));
        assert_eq!(compile(b"(prev_pid == 1", &f), Err(ParseError::Syntax));
        assert_eq!(compile(b"prev_pid == 1 prev_pid == 2", &f), Err(ParseError::Trailing));
        assert_eq!(compile(b"", &f), Err(ParseError::Empty));
    }

    #[test]
    fn slot_keeps_prior_on_invalid() {
        static FMT: &[u8] = SCHED;
        let slot = FilterSlot::new(FMT);
        assert!(slot.passes(&rec(&[("prev_pid", FieldVal::Int(5))]))); // no filter → pass
        slot.set(b"prev_pid == 5\n").unwrap();
        assert!(slot.has_filter());
        assert!(slot.passes(&rec(&[("prev_pid", FieldVal::Int(5))])));
        assert!(!slot.passes(&rec(&[("prev_pid", FieldVal::Int(6))])));
        // invalid write → Err, prior kept
        assert!(slot.set(b"bogus_field == 1\n").is_err());
        assert!(slot.has_filter());
        assert!(slot.passes(&rec(&[("prev_pid", FieldVal::Int(5))])));
        assert!(!slot.passes(&rec(&[("prev_pid", FieldVal::Int(6))])));
        // clear
        slot.set(b"0\n").unwrap();
        assert!(!slot.has_filter());
        assert!(slot.passes(&rec(&[("prev_pid", FieldVal::Int(6))])));
    }

    #[test]
    fn slot_read_echoes_filter() {
        let slot = FilterSlot::new(SCHED);
        let mut buf = [0u8; 64];
        let n = slot.read_into(0, &mut buf);
        assert_eq!(&buf[..n], b"none\n");
        slot.set(b"prev_pid == 9").unwrap();
        let n = slot.read_into(0, &mut buf);
        assert_eq!(&buf[..n], b"prev_pid == 9\n");
    }

    #[test]
    fn glob_matcher_edges() {
        assert!(glob_match(b"*", b"anything"));
        assert!(glob_match(b"a*c", b"abc"));
        assert!(glob_match(b"a*c", b"ac"));
        assert!(!glob_match(b"a*c", b"ab"));
        assert!(glob_match(b"a?c", b"abc"));
        assert!(!glob_match(b"a?c", b"ac"));
        assert!(glob_match(b"**a", b"xxa"));
    }
}
