// POSIX ERE engine (docs/59§6 G7+). Parser → instruction program → backtracking
// VM with Save slots for captures, after Russ Cox's "Regular Expression
// Matching: the Virtual Machine Approach". Greedy quantifiers; leftmost match
// by scanning start positions. ERE operators: . ^ $ * + ? {n,m} | ( ) [ ],
// POSIX named classes [[:alpha:]], REG_ICASE/REG_NEWLINE/REG_NOTBOL/REG_NOTEOL.
// Pure + hosted-tested; the C ABI (regcomp/regexec) wraps it in mod.rs.
extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

#[derive(Clone)]
enum Node {
    Empty,
    Char(u8),
    Any,
    Class(usize),              // index into Prog.classes
    Bol,
    Eol,
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Group(Box<Node>, usize),   // capturing, 1-based slot
    Repeat(Box<Node>, usize, Option<usize>), // min, max (greedy)
}

enum Inst { Char(u8), Any, Class(usize), Match, Jmp(usize), Split(usize, usize), Save(usize), Bol, Eol }

pub struct Prog { insts: Vec<Inst>, classes: Vec<[bool; 256]>, pub ngroup: usize, icase: bool, newline: bool }

struct Parser<'a> { b: &'a [u8], i: usize, ngroup: usize, classes: Vec<[bool; 256]>, icase: bool, ere: bool }

fn lc(c: u8) -> u8 { if c.is_ascii_uppercase() { c + 32 } else { c } }

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> { self.b.get(self.i).copied() }
    fn bump(&mut self) -> Option<u8> { let c = self.peek(); if c.is_some() { self.i += 1; } c }

    fn parse(&mut self) -> Result<Node, i32> {
        let n = self.alt()?;
        if self.i != self.b.len() { return Err(super::REG_BADPAT); } // stray ')' etc.
        Ok(n)
    }

    // second byte of a "\x" escape at the cursor, if any (for BRE delimiters).
    fn esc2(&self) -> Option<u8> { if self.peek() == Some(b'\\') { self.b.get(self.i + 1).copied() } else { None } }
    // is the cursor at the alternation token? ERE '|', BRE '\|' (GNU).
    fn at_alt(&self) -> bool { if self.ere { self.peek() == Some(b'|') } else { self.esc2() == Some(b'|') } }
    // is the cursor at a group close? ERE ')', BRE '\)'.
    fn at_close(&self) -> bool { if self.ere { self.peek() == Some(b')') } else { self.esc2() == Some(b')') } }

    fn alt(&mut self) -> Result<Node, i32> {
        let mut branches = alloc::vec![self.concat()?];
        while self.at_alt() { self.i += if self.ere { 1 } else { 2 }; branches.push(self.concat()?); }
        Ok(if branches.len() == 1 { branches.pop().unwrap() } else { Node::Alt(branches) })
    }

    fn concat(&mut self) -> Result<Node, i32> {
        let mut parts = Vec::new();
        let mut first = true;
        while self.peek().is_some() && !self.at_alt() && !self.at_close() {
            parts.push(self.repeat(first)?);
            first = false;
        }
        Ok(match parts.len() { 0 => Node::Empty, 1 => parts.pop().unwrap(), _ => Node::Concat(parts) })
    }

    fn repeat(&mut self, first: bool) -> Result<Node, i32> {
        let mut atom = self.atom(first)?;
        loop {
            match self.peek() {
                Some(b'*') => { self.bump(); atom = Node::Repeat(Box::new(atom), 0, None); }
                Some(b'+') if self.ere => { self.bump(); atom = Node::Repeat(Box::new(atom), 1, None); }
                Some(b'?') if self.ere => { self.bump(); atom = Node::Repeat(Box::new(atom), 0, Some(1)); }
                _ => {
                    // bound: ERE "{...}", BRE "\{...\}"
                    let at_bound = if self.ere { self.peek() == Some(b'{') } else { self.esc2() == Some(b'{') };
                    if at_bound {
                        if let Some((min, max, adv)) = self.try_bound() { self.i = adv; atom = Node::Repeat(Box::new(atom), min, max); continue; }
                    }
                    break;
                }
            }
        }
        Ok(atom)
    }

    // parse {n}/{n,}/{n,m}; cursor at '{' (ERE) or '\{' (BRE). None = literal.
    fn try_bound(&self) -> Option<(usize, Option<usize>, usize)> {
        let close = if self.ere { 1 } else { 2 }; // bytes of "}" vs "\}"
        let at_close = |j: usize| if self.ere { self.b.get(j) == Some(&b'}') } else { self.b.get(j) == Some(&b'\\') && self.b.get(j + 1) == Some(&b'}') };
        let mut j = self.i + close; // past "{" / "\{"
        let mut min = 0usize; let mut any = false;
        while j < self.b.len() && self.b[j].is_ascii_digit() { min = min * 10 + (self.b[j] - b'0') as usize; j += 1; any = true; }
        if !any { return None; }
        let max;
        if at_close(j) { max = Some(min); j += close; }
        else if self.b.get(j) == Some(&b',') {
            j += 1;
            if at_close(j) { max = None; j += close; }
            else {
                let mut m = 0usize; let mut many = false;
                while j < self.b.len() && self.b[j].is_ascii_digit() { m = m * 10 + (self.b[j] - b'0') as usize; j += 1; many = true; }
                if !many || !at_close(j) { return None; }
                max = Some(m); j += close;
            }
        } else { return None; }
        Some((min, max, j))
    }

    // `$` is an anchor in ERE always; in BRE only at end or before '\)' / '\|'.
    fn dollar_is_anchor(&self) -> bool {
        if self.ere { return true; }
        self.peek().is_none() || self.esc2() == Some(b')') || self.esc2() == Some(b'|')
    }

    fn atom(&mut self, first: bool) -> Result<Node, i32> {
        // group open: ERE '(', BRE '\('
        let group_open = if self.ere { self.peek() == Some(b'(') } else { self.esc2() == Some(b'(') };
        if group_open {
            self.i += if self.ere { 1 } else { 2 };
            self.ngroup += 1; let idx = self.ngroup;
            let inner = self.alt()?;
            if !self.at_close() { return Err(super::REG_EPAREN); }
            self.i += if self.ere { 1 } else { 2 };
            return Ok(Node::Group(Box::new(inner), idx));
        }
        match self.bump() {
            Some(b'[') => self.class(),
            Some(b'.') => Ok(Node::Any),
            Some(b'^') if self.ere || first => Ok(Node::Bol),
            Some(b'$') if self.dollar_is_anchor() => Ok(Node::Eol),
            Some(b'\\') => { let c = self.bump().ok_or(super::REG_EESCAPE)?; Ok(self.lit(c)) }
            Some(c) => Ok(self.lit(c)), // BRE: +?(){}| ^ $ here are literals
            None => Ok(Node::Empty),
        }
    }

    fn lit(&mut self, c: u8) -> Node {
        if self.icase && c.is_ascii_alphabetic() {
            let mut set = [false; 256];
            set[lc(c) as usize] = true; set[(lc(c) - 32) as usize] = true;
            self.classes.push(set); Node::Class(self.classes.len() - 1)
        } else { Node::Char(c) }
    }

    fn class(&mut self) -> Result<Node, i32> {
        let mut set = [false; 256];
        let negate = self.peek() == Some(b'^');
        if negate { self.bump(); }
        let mut first = true;
        loop {
            let c = match self.peek() { Some(c) => c, None => return Err(super::REG_EBRACK) };
            if c == b']' && !first { self.bump(); break; }
            first = false;
            // POSIX named class [[:name:]]
            if c == b'[' && self.b.get(self.i + 1) == Some(&b':') {
                if let Some(adv) = self.named_class(&mut set) { self.i = adv; continue; }
            }
            self.bump();
            // range a-z (when '-' is not last)
            if self.peek() == Some(b'-') && self.b.get(self.i + 1).is_some_and(|&n| n != b']') {
                self.bump(); let hi = self.bump().unwrap();
                let (mut x, hi) = (c as u16, hi as u16);
                while x <= hi { set[x as usize] = true; x += 1; }
            } else {
                set[c as usize] = true;
            }
        }
        if negate { for s in set.iter_mut() { *s = !*s; } }
        if self.icase {
            // fold case so [A-Z] also matches lowercase under REG_ICASE
            for x in b'a'..=b'z' { let u = x - 32; if set[x as usize] != set[u as usize] { set[x as usize] = true; set[u as usize] = true; } }
        }
        self.classes.push(set); Ok(Node::Class(self.classes.len() - 1))
    }

    // [[:name:]] at self.i ('['); fill set, return index past the closing ":]".
    fn named_class(&self, set: &mut [bool; 256]) -> Option<usize> {
        let start = self.i + 2; // past "[:"
        let mut j = start;
        while j < self.b.len() && self.b[j] != b':' { j += 1; }
        if j + 1 >= self.b.len() || self.b[j] != b':' || self.b[j + 1] != b']' { return None; }
        let name = &self.b[start..j];
        let pred: fn(u8) -> bool = match name {
            b"alpha" => |c| c.is_ascii_alphabetic(),
            b"digit" => |c| c.is_ascii_digit(),
            b"alnum" => |c| c.is_ascii_alphanumeric(),
            b"space" => |c| c.is_ascii_whitespace() || c == 0x0b,
            b"upper" => |c| c.is_ascii_uppercase(),
            b"lower" => |c| c.is_ascii_lowercase(),
            b"punct" => |c| c.is_ascii_punctuation(),
            b"xdigit" => |c| c.is_ascii_hexdigit(),
            b"blank" => |c| c == b' ' || c == b'\t',
            b"cntrl" => |c| c.is_ascii_control(),
            b"print" => |c| c.is_ascii_graphic() || c == b' ',
            b"graph" => |c| c.is_ascii_graphic(),
            _ => return None,
        };
        for c in 0u16..256 { if pred(c as u8) { set[c as usize] = true; } }
        Some(j + 2)
    }
}

// Compile an AST node, appending instructions; Save wrapping for groups.
fn compile(n: &Node, out: &mut Vec<Inst>) {
    match n {
        Node::Empty => {}
        Node::Char(c) => out.push(Inst::Char(*c)),
        Node::Any => out.push(Inst::Any),
        Node::Class(i) => out.push(Inst::Class(*i)),
        Node::Bol => out.push(Inst::Bol),
        Node::Eol => out.push(Inst::Eol),
        Node::Concat(v) => for c in v { compile(c, out); },
        Node::Group(inner, idx) => {
            out.push(Inst::Save(2 * idx));
            compile(inner, out);
            out.push(Inst::Save(2 * idx + 1));
        }
        Node::Alt(v) => {
            // split to each branch; each jumps to the end
            let mut jmps = Vec::new();
            for (k, b) in v.iter().enumerate() {
                if k + 1 < v.len() {
                    let split = out.len(); out.push(Inst::Split(0, 0));
                    let b1 = out.len();
                    compile(b, out);
                    let j = out.len(); out.push(Inst::Jmp(0)); jmps.push(j);
                    let b2 = out.len();
                    out[split] = Inst::Split(b1, b2);
                } else { compile(b, out); }
            }
            let end = out.len();
            for j in jmps { out[j] = Inst::Jmp(end); }
        }
        Node::Repeat(inner, min, max) => compile_repeat(inner, *min, *max, out),
    }
}

fn compile_repeat(inner: &Node, min: usize, max: Option<usize>, out: &mut Vec<Inst>) {
    // mandatory copies
    for _ in 0..min { compile(inner, out); }
    match max {
        None => {
            // greedy star/plus tail: L: split body,end; body; jmp L; end:
            let l = out.len(); out.push(Inst::Split(0, 0));
            let body = out.len(); compile(inner, out);
            out.push(Inst::Jmp(l));
            let end = out.len();
            out[l] = Inst::Split(body, end);
        }
        Some(m) => {
            // optional copies: each `split take,skip; <inner>`; skips chain to end
            let mut splits = Vec::new();
            for _ in min..m {
                let s = out.len(); out.push(Inst::Split(0, 0)); splits.push(s);
                let body = out.len(); compile(inner, out);
                out[s] = Inst::Split(body, 0); // skip target patched below
            }
            let end = out.len();
            for s in splits { if let Inst::Split(b, _) = out[s] { out[s] = Inst::Split(b, end); } }
        }
    }
}

/// # C: compile an ERE pattern to a VM program (regcomp backend)
pub fn compile_pattern(pat: &[u8], icase: bool, newline: bool, ere: bool) -> Result<Prog, i32> {
    let mut p = Parser { b: pat, i: 0, ngroup: 0, classes: Vec::new(), icase, ere };
    let ast = p.parse()?;
    let mut insts = Vec::new();
    insts.push(Inst::Save(0));
    compile(&ast, &mut insts);
    insts.push(Inst::Save(1));
    insts.push(Inst::Match);
    Ok(Prog { insts, classes: p.classes, ngroup: p.ngroup, icase, newline })
}

struct Ctx<'a> { prog: &'a Prog, input: &'a [u8], notbol: bool, noteol: bool, steps: u64 }

impl Ctx<'_> {
    // Backtracking VM. Returns true if Match reached; caps records Save slots.
    fn run(&mut self, mut pc: usize, mut sp: usize, caps: &mut [usize]) -> bool {
        loop {
            self.steps += 1;
            if self.steps > 50_000_000 { return false; } // runaway guard
            match self.prog.insts[pc] {
                Inst::Char(c) => {
                    if sp >= self.input.len() { return false; }
                    let m = if self.prog.icase { lc(self.input[sp]) == lc(c) } else { self.input[sp] == c };
                    if !m { return false; }
                    sp += 1; pc += 1;
                }
                Inst::Any => {
                    if sp >= self.input.len() || (self.prog.newline && self.input[sp] == b'\n') { return false; }
                    sp += 1; pc += 1;
                }
                Inst::Class(i) => {
                    if sp >= self.input.len() || !self.prog.classes[i][self.input[sp] as usize] { return false; }
                    sp += 1; pc += 1;
                }
                Inst::Match => return true,
                Inst::Jmp(x) => pc = x,
                Inst::Split(a, b) => {
                    if self.run(a, sp, caps) { return true; }
                    pc = b;
                }
                Inst::Save(s) => {
                    let old = caps[s];
                    caps[s] = sp;
                    if self.run(pc + 1, sp, caps) { return true; }
                    caps[s] = old;
                    return false;
                }
                Inst::Bol => {
                    let ok = (sp == 0 && !self.notbol) || (self.prog.newline && sp > 0 && self.input[sp - 1] == b'\n');
                    if !ok { return false; }
                    pc += 1;
                }
                Inst::Eol => {
                    let ok = (sp == self.input.len() && !self.noteol) || (self.prog.newline && sp < self.input.len() && self.input[sp] == b'\n');
                    if !ok { return false; }
                    pc += 1;
                }
            }
        }
    }
}

/// # C: leftmost match → capture slots 2*(ngroup+1), usize::MAX = unset (regexec backend)
pub fn exec(prog: &Prog, input: &[u8], notbol: bool, noteol: bool) -> Option<Vec<usize>> {
    let mut ctx = Ctx { prog, input, notbol, noteol, steps: 0 };
    for start in 0..=input.len() {
        let mut caps = alloc::vec![usize::MAX; 2 * (prog.ngroup + 1)];
        if ctx.run(0, start, &mut caps) { return Some(caps); }
        // Bol/Eol with the same notbol still apply per-position; keep scanning.
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn m(pat: &str, s: &str) -> Option<(usize, usize)> {
        let p = compile_pattern(pat.as_bytes(), false, false, true).unwrap();
        exec(&p, s.as_bytes(), false, false).map(|c| (c[0], c[1]))
    }
    #[test]
    fn basics() {
        assert_eq!(m("a.c", "xabcx"), Some((1, 4)));
        assert_eq!(m("a*", "aaab"), Some((0, 3)));
        assert_eq!(m("[0-9]+", "ab123c"), Some((2, 5)));
        assert_eq!(m("^foo$", "foo"), Some((0, 3)));
        assert_eq!(m("^foo$", "foox"), None);
        assert_eq!(m("(ab)+", "ababab"), Some((0, 6)));
        assert_eq!(m("a{2,3}", "aaaa"), Some((0, 3)));
        assert_eq!(m("colou?r", "color"), Some((0, 5)));
        assert_eq!(m("[[:digit:]]+", "x42"), Some((1, 3)));
        assert_eq!(m("cat|dog", "the dog"), Some((4, 7)));
        assert_eq!(m("z", "abc"), None);
    }
    #[test]
    fn captures() {
        let p = compile_pattern(b"(a+)(b+)", false, false, true).unwrap();
        let c = exec(&p, b"aaabb", false, false).unwrap();
        assert_eq!((c[0], c[1]), (0, 5));
        assert_eq!((c[2], c[3]), (0, 3)); // group 1 = "aaa"
        assert_eq!((c[4], c[5]), (3, 5)); // group 2 = "bb"
    }
}
