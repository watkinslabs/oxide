// <wordexp.h> (docs/59§6 G8). Shell word expansion: tilde, $VAR / ${VAR},
// ${VAR:-default} / ${VAR:+alt} / ${VAR-d} / ${VAR+a}, single+double quotes,
// backslash escapes, IFS field splitting on unquoted whitespace, and pathname
// globbing (via the crate's glob) of unquoted fields containing * ? [.
// Command substitution `$(...)` / backtick is rejected (WRDE_CMDSUB) unless
// the caller would allow it — we do not run commands. WRDE_* flags honored.
#![cfg(feature = "freestanding")]
use crate::malloc::heap;
use crate::posix::glob::{glob, globfree, glob_t};
use crate::stdlib::env::{current_environ, find_env};
use crate::string::len::strlen_impl;
use alloc::vec::Vec;

const WRDE_DOOFFS: i32 = 1 << 0;
const WRDE_APPEND: i32 = 1 << 1;
const WRDE_NOCMD: i32 = 1 << 2;
const WRDE_REUSE: i32 = 1 << 3;
#[allow(dead_code)]
const WRDE_SHOWERR: i32 = 1 << 4;
const WRDE_UNDEF: i32 = 1 << 5;

const WRDE_NOSPACE: i32 = 1;
const WRDE_BADCHAR: i32 = 2;
const WRDE_BADVAL: i32 = 3;
const WRDE_CMDSUB: i32 = 4;
const WRDE_SYNTAX: i32 = 5;

const GLOB_NOSORT: i32 = 4;
const GLOB_NOMATCH: i32 = 3;

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
pub struct wordexp_t {
    pub we_wordc: usize,
    pub we_wordv: *mut *mut u8,
    pub we_offs: usize,
}

// A field accumulator: bytes built so far + whether any glob metachar appeared
// *unquoted* (so we know whether to glob) + whether the field is non-empty due
// to a quote (so "" yields an empty field, not nothing).
struct Field { buf: Vec<u8>, glob_meta: bool, quoted_empty: bool, active: bool }
impl Field {
    fn new() -> Field { Field { buf: Vec::new(), glob_meta: false, quoted_empty: false, active: false } }
    fn push(&mut self, b: u8) { self.buf.push(b); self.active = true; }
    fn push_meta(&mut self, b: u8) { self.glob_meta = true; self.push(b); }
}

// Output word list being assembled.
struct Words { v: Vec<*mut u8> }
impl Words {
    fn new() -> Words { Words { v: Vec::new() } }
    // Push a heap copy of bytes+NUL.
    unsafe fn push_bytes(&mut self, b: &[u8]) -> bool {
        // SAFETY: allocate len+1, copy the field bytes + NUL, store the ptr.
        unsafe {
            let p = heap::malloc(b.len() + 1);
            if p.is_null() { return false; }
            core::ptr::copy_nonoverlapping(b.as_ptr(), p, b.len());
            *p.add(b.len()) = 0;
            self.v.push(p);
            true
        }
    }
    unsafe fn push_owned(&mut self, p: *mut u8) { self.v.push(p); }
}

// Look up a variable; returns (ptr,len) into environ, or null/0 if unset.
unsafe fn lookup(name: &[u8]) -> (*const u8, usize) {
    // SAFETY: query environ for the entry whose NAME matches name[..len].
    unsafe {
        let v = find_env(current_environ() as *const *const u8, name.as_ptr(), name.len());
        if v.is_null() { (core::ptr::null(), 0) } else { (v, strlen_impl(v)) }
    }
}

// Parse a $-expansion starting at words[i] (words[i]=='$'). Append the value
// to `f` (treated as already field-split-eligible: glob_meta stays false since
// expansions don't introduce glob metachars). Returns the next index or Err.
unsafe fn expand_dollar(w: &[u8], i: usize, flags: i32, f: &mut Vec<u8>, split: &mut Vec<usize>) -> Result<usize, i32> {
    // SAFETY: w[i]=='$'; reads within w.len(). Pushes the var value into f and
    // records split points (IFS whitespace) for later field separation.
    unsafe {
        let n = w.len();
        let mut j = i + 1;
        if j >= n { f.push(b'$'); return Ok(j); }
        let braced = w[j] == b'{';
        if w[j] == b'(' { return Err(WRDE_CMDSUB); } // $(...) command sub
        if braced { j += 1; }
        let nstart = j;
        while j < n && (w[j].is_ascii_alphanumeric() || w[j] == b'_') { j += 1; }
        let name = &w[nstart..j];
        if name.is_empty() { f.push(b'$'); if braced { f.push(b'{'); } return Ok(nstart); }
        let (mut vp, mut vl) = lookup(name);
        let mut have = !vp.is_null();
        // ${VAR:-word} / ${VAR-word} / ${VAR:+word} / ${VAR+word}
        if braced && j < n && w[j] != b'}' {
            let colon = w[j] == b':';
            let opc = if colon { w.get(j + 1).copied().unwrap_or(0) } else { w[j] };
            let wstart = j + if colon { 2 } else { 1 };
            // find matching '}'
            let mut k = wstart;
            while k < n && w[k] != b'}' { k += 1; }
            if k >= n { return Err(WRDE_SYNTAX); }
            let word = &w[wstart..k];
            let unset_or_null = !have || (colon && vl == 0);
            match opc {
                b'-' => if unset_or_null {
                    // expand `word` recursively into f, with splitting
                    let sub = expand_word_segment(word, flags, split, f.len())?;
                    f.extend_from_slice(&sub.0); split.extend_from_slice(&sub.1);
                    return Ok(k + 1);
                },
                b'+' => {
                    if !unset_or_null {
                        let sub = expand_word_segment(word, flags, split, f.len())?;
                        f.extend_from_slice(&sub.0); split.extend_from_slice(&sub.1);
                    }
                    return Ok(k + 1);
                }
                _ => return Err(WRDE_BADCHAR),
            }
            // ${VAR:-word}: VAR set+nonnull → fall through to emit value
        } else if braced {
            if j >= n || w[j] != b'}' { return Err(WRDE_SYNTAX); }
            j += 1;
        }
        if !have && flags & WRDE_UNDEF != 0 { return Err(WRDE_BADVAL); }
        if !have { vp = core::ptr::null(); vl = 0; }
        let _ = &mut have;
        // emit value; record IFS whitespace split points (unquoted context)
        for x in 0..vl {
            let b = *vp.add(x);
            if b == b' ' || b == b'\t' || b == b'\n' { split.push(f.len()); }
            f.push(b);
        }
        Ok(j)
    }
}

// Expand a sub-word (the default/alt text inside ${..}) into bytes + relative
// split offsets (offsets are relative to base_off, added by the caller).
#[allow(clippy::type_complexity)]
unsafe fn expand_word_segment(seg: &[u8], flags: i32, _split: &mut Vec<usize>, base_off: usize) -> Result<(Vec<u8>, Vec<usize>), i32> {
    // SAFETY: seg is a slice of the input; recursively handle $ and quotes
    // within the default text. Returns the bytes + absolute split points.
    unsafe {
        let mut out = Vec::new();
        let mut sp = Vec::new();
        let mut i = 0;
        while i < seg.len() {
            let c = seg[i];
            if c == b'$' { i = expand_dollar(seg, i, flags, &mut out, &mut sp)?; }
            else if c == b'\\' && i + 1 < seg.len() { out.push(seg[i + 1]); i += 2; }
            else { out.push(c); i += 1; }
        }
        for s in sp.iter_mut() { *s += base_off; }
        Ok((out, sp))
    }
}

// Finalize a completed field: glob if it had unquoted metachars and matches,
// else push the literal field. Returns false on OOM.
unsafe fn emit_field(words: &mut Words, f: &Field) -> Result<(), i32> {
    // SAFETY: f.buf holds the field bytes; glob via the crate glob over a
    // NUL-terminated copy, else push the literal.
    unsafe {
        if !f.active && !f.quoted_empty { return Ok(()); }
        if f.glob_meta {
            // build NUL-terminated pattern
            let pat = heap::malloc(f.buf.len() + 1);
            if pat.is_null() { return Err(WRDE_NOSPACE); }
            core::ptr::copy_nonoverlapping(f.buf.as_ptr(), pat, f.buf.len());
            *pat.add(f.buf.len()) = 0;
            let mut g: glob_t = core::mem::zeroed();
            let r = glob(pat, GLOB_NOSORT, core::ptr::null(), &mut g);
            heap::free(pat);
            if r == 0 {
                // steal each path into words (so globfree won't free them)
                for x in 0..g.gl_pathc {
                    let p = *g.gl_pathv.add(x);
                    words.push_owned(p);
                    *g.gl_pathv.add(x) = core::ptr::null_mut();
                }
                g.gl_pathc = 0;
                globfree(&mut g);
                return Ok(());
            }
            if r != GLOB_NOMATCH { globfree(&mut g); return Err(WRDE_NOSPACE); }
            // no match → literal word (glibc default, no WRDE_NOMATCH)
        }
        if !words.push_bytes(&f.buf) { return Err(WRDE_NOSPACE); }
        Ok(())
    }
}

// Core expansion: walk the input once, producing fields into `words`.
unsafe fn expand(input: &[u8], flags: i32, words: &mut Words) -> Result<(), i32> {
    // SAFETY: input is the caller's word string; drive the state machine,
    // emitting fields on unquoted IFS whitespace.
    unsafe {
        let mut f = Field::new();
        let n = input.len();
        let mut i = 0;
        // leading tilde (only at field start, unquoted)
        while i < n {
            let c = input[i];
            match c {
                b' ' | b'\t' | b'\n' => { emit_field(words, &f)?; f = Field::new(); i += 1; }
                b'\'' => {
                    f.quoted_empty = true; f.active = true; i += 1;
                    while i < n && input[i] != b'\'' { f.push(input[i]); i += 1; }
                    if i >= n { return Err(WRDE_SYNTAX); }
                    i += 1;
                }
                b'"' => {
                    f.quoted_empty = true; f.active = true; i += 1;
                    while i < n && input[i] != b'"' {
                        if input[i] == b'$' {
                            let mut tmp: Vec<u8> = Vec::new();
                            let mut sp: Vec<usize> = Vec::new();
                            i = expand_dollar(input, i, flags, &mut tmp, &mut sp)?;
                            for b in tmp { f.push(b); } // no splitting inside ""
                        } else if input[i] == b'\\' && i + 1 < n && matches!(input[i + 1], b'"' | b'\\' | b'$' | b'`') {
                            f.push(input[i + 1]); i += 2;
                        } else { f.push(input[i]); i += 1; }
                    }
                    if i >= n { return Err(WRDE_SYNTAX); }
                    i += 1;
                }
                b'\\' => { if i + 1 < n { f.push(input[i + 1]); i += 2; } else { i += 1; } }
                b'`' => return Err(WRDE_CMDSUB),
                b'~' if !f.active => {
                    // tilde: ~ or ~/... → $HOME
                    let mut k = i + 1;
                    while k < n && input[k] != b'/' && input[k] != b' ' && input[k] != b'\t' { k += 1; }
                    if k == i + 1 {
                        let (hp, hl) = lookup(b"HOME");
                        if !hp.is_null() { for x in 0..hl { f.push(*hp.add(x)); } } else { f.push(b'~'); }
                        i = k;
                    } else { f.push(b'~'); i += 1; }
                }
                b'$' => {
                    let mut tmp: Vec<u8> = Vec::new();
                    let mut sp: Vec<usize> = Vec::new();
                    i = expand_dollar(input, i, flags, &mut tmp, &mut sp)?;
                    // apply field splitting at recorded points
                    let mut last = 0usize;
                    for s in &sp {
                        for &b in &tmp[last..*s] { f.push(b); }
                        emit_field(words, &f)?; f = Field::new();
                        last = *s + 1;
                    }
                    for &b in &tmp[last..] { f.push(b); }
                }
                b'*' | b'?' | b'[' => { f.push_meta(c); i += 1; }
                _ => { f.push(c); i += 1; }
            }
        }
        emit_field(words, &f)?;
        Ok(())
    }
}

// # C: int wordexp(const char *words, wordexp_t *pwordexp, int flags)
#[no_mangle]
pub unsafe extern "C" fn wordexp(words: *const u8, pwordexp: *mut wordexp_t, flags: i32) -> i32 {
    // SAFETY: words NUL-terminated; pwordexp a valid wordexp_t. Expand into a
    // freshly-allocated we_wordv (NULL-terminated), honoring WRDE_* flags.
    unsafe {
        let wp = &mut *pwordexp;
        let input = core::slice::from_raw_parts(words, strlen_impl(words));
        let mut out = Words::new();
        match expand(input, flags, &mut out) {
            Ok(()) => {}
            Err(e) => { for p in &out.v { heap::free(*p); } return e; }
        }

        // assemble we_wordv: [DOOFFS NULLs][APPEND old][new][NULL]
        let offs = if flags & WRDE_DOOFFS != 0 { wp.we_offs } else { 0 };
        let (old_c, old_v) = if flags & WRDE_APPEND != 0 && !wp.we_wordv.is_null() { (wp.we_wordc, wp.we_wordv) } else { (0, core::ptr::null_mut()) };
        let newc = out.v.len();
        let total = offs + old_c + newc;
        let arr = heap::malloc((total + 1) * 8) as *mut *mut u8;
        if arr.is_null() { for p in &out.v { heap::free(*p); } return WRDE_NOSPACE; }
        let mut w = 0usize;
        for _ in 0..offs { *arr.add(w) = core::ptr::null_mut(); w += 1; }
        for x in 0..old_c { *arr.add(w) = *old_v.add(offs + x); w += 1; }
        for &p in &out.v { *arr.add(w) = p; w += 1; }
        *arr.add(w) = core::ptr::null_mut();
        if flags & WRDE_APPEND != 0 && !old_v.is_null() { heap::free(old_v as *mut u8); }
        if flags & WRDE_REUSE != 0 && (flags & WRDE_APPEND == 0) && !wp.we_wordv.is_null() {
            // REUSE without APPEND: free previous result first
            wordfree(wp as *mut wordexp_t);
        }

        wp.we_wordc = old_c + newc;
        wp.we_wordv = arr;
        wp.we_offs = offs;
        0
    }
}

// # C: void wordfree(wordexp_t *wordexp)
#[no_mangle]
pub unsafe extern "C" fn wordfree(we: *mut wordexp_t) {
    // SAFETY: we was filled by wordexp(); free each word + the vector.
    unsafe {
        if we.is_null() || (*we).we_wordv.is_null() { return; }
        let v = (*we).we_wordv;
        let offs = (*we).we_offs;
        for x in 0..(*we).we_wordc { heap::free(*v.add(offs + x)); }
        heap::free(v as *mut u8);
        (*we).we_wordv = core::ptr::null_mut();
        (*we).we_wordc = 0;
    }
}
