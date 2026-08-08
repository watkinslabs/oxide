//! Normalizing scanner: yields the codepoints of a name's normalized form, in
//! canonical order, without allocating.
//!
//! Canonical ordering is a stable sort of each run of combining marks by
//! combining class, which normally wants a buffer. Instead the cursor emits one
//! class per pass and rescans the run for the next class, so a run costs one
//! pass per distinct class present and no memory. Two names compare equal iff
//! their cursors yield the same codepoint sequence.
//!
//! An ignorable codepoint contributes nothing but is still a starter, so it
//! terminates the run being sorted — dropping it silently would let marks
//! either side of it reorder across each other.

use crate::api::InvalidName;
use crate::blob::{Expansion, Form, Table};
use crate::decode::{decode, encoded_len};
use crate::hangul;

/// Combining class of a starter.
const STOPPER: i16 = 0;
/// Highest combining class Unicode assigns.
const MAXCCC: i16 = 254;
/// Sentinel below every real class: "this is the first pass over a run".
const PRESCAN: i16 = -1;
/// Sentinel above every real class: "no further class remains in this run".
const NO_MORE: i16 = MAXCCC + 1;

/// Position inside an expansion, or `None` when reading the input directly.
#[derive(Clone, Copy)]
enum Exp {
    None,
    /// Byte range still to emit from the generated expansion pool.
    Pool { off: u32, end: u32 },
    /// Hangul syllable being decomposed arithmetically.
    Hangul { cp: u32, idx: u8, len: u8 },
}

/// Scanner over one name under one normalization form.
pub struct Cursor<'a> {
    tab:   Table,
    form:  Form,
    s:     &'a [u8],
    pos:   usize,
    exp:   Exp,
    /// Position to restart the run scan from, saved on the first pass.
    saved: Option<(usize, Exp)>,
    /// Combining class currently being emitted.
    ccc:   i16,
    /// Lowest class seen this pass that is still above `ccc`.
    nccc:  i16,
}

impl<'a> Cursor<'a> {
    /// # C: O(1)
    pub(crate) fn new(tab: Table, form: Form, s: &'a [u8]) -> Self {
        Cursor { tab, form, s, pos: 0, exp: Exp::None, saved: None, ccc: STOPPER, nccc: STOPPER }
    }

    /// Next codepoint of the normalized form, or `None` at the end.
    /// # C: O(distinct combining classes in the current run)
    pub fn next(&mut self) -> Result<Option<u32>, InvalidName> {
        loop {
            if self.pop_finished_expansion() { continue; }
            let (cp, from_expansion) = match self.peek()? {
                Some(v) => v,
                None => {
                    // End of input acts as a starter: it terminates the run.
                    if self.ccc == STOPPER { return Ok(None); }
                    self.mismatch(STOPPER);
                    continue;
                }
            };
            if !from_expansion && self.begin_expansion(cp)? { continue; }
            let ccc = self.tab.ccc(cp) as i16;
            if ccc != STOPPER && self.ccc < ccc && ccc < self.nccc { self.nccc = ccc; }
            if ccc == self.ccc {
                self.advance(cp);
                return Ok(Some(cp));
            }
            self.mismatch(ccc);
        }
    }

    /// Drop a fully consumed expansion so the scan resumes in the input.
    fn pop_finished_expansion(&mut self) -> bool {
        let done = match self.exp {
            Exp::None => false,
            Exp::Pool { off, end } => off == end,
            Exp::Hangul { idx, len, .. } => idx == len,
        };
        if done { self.exp = Exp::None; }
        done
    }

    /// Codepoint under the cursor, and whether it came from an expansion.
    fn peek(&self) -> Result<Option<(u32, bool)>, InvalidName> {
        match self.exp {
            Exp::None => {
                if self.pos >= self.s.len() { return Ok(None); }
                let (cp, _) = decode(&self.s[self.pos..])?;
                Ok(Some((cp, false)))
            }
            Exp::Pool { off, .. } => {
                let (cp, _) = decode(&self.tab.pool()[off as usize..])?;
                Ok(Some((cp, true)))
            }
            Exp::Hangul { cp, idx, .. } => Ok(Some((hangul::jamo(cp, idx), true))),
        }
    }

    /// If `cp` expands, consume it and switch the scan into its expansion.
    /// Returns whether the caller should re-enter the loop.
    fn begin_expansion(&mut self, cp: u32) -> Result<bool, InvalidName> {
        match self.tab.expansion(self.form, cp) {
            Expansion::Identity => Ok(false),
            Expansion::Pool { off, end } => {
                self.pos += encoded_len(cp);
                self.exp = Exp::Pool { off, end };
                Ok(true)
            }
            Expansion::Hangul => {
                self.pos += encoded_len(cp);
                self.exp = Exp::Hangul { cp, idx: 0, len: hangul::jamo_count(cp) };
                Ok(true)
            }
            Expansion::Ignorable => {
                self.pos += encoded_len(cp);
                // Emits nothing, but is a starter: if a run is being sorted it
                // ends here, and the scan revisits this position afterwards.
                if self.ccc != STOPPER { self.mismatch(STOPPER); }
                Ok(true)
            }
        }
    }

    /// Step past the codepoint just emitted or skipped.
    fn advance(&mut self, cp: u32) {
        match &mut self.exp {
            Exp::None => self.pos += encoded_len(cp),
            Exp::Pool { off, .. } => *off += encoded_len(cp) as u32,
            Exp::Hangul { idx, .. } => *idx += 1,
        }
    }

    /// The codepoint under the cursor is not in the class being emitted: either
    /// note its class and keep scanning, restart the run for the next class, or
    /// finish the run.
    fn mismatch(&mut self, ccc: i16) {
        if self.nccc == STOPPER {
            // First pass over this run: remember where it starts and which
            // class to emit first.
            self.ccc = PRESCAN;
            self.nccc = ccc;
            self.saved = Some((self.pos, self.exp));
            self.advance_raw();
        } else if ccc != STOPPER {
            self.advance_raw();
        } else if self.nccc != NO_MORE {
            // Run ended; go back and emit the next class up.
            self.ccc = self.nccc;
            self.nccc = NO_MORE;
            if let Some((pos, exp)) = self.saved { self.pos = pos; self.exp = exp; }
        } else {
            // Every class in the run has been emitted; resume normal scanning.
            self.ccc = STOPPER;
            self.nccc = STOPPER;
            self.saved = None;
        }
    }

    /// Skip the codepoint under the cursor during a run scan. Never reached at
    /// end of input, where there is nothing to skip.
    fn advance_raw(&mut self) {
        if let Ok(Some((cp, _))) = self.peek() { self.advance(cp); }
    }
}
