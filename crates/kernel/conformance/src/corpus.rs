//! Table-driven corpus runner shared by every `conformance_*.rs` test file.
//! Adding a case is one [`Case`] literal appended to the crate's `CASES`
//! table (see any `conformance_*.rs` file for the pattern); `run` is the one
//! call each file's `#[test]` makes.

extern crate std;
use std::format;
use std::string::String;
use std::vec::Vec;

use crate::outcome::Outcome;

/// One corpus row. `run` executes BOTH sides (host oracle + oxide work-fn)
/// and returns their outcomes; `run_corpus` does the comparison so every
/// case gets identical, uniform errno-class + optional ret matching.
pub struct Case {
    pub id: &'static str,
    /// `Some(defect)` — a real, already-diagnosed divergence. Cites the
    /// responsible file:line (`docs/38` convention) so `run_corpus` reports
    /// it as a KNOWN divergence instead of failing the suite. Never used to
    /// silently loosen an expectation: the recorded host/oxide outcomes are
    /// still printed every run.
    pub known_divergence: Option<&'static str>,
    /// `Some(reason)` — cannot be run in this hosted harness (e.g. needs a
    /// resource this lane didn't wire up). `run` is not called.
    pub skip: Option<&'static str>,
    /// Compare success `ret` values too (fd numbers/inode-adjacent values are
    /// never host/oxide comparable — leave `false` for those; flip to `true`
    /// when `ret` carries content both sides compute the same way, e.g. an
    /// F_GETFL flag word or a seek offset).
    pub compare_ret_on_success: bool,
    pub run: fn() -> (Outcome, Outcome),
}

pub struct RunReport {
    pub total: usize,
    pub skipped: Vec<(&'static str, &'static str)>,
    pub known: Vec<String>,
    pub failures: Vec<String>,
}

impl RunReport {
    pub fn print(&self) {
        std::println!("--- F721 conformance corpus: {} case(s) ---", self.total);
        for (id, why) in &self.skipped { std::println!("  SKIP  {id}: {why}"); }
        for line in &self.known { std::println!("  KNOWN {line}"); }
        for line in &self.failures { std::println!("  FAIL  {line}"); }
    }
}

/// Run every case in `cases`, printing a summary. Panics (failing the
/// `cargo test` run) only on an UNCLASSIFIED divergence — a case with
/// `known_divergence: Some(..)` still gets compared and reported every run,
/// it just cannot fail the build. This makes the corpus a live regression
/// gate: a newly introduced divergence anywhere in `cases` fails CI with the
/// exact host-vs-oxide values, and a FIXED known-divergence is silently
/// caught the moment its outcomes start matching again (nothing to do but
/// delete the stale `known_divergence` entry).
pub fn run_corpus(cases: &[Case]) -> RunReport {
    let mut report = RunReport { total: cases.len(), skipped: Vec::new(), known: Vec::new(), failures: Vec::new() };
    for c in cases {
        if let Some(reason) = c.skip { report.skipped.push((c.id, reason)); continue; }
        let (host, oxide) = (c.run)();
        let matches = host.same_errno_class(&oxide)
            && (!c.compare_ret_on_success || !host.is_success() || host.ret == oxide.ret);
        if matches { continue; }
        let line = format!("{}: host={host} oxide={oxide}", c.id);
        match c.known_divergence {
            Some(defect) => report.known.push(format!("{line} [{defect}]")),
            None => report.failures.push(line),
        }
    }
    report.print();
    if !report.failures.is_empty() {
        panic!(
            "{} NEW (unclassified) divergence(s) found — see FAIL lines above.\n\
             If real, file the defect and add `known_divergence: Some(\"<ref>\")` to the case;\n\
             if the fixture/case was wrong, fix the case. Never loosen the expected errno to hide it.",
            report.failures.len()
        );
    }
    report
}
