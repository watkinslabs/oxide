// spec-lint: enforce doc + code rules per docs/02, docs/07§5, docs/08.
// Subcommands: docs|code|manifest|all. Exit non-zero on any finding.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod doc_lint;
mod code_lint;
mod manifest_lint;
mod walk;
mod xref_lint;

#[derive(Default)]
pub struct Findings {
    items: Vec<Finding>,
}

pub struct Finding {
    pub path: PathBuf,
    pub line: usize,
    pub rule: &'static str,
    pub msg: String,
}

impl Findings {
    pub fn push(&mut self, path: &Path, line: usize, rule: &'static str, msg: impl Into<String>) {
        self.items.push(Finding { path: path.to_path_buf(), line, rule, msg: msg.into() });
    }
    pub fn report(&self) -> bool {
        for f in &self.items {
            eprintln!("{}:{}: [{}] {}", f.path.display(), f.line, f.rule, f.msg);
        }
        if self.items.is_empty() {
            println!("spec-lint: clean");
            true
        } else {
            eprintln!("spec-lint: {} finding(s)", self.items.len());
            false
        }
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "all".into());
    let root = args.next().map(PathBuf::from).unwrap_or_else(|| std::env::current_dir().unwrap());

    let mut f = Findings::default();
    match cmd.as_str() {
        "docs" => doc_lint::run(&root, &mut f),
        "code" => code_lint::run(&root, &mut f),
        "manifest" => manifest_lint::run(&root, &mut f),
        "xref" => xref_lint::run(&root, &mut f),
        "all" => {
            doc_lint::run(&root, &mut f);
            manifest_lint::run(&root, &mut f);
            xref_lint::run(&root, &mut f);
            code_lint::run(&root, &mut f);
        }
        "-h" | "--help" => { eprintln!("usage: spec-lint <docs|code|manifest|xref|all> [root]"); return ExitCode::from(2); }
        other => { eprintln!("spec-lint: unknown subcommand `{other}`"); return ExitCode::from(2); }
    }
    if f.report() { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

// shared helpers ------------------------------------------------------------

pub fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Strip double-quoted and backtick-quoted spans (replace contents with spaces).
/// Used by lints that should not match patterns inside quoted/example text.
pub fn strip_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_dq = false;
    let mut in_bt = false;
    for c in s.chars() {
        match c {
            '"' if !in_bt => { in_dq = !in_dq; out.push(' '); }
            '`' if !in_dq => { in_bt = !in_bt; out.push(' '); }
            _ if in_dq || in_bt => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

pub fn is_charter(stem: &str) -> bool {
    // 00..09 (and 09a etc) keep titles in section headers
    if stem.len() < 2 { return false; }
    let two = &stem[..2];
    matches!(two, "00"|"01"|"02"|"03"|"04"|"05"|"06"|"07"|"08"|"09")
}

